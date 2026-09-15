// Package upstream connects Warden to tool servers over MCP (ADR-0011) and
// implements gateway.Upstream.
//
// Streamable HTTP servers receive header credentials on each call, set by an
// HTTP transport that reads them from the call's context. stdio servers receive
// their server-wide environment credentials once, when the process starts, and
// nothing else from Warden's environment except PATH.
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fkadusei/agent-warden/internal/broker"
	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/registry"
)

// Reserved is the server name Warden keeps for its own tools.
const Reserved = "warden"

var serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Server describes one upstream tool server. Exactly one of URL or Command is set.
type Server struct {
	Name string
	// URL is a Streamable HTTP endpoint.
	URL string
	// Command runs a stdio server: the program followed by its arguments.
	Command []string
}

// Upstream holds a client session per tool server. It is safe for concurrent use.
type Upstream struct {
	mu       sync.Mutex
	sessions map[string]*mcp.ClientSession
}

type credentialsKey struct{}

// headerTransport sets the header credentials carried by the request's context.
type headerTransport struct{ base http.RoundTripper }

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	creds, _ := r.Context().Value(credentialsKey{}).([]broker.Credential)
	if len(creds) == 0 {
		return t.base.RoundTrip(r)
	}
	r = r.Clone(r.Context())
	for _, c := range creds {
		if c.Inject == broker.Header {
			r.Header.Set(c.Name, c.Value.Reveal())
		}
	}
	return t.base.RoundTrip(r)
}

// Connect opens a session to every server. base is the HTTP transport for
// Streamable HTTP servers; http.DefaultTransport if nil.
func Connect(ctx context.Context, servers []Server, brk *broker.Broker, base http.RoundTripper) (*Upstream, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	u := &Upstream{sessions: map[string]*mcp.ClientSession{}}
	client := mcp.NewClient(&mcp.Implementation{Name: "agent-warden", Version: "0.1.0"}, nil)
	for _, s := range servers {
		if err := validate(s, brk, u.sessions); err != nil {
			u.Close()
			return nil, err
		}
		var transport mcp.Transport
		if s.URL != "" {
			transport = &mcp.StreamableClientTransport{
				Endpoint:             s.URL,
				HTTPClient:           &http.Client{Transport: headerTransport{base}},
				DisableStandaloneSSE: true,
			}
		} else {
			creds, err := brk.ServerCredentials(s.Name)
			if err != nil {
				u.Close()
				return nil, fmt.Errorf("upstream: %s: %w", s.Name, err)
			}
			cmd := exec.Command(s.Command[0], s.Command[1:]...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			for _, c := range creds {
				cmd.Env = append(cmd.Env, c.Name+"="+c.Value.Reveal())
			}
			transport = &mcp.CommandTransport{Command: cmd}
		}
		session, err := client.Connect(ctx, transport, nil)
		if err != nil {
			u.Close()
			return nil, fmt.Errorf("upstream: connect %s: %w", s.Name, err)
		}
		u.sessions[s.Name] = session
	}
	return u, nil
}

func validate(s Server, brk *broker.Broker, existing map[string]*mcp.ClientSession) error {
	switch {
	case !serverNamePattern.MatchString(s.Name):
		return fmt.Errorf("upstream: server name %q must match %s", s.Name, serverNamePattern)
	case s.Name == Reserved:
		return fmt.Errorf("upstream: server name %q is reserved", Reserved)
	case existing[s.Name] != nil:
		return fmt.Errorf("upstream: duplicate server %q", s.Name)
	case (s.URL == "") == (len(s.Command) == 0):
		return fmt.Errorf("upstream: server %q needs exactly one of a URL or a command", s.Name)
	}
	for _, b := range brk.Describe(s.Name) {
		switch {
		case s.URL != "" && b.Inject == broker.Env:
			return fmt.Errorf("upstream: %s is an HTTP server; environment credential %q cannot be delivered", s.Name, b.Name)
		case s.URL == "" && b.Inject == broker.Header:
			return fmt.Errorf("upstream: %s is a stdio server; header credential %q cannot be delivered", s.Name, b.Name)
		case s.URL == "" && b.Tool != "*":
			return fmt.Errorf("upstream: %s is a stdio server; per-tool credential %q for %q cannot be delivered to a long-running process", s.Name, b.Name, b.Tool)
		}
	}
	return nil
}

func (u *Upstream) session(server string) (*mcp.ClientSession, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.sessions[server]
	if s == nil {
		return nil, fmt.Errorf("upstream: unknown server %q", server)
	}
	return s, nil
}

// Tools lists every tool a server offers, as manifests.
func (u *Upstream) Tools(ctx context.Context, server string) ([]registry.Manifest, error) {
	s, err := u.session(server)
	if err != nil {
		return nil, err
	}
	var out []registry.Manifest
	for t, err := range s.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("upstream: list tools on %s: %w", server, err)
		}
		m, err := toManifest(server, t)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Manifest returns a tool's current manifest, listed from the server now.
func (u *Upstream) Manifest(ctx context.Context, server, tool string) (registry.Manifest, error) {
	ms, err := u.Tools(ctx, server)
	if err != nil {
		return registry.Manifest{}, err
	}
	for _, m := range ms {
		if m.Name == tool {
			return m, nil
		}
	}
	return registry.Manifest{}, fmt.Errorf("upstream: %s has no tool %q", server, tool)
}

// Call runs a tool. Header credentials ride on this call's HTTP request only.
func (u *Upstream) Call(ctx context.Context, server, tool string, args json.RawMessage, creds []broker.Credential) (*gateway.ToolResult, error) {
	s, err := u.session(server)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, credentialsKey{}, creds)
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return nil, fmt.Errorf("upstream: call %s/%s: %w", server, tool, err)
	}
	content, err := render(res)
	if err != nil {
		return nil, err
	}
	return &gateway.ToolResult{Content: content, IsError: res.IsError}, nil
}

// render returns text content joined by newlines, or the JSON of the content and
// structured content when the result is not plain text.
func render(res *mcp.CallToolResult) ([]byte, error) {
	var texts []string
	allText := true
	for _, c := range res.Content {
		t, ok := c.(*mcp.TextContent)
		if !ok {
			allText = false
			break
		}
		texts = append(texts, t.Text)
	}
	if allText && res.StructuredContent == nil {
		return []byte(strings.Join(texts, "\n")), nil
	}
	b, err := json.Marshal(struct {
		Content           []mcp.Content `json:"content"`
		StructuredContent any           `json:"structuredContent,omitempty"`
	}{res.Content, res.StructuredContent})
	if err != nil {
		return nil, fmt.Errorf("upstream: render result: %w", err)
	}
	return b, nil
}

// toManifest converts a listed tool into the manifest that gets pinned. Values are
// passed through JSON so their representation does not depend on Go types.
func toManifest(server string, t *mcp.Tool) (registry.Manifest, error) {
	m := registry.Manifest{Server: server, Name: t.Name, Title: t.Title, Description: t.Description}
	var err error
	if m.InputSchema, err = normalize(t.InputSchema); err != nil {
		return m, err
	}
	if m.OutputSchema, err = normalize(t.OutputSchema); err != nil {
		return m, err
	}
	if t.Annotations != nil {
		if m.Annotations, err = normalize(t.Annotations); err != nil {
			return m, err
		}
	}
	return m, nil
}

func normalize(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("upstream: tool definition: %w", err)
	}
	if string(b) == "null" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("upstream: tool definition: %w", err)
	}
	return out, nil
}

// Close closes every session.
func (u *Upstream) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	var errs []error
	for name, s := range u.sessions {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
