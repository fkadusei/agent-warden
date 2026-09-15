// Package mcpgw serves Warden to agents over MCP (ADR-0011): stateless
// Streamable HTTP behind mutual TLS, where the client certificate is the agent's
// task credential.
//
// A middleware removes any client-supplied identity header and sets it to the
// verified peer certificate, so tool handlers, which see only request headers,
// act under the identity the TLS handshake proved. The gateway verifies that
// credential again on every call.
package mcpgw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/upstream"
)

const (
	// PeerCertificateHeader carries the verified client certificate to tool
	// handlers. Any value sent by a client is discarded.
	PeerCertificateHeader = "X-Warden-Peer-Certificate"
	// ResumeTool runs an approved call.
	ResumeTool = upstream.Reserved + ".resume"
)

var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Lister lists a server's current tools.
type Lister interface {
	Tools(ctx context.Context, server string) ([]registry.Manifest, error)
}

// Exposed describes the tools offered to agents and those withheld.
type Exposed struct {
	Tools    []string
	Withheld map[string]string // tool ID -> reason
}

// NewHandler builds the agent-facing handler. It exposes, for each server, the
// tools whose current manifest matches its pin, plus warden.resume. The handler
// must be served over TLS that requires and verifies client certificates.
func NewHandler(ctx context.Context, gw *gateway.Gateway, reg *registry.Registry, lister Lister, servers []string) (http.Handler, *Exposed, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "agent-warden", Version: "0.1.0"}, nil)
	exposed := &Exposed{Withheld: map[string]string{}}

	for _, srv := range servers {
		ms, err := lister.Tools(ctx, srv)
		if err != nil {
			return nil, nil, err
		}
		rev := reg.Review(ms)
		for _, c := range append(append(rev.Unpinned, rev.Changed...), rev.Invalid...) {
			exposed.Withheld[c.Manifest.ID()] = c.Err.Error()
		}
		for _, c := range rev.Allowed {
			name := srv + "." + c.Manifest.Name
			if !toolNamePattern.MatchString(name) {
				exposed.Withheld[c.Manifest.ID()] = "name is not a valid MCP tool name"
				continue
			}
			if err := addTool(server, &mcp.Tool{
				Name:        name,
				Title:       c.Manifest.Title,
				Description: c.Manifest.Description,
				InputSchema: c.Manifest.InputSchema,
			}, callHandler(gw, srv, c.Manifest.Name)); err != nil {
				exposed.Withheld[c.Manifest.ID()] = err.Error()
				continue
			}
			exposed.Tools = append(exposed.Tools, name)
		}
	}

	if err := addTool(server, &mcp.Tool{
		Name:        ResumeTool,
		Description: "Run a call that was held for human approval, once it has been approved.",
		InputSchema: map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"decision_seq": map[string]any{"type": "integer", "minimum": 0}},
			"required":             []any{"decision_seq"},
			"additionalProperties": false,
		},
	}, resumeHandler(gw)); err != nil {
		return nil, nil, err
	}
	exposed.Tools = append(exposed.Tools, ResumeTool)

	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return authenticate(h), exposed, nil
}

// addTool registers a tool, turning an SDK panic on an invalid definition into an error.
func addTool(s *mcp.Server, t *mcp.Tool, h mcp.ToolHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid tool definition: %v", r)
		}
	}()
	s.AddTool(t, h)
	return nil
}

// authenticate requires a verified TLS client certificate and passes it to tool
// handlers in PeerCertificateHeader, overwriting anything the client sent.
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(PeerCertificateHeader)
		if r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "a verified task credential is required", http.StatusUnauthorized)
			return
		}
		r.Header.Set(PeerCertificateHeader, base64.StdEncoding.EncodeToString(r.TLS.PeerCertificates[0].Raw))
		next.ServeHTTP(w, r)
	})
}

func credential(req *mcp.CallToolRequest) ([]byte, error) {
	if req.Extra == nil {
		return nil, errors.New("no transport headers")
	}
	v := req.Extra.Header.Get(PeerCertificateHeader)
	if v == "" {
		return nil, errors.New("no verified client certificate")
	}
	return base64.StdEncoding.DecodeString(v)
}

func text(isError bool, format string, a ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, a...)}}}
}

func callHandler(gw *gateway.Gateway, server, tool string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cred, err := credential(req)
		if err != nil {
			return text(true, "Warden refused the call: %v.", err), nil
		}
		resp, err := gw.Call(ctx, cred, server, tool, req.Params.Arguments)
		return renderResponse(resp, err), nil
	}
}

func resumeHandler(gw *gateway.Gateway) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cred, err := credential(req)
		if err != nil {
			return text(true, "Warden refused the call: %v.", err), nil
		}
		var args struct {
			DecisionSeq *int64 `json:"decision_seq"`
		}
		dec := json.NewDecoder(bytes.NewReader(req.Params.Arguments))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&args); err != nil || args.DecisionSeq == nil || *args.DecisionSeq < 0 {
			return text(true, `warden.resume needs {"decision_seq": <non-negative integer>}.`), nil
		}
		resp, err := gw.Resume(ctx, cred, *args.DecisionSeq)
		return renderResponse(resp, err), nil
	}
}

// renderResponse turns a gateway outcome into what the agent sees. Errors are
// described by category only.
func renderResponse(resp *gateway.Response, err error) *mcp.CallToolResult {
	switch {
	case errors.Is(err, gateway.ErrUnauthenticated):
		return text(true, "Warden refused the call: the task credential was rejected.")
	case errors.Is(err, gateway.ErrReceipt):
		return text(true, "Warden refused the call: its receipt could not be recorded.")
	case errors.Is(err, gateway.ErrUpstream):
		return text(true, "Warden refused the call: the tool server is unavailable.")
	case errors.Is(err, gateway.ErrNotApproved):
		return text(true, "Warden will not run this call: %v.", err)
	case errors.Is(err, gateway.ErrNotPending):
		return text(true, "Warden has no call waiting under that decision.")
	case errors.Is(err, gateway.ErrMismatch):
		return text(true, "Warden refused: this credential is not the one that made the original call.")
	case err != nil:
		return text(true, "Warden refused the call.")
	}
	switch resp.Status {
	case gateway.StatusOK:
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(resp.Result)}}}
	case gateway.StatusDenied:
		if resp.Rule == "" {
			return text(true, "Denied by Warden: no policy permits this call. Decision receipt #%d.", resp.DecisionSeq)
		}
		msg := fmt.Sprintf("Denied by Warden (rule %q). Decision receipt #%d.", resp.Rule, resp.DecisionSeq)
		if resp.Rule == gateway.RuleInvalidArguments && resp.Detail != "" {
			// The agent sent these arguments, so the reason reveals nothing new and lets it correct them.
			msg += " " + resp.Detail
		}
		return text(true, "%s", msg)
	case gateway.StatusPending:
		return text(true, "This call needs human approval (rule %q). Decision receipt #%d. Once it is approved, call %s with {\"decision_seq\": %d}.",
			resp.Rule, resp.DecisionSeq, ResumeTool, resp.DecisionSeq)
	default:
		msg := fmt.Sprintf("Tool error: %s. Decision receipt #%d, result receipt #%d.", resp.Detail, resp.DecisionSeq, resp.ResultSeq)
		if len(resp.Result) > 0 {
			msg += "\n" + string(resp.Result)
		}
		return text(true, "%s", msg)
	}
}
