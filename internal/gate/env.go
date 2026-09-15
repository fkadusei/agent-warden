// Package gate is the Phase 2 gate (design §6, §7): attack scenarios run against
// the whole stack — an agent MCP client over mutual TLS, Warden's gateway, the
// approver API, and real MCP tool servers that count every execution — so each
// scenario checks not only that Warden refused, but that the tool never ran.
package gate

import (
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fkadusei/agent-warden/internal/approverapi"
	"github.com/fkadusei/agent-warden/internal/broker"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/mcpgw"
	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/store"
	"github.com/fkadusei/agent-warden/internal/upstream"
)

const (
	chainID       = "gate-chain"
	kid           = "gate-e1"
	paymentsToken = "tok_gate_4f7c2a9e1b"
)

const policyText = `
@id("support_crm")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource in Server::"crm");

@id("refunds_need_approval")
permit (principal in Role::"support", action == Action::"call", resource == Tool::"payments/refund");

@id("small_refunds_unattended")
permit (principal in Role::"support", action == Action::"call_unattended", resource == Tool::"payments/refund")
when { context.args.amount <= 100 };

@id("mail_allowed")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"mail/send");
`

// The mail server's credential is bound but never provided, to show that a
// missing secret stops execution.
const brokerConfig = `{"v":1,"bindings":[
  {"server":"payments","tool":"*","inject":"header","name":"Authorization","prefix":"Bearer ","secret":"env:WARDEN_SECRET_PAYMENTS"},
  {"server":"mail","tool":"*","inject":"header","name":"X-Mail-Key","secret":"env:WARDEN_SECRET_MAIL"}
]}`

func object(props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props}
}

// toolDef is an upstream tool whose definition a scenario may change.
type toolDef struct {
	server string
	tool   *mcp.Tool
}

// toolHost runs real MCP tool servers and counts executions per tool.
type toolHost struct {
	mu      sync.Mutex
	runs    map[string]int
	auth    map[string][]string
	servers map[string]*mcp.Server
	http    *http.Server
	url     string
}

func (h *toolHost) handler(id string) mcp.ToolHandler {
	return func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.mu.Lock()
		h.runs[id]++
		if req.Extra != nil {
			h.auth[id] = append(h.auth[id], req.Extra.Header.Get("Authorization"))
		}
		h.mu.Unlock()
		if id == "payments/refund" && (req.Extra == nil || req.Extra.Header.Get("Authorization") != "Bearer "+paymentsToken) {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: `{"error":"unauthorized"}`}}}, nil
		}
		body, _ := json.Marshal(map[string]any{"ok": true, "tool": id, "args": json.RawMessage(req.Params.Arguments)})
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
	}
}

func (h *toolHost) ran(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runs[id]
}

// set adds or replaces a tool definition on its server.
func (h *toolHost) set(server string, t *mcp.Tool) {
	s := h.servers[server]
	s.RemoveTools(t.Name)
	s.AddTool(t, h.handler(server+"/"+t.Name))
}

var initialTools = []toolDef{
	{"crm", &mcp.Tool{Name: "lookup", Description: "Look up a customer.", InputSchema: object(map[string]any{"id": map[string]any{"type": "string"}})}},
	{"crm", &mcp.Tool{Name: "export", Description: "Export customers.", InputSchema: object(nil)}},
	{"payments", &mcp.Tool{Name: "refund", Description: "Refund a payment.", InputSchema: object(map[string]any{"amount": map[string]any{"type": "integer"}})}},
	{"mail", &mcp.Tool{Name: "send", Description: "Send an email.", InputSchema: object(map[string]any{"to": map[string]any{"type": "string"}})}},
	{"hr", &mcp.Tool{Name: "salaries", Description: "List salaries.", InputSchema: object(nil)}},
}

// unpinned tools exist upstream but were never reviewed.
var unpinned = map[string]bool{"crm/export": true}

// Env is one isolated Warden deployment for a scenario.
type Env struct {
	ctx        context.Context
	pool       *x509.CertPool
	store      *store.Store
	receiptKey *composite.PrivateKey
	gw         *gateway.Gateway
	tools      *toolHost
	agentURL   string
	approveURL string

	// Task credentials.
	Alice      tls.Certificate // support-agent-7 for alice@tenant-a (support role)
	AliceOther tls.Certificate // other-agent for alice@tenant-a, same task
	Outsider   tls.Certificate // agent-x for bob@tenant-b (no role)

	// Approver keys; mallory is not trusted.
	Bob, AliceApprover, Mallory *composite.PrivateKey

	closers []func()
	dir     string
}

func listen(srv *http.Server, withTLS bool) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	if withTLS {
		go srv.ServeTLS(ln, "", "")
		return "https://" + ln.Addr().String(), nil
	}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String(), nil
}

func newEnv(ctx context.Context) (e *Env, err error) {
	e = &Env{ctx: ctx}
	defer func() {
		if err != nil {
			e.Close()
		}
	}()
	if e.dir, err = os.MkdirTemp("", "warden-gate-*"); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { os.RemoveAll(e.dir) })
	now := time.Now()

	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	ca, err := identity.NewCA("Warden Gate Root", rootKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	e.pool = ca.Pool()
	cred := func(agent, principal, task string) (tls.Certificate, error) {
		k, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return tls.Certificate{}, err
		}
		der, err := ca.IssueTask(identity.TaskClaims{Agent: agent, Principal: principal, Task: task}, k.PublicKey(), now.Add(-time.Minute), now.Add(identity.MaxTaskLifetime))
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, err
	}
	if e.Alice, err = cred("support-agent-7", "alice@tenant-a", "t1"); err != nil {
		return nil, err
	}
	if e.AliceOther, err = cred("other-agent", "alice@tenant-a", "t1"); err != nil {
		return nil, err
	}
	if e.Outsider, err = cred("agent-x", "bob@tenant-b", "t9"); err != nil {
		return nil, err
	}
	for _, k := range []**composite.PrivateKey{&e.receiptKey, &e.Bob, &e.AliceApprover, &e.Mallory} {
		if *k, err = composite.MLDSA65Ed25519.GenerateKey(); err != nil {
			return nil, err
		}
	}

	// Tool servers.
	e.tools = &toolHost{runs: map[string]int{}, auth: map[string][]string{}, servers: map[string]*mcp.Server{}}
	mux := http.NewServeMux()
	for _, name := range []string{"crm", "payments", "mail", "hr"} {
		s := mcp.NewServer(&mcp.Implementation{Name: name, Version: "1"}, nil)
		e.tools.servers[name] = s
		mux.Handle("/"+name, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	}
	for _, d := range initialTools {
		e.tools.set(d.server, d.tool)
	}
	e.tools.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if e.tools.url, err = listen(e.tools.http, false); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { e.tools.http.Close() })

	// Warden.
	if e.store, err = store.Open(filepath.Join(e.dir, "receipts.db"), e.receiptKey, kid, chainID); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { e.store.Close() })
	brk, err := broker.Load([]byte(brokerConfig), broker.Sources{LookupEnv: func(k string) (string, bool) {
		return paymentsToken, k == "WARDEN_SECRET_PAYMENTS"
	}})
	if err != nil {
		return nil, err
	}
	names := []string{"crm", "payments", "mail", "hr"}
	var servers []upstream.Server
	for _, n := range names {
		servers = append(servers, upstream.Server{Name: n, URL: e.tools.url + "/" + n})
	}
	up, err := upstream.Connect(ctx, servers, brk, nil)
	if err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { up.Close() })

	var reviewed []registry.Manifest
	for _, n := range names {
		ms, err := up.Tools(ctx, n)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if !unpinned[m.ID()] {
				reviewed = append(reviewed, m)
			}
		}
	}
	pins, err := registry.PinAll(reviewed)
	if err != nil {
		return nil, err
	}
	reg, err := registry.Load(pins)
	if err != nil {
		return nil, err
	}
	eng, err := policy.Load("gate.cedar", []byte(policyText))
	if err != nil {
		return nil, err
	}
	approvers := func(k string) (*composite.PublicKey, error) {
		switch k {
		case "bob@tenant-a":
			return e.Bob.Public(), nil
		case "alice@tenant-a":
			return e.AliceApprover.Public(), nil
		}
		return nil, errors.New("not a trusted approver")
	}
	e.gw, err = gateway.New(gateway.Config{
		Store: e.store, Registry: reg, Policy: eng, Broker: brk, Roots: e.pool, Approvers: approvers, Upstream: up,
		Roles: func(p string) []string {
			if p == "alice@tenant-a" {
				return []string{"support"}
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	handler, _, err := mcpgw.NewHandler(ctx, e.gw, reg, up, names)
	if err != nil {
		return nil, err
	}

	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	serverDER, err := ca.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")}, serverKey.PublicKey(), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	serverCert := tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
	// F4 deliberately fails handshakes; keep those out of the report.
	agentSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: e.pool, MinVersion: tls.VersionTLS13,
	}}
	if e.agentURL, err = listen(agentSrv, true); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { agentSrv.Close() })
	approveSrv := &http.Server{Handler: approverapi.NewServer(e.gw, e.store, approvers, nil).Handler(), ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}}
	if e.approveURL, err = listen(approveSrv, true); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { approveSrv.Close() })
	return e, nil
}

// Close shuts everything down, in reverse order of creation.
func (e *Env) Close() {
	for i := len(e.closers) - 1; i >= 0; i-- {
		e.closers[i]()
	}
	e.closers = nil
}

// spoofHeader forges Warden's internal identity header on every request.
type spoofHeader struct {
	base  http.RoundTripper
	value string
}

func (s spoofHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(mcpgw.PeerCertificateHeader, s.value)
	return s.base.RoundTrip(r)
}

// session connects as an agent. certs may be empty; spoof, if set, forges the
// internal identity header.
func (e *Env) session(certs []tls.Certificate, spoof string) (*mcp.ClientSession, error) {
	var rt http.RoundTripper = &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: e.pool, Certificates: certs, MinVersion: tls.VersionTLS13, VerifyConnection: identity.CheckServer,
	}}
	if spoof != "" {
		rt = spoofHeader{rt, spoof}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "gate-agent", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(e.ctx, 20*time.Second)
	defer cancel()
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: e.agentURL, HTTPClient: &http.Client{Transport: rt, Timeout: 20 * time.Second}, DisableStandaloneSSE: true, MaxRetries: -1,
	}, nil)
}

// call runs one tool call as the given agent and returns the text Warden sent back.
func (e *Env) call(cert tls.Certificate, tool, args string) (string, bool, error) {
	s, err := e.session([]tls.Certificate{cert}, "")
	if err != nil {
		return "", false, err
	}
	defer s.Close()
	return callOn(e.ctx, s, tool, args)
}

func callOn(ctx context.Context, s *mcp.ClientSession, tool, args string) (string, bool, error) {
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: json.RawMessage(args)})
	if err != nil {
		return "", false, err
	}
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n"), res.IsError, nil
}

// approver returns an approver API client.
func (e *Env) approver(id string, key *composite.PrivateKey) *approverapi.Client {
	return &approverapi.Client{
		BaseURL: e.approveURL, Key: key, Approver: id,
		HTTP: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: e.pool, MinVersion: tls.VersionTLS13, VerifyConnection: identity.CheckServer,
		}}},
	}
}

// pendingRefund asks for a refund that needs approval and returns its decision.
func (e *Env) pendingRefund() (int64, error) {
	text, isErr, err := e.call(e.Alice, "payments.refund", `{"amount":500}`)
	if err != nil {
		return 0, err
	}
	if !isErr || !strings.Contains(text, "needs human approval") {
		return 0, fmt.Errorf("refund was not held for approval: %q", text)
	}
	var seq int64
	marker := "Decision receipt #"
	i := strings.Index(text, marker)
	if i < 0 {
		return 0, fmt.Errorf("no decision number in %q", text)
	}
	if _, err := fmt.Sscanf(text[i+len(marker):], "%d", &seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// pending returns the pending entry for seq, as bob sees it.
func (e *Env) pending(seq int64) (approverapi.Pending, error) {
	list, err := e.approver("bob@tenant-a", e.Bob).List(e.ctx)
	if err != nil {
		return approverapi.Pending{}, err
	}
	for _, p := range list {
		if p.DecisionSeq == seq {
			return p, nil
		}
	}
	return approverapi.Pending{}, fmt.Errorf("decision #%d is not pending", seq)
}
