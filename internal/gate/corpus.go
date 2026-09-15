package gate

import (
	"bytes"
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
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fkadusei/agent-warden/internal/broker"
	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/exampletools"
	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/inspect"
	"github.com/fkadusei/agent-warden/internal/mcpgw"
	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/scenario"
	"github.com/fkadusei/agent-warden/internal/store"
	"github.com/fkadusei/agent-warden/internal/upstream"
)

// CorpusOptions change the deployment the corpus runs against.
type CorpusOptions struct {
	// Policy replaces the example policy; used to show the gate fails when
	// Warden's policy is weak.
	Policy string
}

// StepResult is what happened to one scripted call.
type StepResult struct {
	scenario.Step
	// Got is the outcome from the receipts: ok, denied, pending_approval,
	// tool_error, no_receipt, or protocol_error.
	Got   string
	Rule  string
	Taint []string
	// Ran is how many times the call reached the tool server.
	Ran int
	Err error
}

// CorpusResult is one scenario's outcome.
type CorpusResult struct {
	Scenario *scenario.Scenario
	Steps    []StepResult
	// Err is the first failed check, or nil when every step held.
	Err      error
	Duration time.Duration
}

// Blocked counts attack steps that Warden refused and that never reached a tool.
func (r CorpusResult) Blocked() (blocked, attacks int) {
	for _, st := range r.Steps {
		if st.Attack {
			attacks++
			if (st.Got == string(scenario.Denied) || st.Got == string(scenario.PendingApproval)) && st.Ran == 0 {
				blocked++
			}
		}
	}
	return blocked, attacks
}

// callCounter counts tools/call requests reaching each tool, whatever the tool
// then does with them.
type callCounter struct {
	mu   sync.Mutex
	runs map[string]int
}

func (c *callCounter) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			r.Body.Close()
			if err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var msg struct {
				Method string `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call" {
				c.mu.Lock()
				c.runs[strings.TrimPrefix(r.URL.Path, "/")+"."+msg.Params.Name]++
				c.mu.Unlock()
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (c *callCounter) ran(tool string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs[tool]
}

// corpusEnv is the example deployment `warden init` creates, for one scenario.
type corpusEnv struct {
	ctx        context.Context
	pool       *x509.CertPool
	agentURL   string
	agent      tls.Certificate
	store      *store.Store
	receiptKey *composite.PrivateKey
	calls      *callCounter
	closers    []func()
}

func (e *corpusEnv) Close() {
	for i := len(e.closers) - 1; i >= 0; i-- {
		e.closers[i]()
	}
	e.closers = nil
}

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

func newCorpusEnv(ctx context.Context, s *scenario.Scenario, opts CorpusOptions) (e *corpusEnv, err error) {
	e = &corpusEnv{ctx: ctx, calls: &callCounter{runs: map[string]int{}}}
	defer func() {
		if err != nil {
			e.Close()
		}
	}()
	dir, err := os.MkdirTemp("", "warden-corpus-*")
	if err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { os.RemoveAll(dir) })
	now := time.Now()

	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	ca, err := identity.NewCA("Warden Corpus Root", rootKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	e.pool = ca.Pool()
	agentKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	agentDER, err := ca.IssueTask(identity.TaskClaims{Agent: "scripted-agent", Principal: s.Principal, Task: s.ID},
		agentKey.PublicKey(), now.Add(-time.Minute), now.Add(identity.MaxTaskLifetime))
	if err != nil {
		return nil, err
	}
	e.agent = tls.Certificate{Certificate: [][]byte{agentDER}, PrivateKey: agentKey}
	if e.receiptKey, err = composite.MLDSA65Ed25519.GenerateKey(); err != nil {
		return nil, err
	}

	// The example tool servers, serving this scenario's planted content.
	toolSrv := &http.Server{Handler: e.calls.wrap(exampletools.Handler(paymentsToken, s.Content...)), ReadHeaderTimeout: 5 * time.Second, ErrorLog: quiet()}
	toolsURL, err := listen(toolSrv, false)
	if err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { toolSrv.Close() })

	if e.store, err = store.Open(filepath.Join(dir, "receipts.db"), e.receiptKey, kid, chainID); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { e.store.Close() })
	brk, err := broker.Load([]byte(exampletools.Broker), broker.Sources{LookupEnv: func(k string) (string, bool) {
		return paymentsToken, k == "WARDEN_SECRET_PAYMENTS"
	}})
	if err != nil {
		return nil, err
	}
	var servers []upstream.Server
	for _, n := range exampletools.Servers {
		servers = append(servers, upstream.Server{Name: n, URL: toolsURL + "/" + n})
	}
	up, err := upstream.Connect(ctx, servers, brk, nil)
	if err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { up.Close() })

	// Every example tool is reviewed and pinned, as `warden pin --write` would.
	var reviewed []registry.Manifest
	for _, n := range exampletools.Servers {
		ms, err := up.Tools(ctx, n)
		if err != nil {
			return nil, err
		}
		reviewed = append(reviewed, ms...)
	}
	pins, err := registry.PinAll(reviewed)
	if err != nil {
		return nil, err
	}
	reg, err := registry.Load(pins)
	if err != nil {
		return nil, err
	}
	policyText := exampletools.Policy
	if opts.Policy != "" {
		policyText = opts.Policy
	}
	eng, err := policy.Load("policy.cedar", []byte(policyText))
	if err != nil {
		return nil, err
	}
	labels := &config.Config{Taint: exampletools.Taint(), ToolTaint: exampletools.ToolTaint()}
	roles := exampletools.Roles()
	var toolNames []string // set from the handler below, before anything is served
	gw, err := gateway.New(gateway.Config{
		Store: e.store, Registry: reg, Policy: eng, Broker: brk, Roots: e.pool, Upstream: up,
		Approvers: func(string) (*composite.PublicKey, error) { return nil, errors.New("no approvers in the corpus gate") },
		Roles:     func(p string) []string { return roles[p] },
		Taint:     labels.Label,
		Inspect:   func(content string) []string { return inspect.Flags(inspect.Inspect(content, toolNames)) },
	})
	if err != nil {
		return nil, err
	}
	handler, exposed, err := mcpgw.NewHandler(ctx, gw, reg, up, exampletools.Servers)
	if err != nil {
		return nil, err
	}
	if len(exposed.Withheld) > 0 {
		return nil, fmt.Errorf("tools withheld from the agent: %v", exposed.Withheld)
	}
	toolNames = exposed.Tools

	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	serverDER, err := ca.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")}, serverKey.PublicKey(), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	agentSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ErrorLog: quiet(), TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: e.pool, MinVersion: tls.VersionTLS13,
	}}
	if e.agentURL, err = listen(agentSrv, true); err != nil {
		return nil, err
	}
	e.closers = append(e.closers, func() { agentSrv.Close() })
	return e, nil
}

func (e *corpusEnv) session() (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "scripted-agent", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(e.ctx, 20*time.Second)
	defer cancel()
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: e.agentURL, DisableStandaloneSSE: true, MaxRetries: -1,
		HTTPClient: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: e.pool, Certificates: []tls.Certificate{e.agent}, MinVersion: tls.VersionTLS13, VerifyConnection: identity.CheckServer,
		}}},
	}, nil)
}

// receiptsFrom returns the verified receipts with seq >= from.
func (e *corpusEnv) receiptsFrom(from int64) ([]*receipt.Receipt, error) {
	var buf bytes.Buffer
	if err := e.store.Export(e.ctx, &buf); err != nil {
		return nil, err
	}
	var out []*receipt.Receipt
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		s, err := receipt.ParseLine(line)
		if err != nil {
			return nil, err
		}
		r, err := receipt.Verify(e.receiptKey.Public(), s)
		if err != nil {
			return nil, err
		}
		if r.Seq >= from {
			out = append(out, r)
		}
	}
	return out, nil
}

// step makes one scripted call and works out, from the receipts, what Warden did.
func (e *corpusEnv) step(s *mcp.ClientSession, st scenario.Step) StepResult {
	res := StepResult{Step: st}
	before, ranBefore := e.store.Next(), e.calls.ran(st.Call)
	_, isErr, callErr := callOn(e.ctx, s, st.Call, string(st.ArgsJSON()))
	res.Ran = e.calls.ran(st.Call) - ranBefore
	if callErr != nil {
		res.Got, res.Err = "protocol_error", callErr
		return res
	}
	rs, err := e.receiptsFrom(before)
	if err != nil {
		res.Got, res.Err = "no_receipt", err
		return res
	}
	var decision *receipt.Receipt
	for _, r := range rs {
		if r.Type == receipt.TypeDecision {
			decision = r
			break
		}
	}
	if decision == nil {
		res.Got = "no_receipt"
		return res
	}
	res.Rule, res.Taint = decision.Decision.Rule, decision.Decision.Taint
	switch decision.Decision.Result {
	case receipt.Deny:
		res.Got = string(scenario.Denied)
	case receipt.RequireApproval:
		res.Got = string(scenario.PendingApproval)
	case receipt.Allow:
		res.Got = "tool_error"
		for _, r := range rs {
			if r.Type == receipt.TypeResult && r.Result.DecisionSeq == decision.Seq && r.Result.Status == receipt.StatusOK {
				res.Got = string(scenario.OK)
			}
		}
	}
	if (res.Got == string(scenario.OK)) == isErr {
		res.Err = fmt.Errorf("the agent saw isError=%v but the receipts say %s", isErr, res.Got)
	}
	return res
}

func (st StepResult) check() error {
	switch {
	case st.Err != nil:
		return st.Err
	case st.Got != string(st.Expect):
		return fmt.Errorf("got %s (rule %q), want %s", st.Got, st.Rule, st.Expect)
	case st.Step.Rule != "" && st.Rule != st.Step.Rule:
		return fmt.Errorf("decided by rule %q, want %q", st.Rule, st.Step.Rule)
	case st.Expect != scenario.OK && st.Ran != 0:
		return fmt.Errorf("refused, yet the call reached the tool %d time(s)", st.Ran)
	case st.Expect == scenario.OK && st.Ran != 1:
		return fmt.Errorf("allowed, but the call reached the tool %d time(s), want 1", st.Ran)
	}
	return nil
}

// runScenario plays one scenario's calls as a compromised agent: every call is made,
// even after Warden refuses an earlier one.
func runScenario(ctx context.Context, s *scenario.Scenario, opts CorpusOptions) CorpusResult {
	start := time.Now()
	out := CorpusResult{Scenario: s}
	defer func() { out.Duration = time.Since(start) }()
	e, err := newCorpusEnv(ctx, s, opts)
	if err != nil {
		out.Err = fmt.Errorf("setting up: %w", err)
		return out
	}
	defer e.Close()
	sess, err := e.session()
	if err != nil {
		out.Err = fmt.Errorf("agent could not connect: %w", err)
		return out
	}
	defer sess.Close()

	for i, st := range s.Steps {
		r := e.step(sess, st)
		out.Steps = append(out.Steps, r)
		if err := r.check(); err != nil && out.Err == nil {
			out.Err = fmt.Errorf("step %d %s: %w", i+1, st.Call, err)
		}
	}
	var buf bytes.Buffer
	if err := e.store.Export(ctx, &buf); err != nil && out.Err == nil {
		out.Err = err
	}
	keys := func(k string) (*composite.PublicKey, error) {
		if k == kid {
			return e.receiptKey.Public(), nil
		}
		return nil, errors.New("unknown key")
	}
	if _, err := chain.Verify(bytes.NewReader(buf.Bytes()), chainID, keys); err != nil && out.Err == nil {
		out.Err = fmt.Errorf("receipt log does not verify: %w", err)
	}
	return out
}

// RunCorpus runs every scenario against a fresh example deployment and writes a report.
func RunCorpus(ctx context.Context, w io.Writer, scenarios []*scenario.Scenario, opts CorpusOptions) []CorpusResult {
	var results []CorpusResult
	for _, s := range scenarios {
		results = append(results, runScenario(ctx, s, opts))
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tCATEGORY\tTHREAT\tRESULT\tATTACKS BLOCKED\tOUTCOMES")
	var blocked, attacks, benign, benignOK, failed int
	for _, r := range results {
		status := "PASS"
		if r.Err != nil {
			status = "FAIL"
			failed++
		}
		b, a := r.Blocked()
		blocked, attacks = blocked+b, attacks+a
		attackCol := "-"
		if a > 0 {
			attackCol = fmt.Sprintf("%d/%d", b, a)
		}
		if r.Scenario.Category == scenario.Benign {
			benign++
			if r.Err == nil {
				benignOK++
			}
		}
		var outcomes []string
		for _, st := range r.Steps {
			o := st.Call + "=" + st.Got
			if st.Attack {
				o = "!" + o
			}
			outcomes = append(outcomes, o)
		}
		threat := r.Scenario.Threat
		if threat == "" {
			threat = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Scenario.ID, r.Scenario.Category, threat, status, attackCol, strings.Join(outcomes, " "))
	}
	tw.Flush()
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(w, "\n%s FAILED: %v\n", r.Scenario.ID, r.Err)
		}
	}
	fmt.Fprintf(w, "\n! marks an attack call. Attacks blocked: %d/%d. Benign scenarios completed: %d/%d. %d passed, %d failed.\n",
		blocked, attacks, benignOK, benign, len(results)-failed, failed)
	return results
}
