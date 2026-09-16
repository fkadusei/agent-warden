package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/fkadusei/agent-warden/internal/approverapi"
	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/tsa"
)

//go:embed console.html
var consolePage []byte

// console is a local operator view: what Warden decided, what is waiting for a person,
// and whether the log still verifies (ADR-0015). It binds to loopback, guards its API
// with a startup token, and can only approve when an approver key was given.
type console struct {
	token string
	// log, keys, anchor, tokens describe an exported receipt log to read.
	logPath, keysPath, anchorPath, tsaTokens, tsaRoots, chainID string
	// approver is nil when the console is read-only.
	approver *approverapi.Client
	ttl      time.Duration
}

func cmdConsole(ctx context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("console", out)
	listen := fs.String("listen", "127.0.0.1:8445", "address to serve on (loopback only)")
	logPath := fs.String("log", "", "exported receipt log to show (warden export --out ...)")
	chainID := fs.String("chain", "", "the chain ID the log must belong to")
	keysPath := fs.String("keys", "", "trusted public keys as a JWK Set")
	anchorPath := fs.String("anchor", "", "anchored checkpoints (optional, strongly recommended)")
	tsaTokens := fs.String("tsa-tokens", "", "RFC 3161 timestamps for the anchored checkpoints (optional)")
	tsaRoots := fs.String("tsa-roots", "", "certificates trusted as timestamp authorities (optional)")
	approverURL := fs.String("url", "https://127.0.0.1:8444", "Warden's approver API")
	caPath := fs.String("ca", "warden-local/pki/ca.pem", "Warden root certificate")
	keyPath := fs.String("key", "", "approver private key; without it the console is read-only")
	id := fs.String("id", "", "approver identity, e.g. bob@tenant-a (with --key)")
	ttl := fs.Duration("ttl", 10*time.Minute, "how long an approval stays valid (at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *logPath == "" || *chainID == "" || *keysPath == "" {
		return errors.New("--log, --chain and --keys are required (see `warden export`)")
	}
	if (*keyPath == "") != (*id == "") {
		return errors.New("--key and --id go together")
	}
	if host, _, err := net.SplitHostPort(*listen); err != nil || !isLoopback(host) {
		return fmt.Errorf("--listen must be a loopback address, got %q", *listen)
	}

	c := &console{logPath: *logPath, chainID: *chainID, keysPath: *keysPath, anchorPath: *anchorPath,
		tsaTokens: *tsaTokens, tsaRoots: *tsaRoots, ttl: *ttl}
	if *keyPath != "" {
		client, err := approverClient(*approverURL, *caPath, *keyPath, *id)
		if err != nil {
			return err
		}
		c.approver = client
	}
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	c.token = base64.RawURLEncoding.EncodeToString(raw[:])

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: c.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	mode := "read-only"
	if c.approver != nil {
		mode = "approving as " + *id
	}
	fmt.Fprintf(out, "Warden console (%s)\n  http://%s/?token=%s\n", mode, ln.Addr(), c.token)
	fmt.Fprintln(out, "  the link carries a one-off token; anyone with it can use this console")
	if c.approver != nil {
		fmt.Fprintln(out, "  the approver key stays in memory while this runs; don't leave it on a shared machine")
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *console) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(consolePage)
	})
	mux.HandleFunc("/api/state", c.guard(c.state))
	mux.HandleFunc("/api/approve", c.guard(c.approve))
	return mux
}

// guard requires the startup token on every API call.
func (c *console) guard(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Warden-Console-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(c.token)) != 1 {
			http.Error(w, "bad or missing console token", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

type stateReply struct {
	ChainID   string          `json:"chain_id"`
	Mode      string          `json:"mode"`
	Approver  string          `json:"approver,omitempty"`
	Receipts  []receiptView   `json:"receipts"`
	Pending   []pendingView   `json:"pending"`
	Verify    verifyView      `json:"verify"`
	PendingBy string          `json:"pending_error,omitempty"`
	Raw       json.RawMessage `json:"-"`
}

type receiptView struct {
	Seq     int64    `json:"seq"`
	TS      string   `json:"ts"`
	Type    string   `json:"type"`
	Tool    string   `json:"tool,omitempty"`
	Actor   string   `json:"actor,omitempty"`
	Outcome string   `json:"outcome,omitempty"`
	Rule    string   `json:"rule,omitempty"`
	Taint   []string `json:"taint,omitempty"`
}

type pendingView struct {
	Seq      int64    `json:"seq"`
	TS       string   `json:"ts"`
	Tool     string   `json:"tool"`
	Agent    string   `json:"agent"`
	For      string   `json:"for"`
	Task     string   `json:"task"`
	Rule     string   `json:"rule,omitempty"`
	Taint    []string `json:"taint,omitempty"`
	Args     string   `json:"args"`
	Verified bool     `json:"verified"`
	State    string   `json:"state"`
}

type verifyView struct {
	OK           bool   `json:"ok"`
	Detail       string `json:"detail"`
	Receipts     int    `json:"receipts"`
	Checkpoints  int    `json:"checkpoints"`
	Unanchored   int64  `json:"unanchored"`
	Timestamps   int    `json:"timestamps,omitempty"`
	EarliestTime string `json:"earliest_timestamp,omitempty"`
}

func (c *console) state(w http.ResponseWriter, r *http.Request) {
	out := stateReply{ChainID: c.chainID, Mode: "read-only"}
	if c.approver != nil {
		out.Mode, out.Approver = "approving", c.approver.Approver
	}

	logData, err := os.ReadFile(c.logPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot read the log: %v", err), http.StatusInternalServerError)
		return
	}
	keyData, err := os.ReadFile(c.keysPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot read the keys: %v", err), http.StatusInternalServerError)
		return
	}
	trusted, err := keys.Parse(keyData)
	if err != nil {
		http.Error(w, fmt.Sprintf("keys: %v", err), http.StatusInternalServerError)
		return
	}
	resolve := keys.Resolver(trusted)

	out.Receipts = summarize(logData, resolve)
	out.Verify = c.verify(logData, resolve)
	if c.approver != nil {
		pending, err := c.approver.List(r.Context())
		if err != nil {
			out.PendingBy = err.Error()
		} else {
			for _, p := range pending {
				v := pendingView{
					Seq: p.DecisionSeq, TS: p.DecisionTS, Tool: p.Call.Tool, Agent: p.Actor.Agent,
					For: p.Actor.Principal, Task: p.TaskID, Rule: p.Rule, Taint: p.Taint,
					Args: string(p.Args), Verified: approverapi.Check(p) == nil, State: "waiting",
				}
				if p.Approval != nil {
					v.State = string(p.Approval.Outcome) + " by " + p.Approval.Approver
				}
				out.Pending = append(out.Pending, v)
			}
		}
	}
	reply(w, out)
}

// summarize renders each receipt for the feed. Signatures are verified by the verify
// panel; this only reads what was signed.
func summarize(logData []byte, resolve chain.KeyResolver) []receiptView {
	var out []receiptView
	for _, line := range bytes.Split(bytes.TrimSpace(logData), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		s, err := receipt.ParseLine(line)
		if err != nil {
			continue
		}
		kid, err := s.KeyID()
		if err != nil {
			continue
		}
		pub, err := resolve(kid)
		if err != nil || pub == nil {
			continue
		}
		r, err := receipt.Verify(pub, s)
		if err != nil {
			continue
		}
		v := receiptView{Seq: r.Seq, TS: r.TS, Type: string(r.Type)}
		if r.Call != nil {
			v.Tool = r.Call.Tool
		}
		if r.Actor != nil {
			v.Actor = r.Actor.Agent + " for " + r.Actor.Principal
		}
		switch {
		case r.Decision != nil:
			v.Outcome, v.Rule, v.Taint = string(r.Decision.Result), r.Decision.Rule, r.Decision.Taint
		case r.Result != nil:
			v.Outcome, v.Taint = string(r.Result.Status), r.Result.Taint
		case r.Approval != nil:
			v.Outcome = string(r.Approval.Outcome) + " by " + r.Approval.Approver
		}
		out = append(out, v)
	}
	// Newest first: the console is for watching what just happened.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (c *console) verify(logData []byte, resolve chain.KeyResolver) verifyView {
	var cps []*checkpoint.Checkpoint
	anchorMissing := false
	if c.anchorPath != "" {
		anchorData, err := os.ReadFile(c.anchorPath)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// Warden writes the anchor at its first checkpoint; until then there is
			// nothing to compare against, which is not a failure.
			anchorMissing = true
		case err != nil:
			return verifyView{Detail: fmt.Sprintf("cannot read the anchor: %v", err)}
		default:
			cps, err = checkpoint.ReadVerified(bytes.NewReader(anchorData), c.chainID, resolve)
			if err != nil {
				return verifyView{Detail: err.Error()}
			}
		}
	}
	rep, err := chain.VerifyWithCheckpoints(bytes.NewReader(logData), c.chainID, resolve, cps)
	if err != nil {
		var f *chain.Failure
		if errors.As(err, &f) {
			return verifyView{Detail: fmt.Sprintf("line %d, seq %d: %s (%s)", f.Line, f.Seq, f.Reason, f.Detail),
				Checkpoints: len(cps)}
		}
		return verifyView{Detail: err.Error(), Checkpoints: len(cps)}
	}
	detail := "the log verifies"
	if len(cps) == 0 {
		// Same caveat warden-verify prints: without a checkpoint, deleting the newest
		// receipts or rewriting the whole log with the key cannot be detected.
		detail = "the log verifies, but nothing is anchored yet, so truncation cannot be detected"
		if anchorMissing {
			detail = "the log verifies; no checkpoint has been written yet, so truncation cannot be detected"
		}
	}
	v := verifyView{OK: true, Detail: detail, Receipts: rep.Receipts,
		Checkpoints: len(cps), Unanchored: rep.Unanchored}
	if c.tsaTokens != "" && c.tsaRoots != "" && c.anchorPath != "" {
		v.Timestamps, v.EarliestTime = c.timestamps()
	}
	return v
}

// timestamps counts the RFC 3161 tokens that cover the anchored checkpoints.
func (c *console) timestamps() (int, string) {
	roots, err := tsa.LoadRoots(c.tsaRoots)
	if err != nil {
		return 0, ""
	}
	tokenData, err := os.ReadFile(c.tsaTokens)
	if err != nil {
		return 0, ""
	}
	tokens, err := tsa.ReadTokens(bytes.NewReader(tokenData))
	if err != nil {
		return 0, ""
	}
	anchorData, err := os.ReadFile(c.anchorPath)
	if err != nil {
		return 0, ""
	}
	var count int
	var earliest time.Time
	for _, line := range bytes.Split(bytes.TrimSpace(anchorData), []byte("\n")) {
		for _, token := range tokens[tsa.Digest(line)] {
			when, err := tsa.Verify(token, line, roots)
			if err != nil {
				continue
			}
			count++
			if earliest.IsZero() || when.Before(earliest) {
				earliest = when
			}
		}
	}
	if earliest.IsZero() {
		return count, ""
	}
	return count, earliest.UTC().Format(time.RFC3339)
}

type approveRequest struct {
	Seq    int64  `json:"seq"`
	Reject bool   `json:"reject"`
	Reason string `json:"reason,omitempty"`
}

func (c *console) approve(w http.ResponseWriter, r *http.Request) {
	if c.approver == nil {
		http.Error(w, "this console is read-only; start it with --key and --id to approve", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post an approval", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "unreadable request", http.StatusBadRequest)
		return
	}
	var req approveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pending, err := c.approver.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var target *approverapi.Pending
	for i := range pending {
		if pending[i].DecisionSeq == req.Seq {
			target = &pending[i]
		}
	}
	if target == nil {
		http.Error(w, fmt.Sprintf("no call is waiting under decision #%d", req.Seq), http.StatusNotFound)
		return
	}
	outcome := receipt.Approved
	if req.Reject {
		outcome = receipt.Rejected
	}
	// Sign verifies the shown arguments against the decision's commitment and computes
	// the call digest itself (ADR-0009); the console adds no second signing path.
	statement, err := c.approver.Sign(*target, outcome, c.ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	done, err := c.approver.Submit(r.Context(), statement)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	reply(w, done)
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, strings.TrimSpace(err.Error()), http.StatusInternalServerError)
	}
}
