package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/store"
)

const (
	consoleChain = "console-test-chain"
	consoleKid   = "console-e1"
	fakeDigest   = "sha256:" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
)

// newConsole writes a two-receipt log with its trusted keys and returns a read-only
// console over it.
func newConsole(t *testing.T) *console {
	t.Helper()
	dir := t.TempDir()
	key, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "receipts.db"), key, consoleKid, consoleChain)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	actor := receipt.Actor{Agent: "support-agent-7", Principal: "alice@tenant-a"}
	call := receipt.Call{Tool: "payments/refund", Manifest: fakeDigest, ArgsCommitment: fakeDigest}
	// Append signs r.TS as given, so the caller stamps it, as the gateway does.
	now := time.Now().UTC().Format(receipt.TimeFormat)
	decision, err := st.Append(ctx, &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, Type: receipt.TypeDecision, TS: now,
		TaskID: "t1", Actor: &actor, Call: &call,
		Decision: &receipt.Decision{Result: receipt.Allow, PolicyRevision: fakeDigest,
			Rule: "small_refunds_unattended", Taint: []string{"web"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Append(ctx, &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, Type: receipt.TypeResult,
		TS:     time.Now().UTC().Format(receipt.TimeFormat),
		TaskID: "t1", Actor: &actor, Call: &call,
		Result: &receipt.Result{DecisionSeq: decision.Seq, Status: receipt.StatusOK,
			ResultCommitment: fakeDigest, Taint: []string{"pii"}},
	}); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, "receipts.jsonl")
	var buf bytes.Buffer
	if err := st.Export(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	keySet, err := json.Marshal(keys.Set{Keys: []keys.JWK{keys.PublicJWK(consoleKid, key.Public())}})
	if err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keysPath, keySet, 0o644); err != nil {
		t.Fatal(err)
	}
	return &console{token: "test-token", logPath: logPath, keysPath: keysPath, chainID: consoleChain}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// Without the startup token, nothing but the page itself is reachable (ADR-0015).
func TestConsoleRequiresItsToken(t *testing.T) {
	h := newConsole(t).handler()
	for _, path := range []string{"/api/state", "/api/state?token=wrong", "/api/approve"} {
		if code := get(t, h, path).Code; code != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, code)
		}
	}
	if code := get(t, h, "/").Code; code != http.StatusOK {
		t.Errorf("the page itself = %d, want 200", code)
	}
}

func TestConsoleStateShowsReceiptsAndVerifies(t *testing.T) {
	h := newConsole(t).handler()
	rec := get(t, h, "/api/state?token=test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("state = %d: %s", rec.Code, rec.Body.String())
	}
	var got stateReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ChainID != consoleChain || got.Mode != "read-only" {
		t.Fatalf("chain %q mode %q", got.ChainID, got.Mode)
	}
	if !got.Verify.OK || got.Verify.Receipts != 2 {
		t.Fatalf("verify %+v", got.Verify)
	}
	if len(got.Receipts) != 2 {
		t.Fatalf("%d receipts", len(got.Receipts))
	}
	// Newest first, and each receipt carries what it decided.
	if got.Receipts[0].Seq != 1 || got.Receipts[1].Seq != 0 {
		t.Fatalf("order: %d then %d", got.Receipts[0].Seq, got.Receipts[1].Seq)
	}
	if got.Receipts[1].Outcome != string(receipt.Allow) || got.Receipts[1].Rule != "small_refunds_unattended" {
		t.Fatalf("decision view %+v", got.Receipts[1])
	}
	if got.Receipts[1].Tool != "payments/refund" || !strings.Contains(got.Receipts[1].Actor, "alice@tenant-a") {
		t.Fatalf("decision view %+v", got.Receipts[1])
	}
	if len(got.Pending) != 0 {
		t.Fatalf("read-only console listed %d pending calls", len(got.Pending))
	}
}

// A console started without an approver key cannot approve, whatever is posted to it.
func TestReadOnlyConsoleCannotApprove(t *testing.T) {
	h := newConsole(t).handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/approve", strings.NewReader(`{"seq":0}`))
	req.Header.Set("X-Warden-Console-Token", "test-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("approve on a read-only console = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "read-only") {
		t.Fatalf("unhelpful refusal: %s", rec.Body.String())
	}
}

// A tampered log is reported as failing rather than quietly shown.
func TestConsoleReportsATamperedLog(t *testing.T) {
	c := newConsole(t)
	data, err := os.ReadFile(c.logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	marker := []byte(`"payload":"`)
	i := bytes.Index(lines[0], marker) + len(marker) + 10
	if lines[0][i] == 'A' {
		lines[0][i] = 'B'
	} else {
		lines[0][i] = 'A'
	}
	if err := os.WriteFile(c.logPath, bytes.Join(lines, []byte("\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := get(t, c.handler(), "/api/state?token=test-token")
	var got stateReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Verify.OK {
		t.Fatal("a tampered log verified")
	}
	if !strings.Contains(got.Verify.Detail, "bad_signature") {
		t.Fatalf("detail %q does not name the failure", got.Verify.Detail)
	}
}
