package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/keys"
)

// TestDemo runs the demo end to end and checks every step and every artifact,
// so the demo cannot silently stop demonstrating what it claims.
func TestDemo(t *testing.T) {
	out := filepath.Join(t.TempDir(), "demo")
	var printed bytes.Buffer
	res, err := run(out, &printed)
	if err != nil {
		t.Fatalf("demo failed: %v\n%s", err, printed.String())
	}

	want := []outcome{
		{"crm lookup", "ok", "support_crm"},
		{"small refund", "ok", "small_refunds_unattended"},
		{"large refund", "pending_approval", "refunds_need_approval"},
		{"resume before approval", "error", ""},
		{"self-approval", "refused", ""},
		{"approval by bob", "approved", ""},
		{"resume after approval", "ok", "refunds_need_approval"},
		{"web fetch with hidden instructions", "ok", "web_fetch"},
		{"email after web content", "denied", "no_email_while_tainted"},
		{"export after rug pull", "denied", "tool_changed"},
		{"tool that echoes its credential", "ok", "support_crm"},
		{"tool policy does not permit", "denied", ""},
	}
	if len(res.Steps) != len(want) {
		t.Fatalf("got %d steps, want %d: %+v", len(res.Steps), len(want), res.Steps)
	}
	for i, w := range want {
		if res.Steps[i] != w {
			t.Errorf("step %d: got %+v, want %+v", i+1, res.Steps[i], w)
		}
	}
	if strings.Contains(printed.String(), demoToken) {
		t.Fatal("the demo printed the simulated credential")
	}
	logData, err := os.ReadFile(res.Log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logData), demoToken) {
		t.Fatal("the receipt log contains the simulated credential")
	}

	keyData, err := os.ReadFile(res.Keys)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := keys.Parse(keyData)
	if err != nil {
		t.Fatal(err)
	}
	anchorData, err := os.ReadFile(res.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	cps, err := checkpoint.ReadVerified(bytes.NewReader(anchorData), res.ChainID, keys.Resolver(trusted))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := chain.VerifyWithCheckpoints(bytes.NewReader(logData), res.ChainID, keys.Resolver(trusted), cps)
	if err != nil {
		t.Fatalf("demo log does not verify: %v", err)
	}
	if rep.Receipts != res.Receipts || rep.Unanchored != 0 {
		t.Fatalf("report %+v", rep)
	}

	for name, reason := range map[string]chain.Reason{
		"edited-receipt.jsonl":  chain.ReasonBadSignature,
		"deleted-receipt.jsonl": chain.ReasonSeqGap,
		"truncated.jsonl":       chain.ReasonCheckpointMismatch,
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(res.Tampered[name])
			if err != nil {
				t.Fatal(err)
			}
			_, err = chain.VerifyWithCheckpoints(bytes.NewReader(data), res.ChainID, keys.Resolver(trusted), cps)
			var f *chain.Failure
			if !errors.As(err, &f) || f.Reason != reason {
				t.Fatalf("got %v, want %s", err, reason)
			}
		})
	}

	t.Run("refuses to overwrite an existing demo", func(t *testing.T) {
		if _, err := run(out, io.Discard); err == nil {
			t.Fatal("ran into a non-empty directory")
		}
	})
}
