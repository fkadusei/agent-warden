package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fkadusei/agent-warden/internal/keys"
)

// The console over a rotated chain, holding only the key the chain began with.
// Without the root it cannot follow the handover; with it, both the verify panel
// and the feed see the whole log.
func TestConsoleFollowsRotationsWithARoot(t *testing.T) {
	dir, cfgPath := initChain(t)
	appendDecisions(t, loadCfg(t, cfgPath), 2)
	runOK(t, "", "rotate-key", "--config", cfgPath, "--kid", "warden-e2")
	cfg := loadCfg(t, cfgPath)
	appendDecisions(t, cfg, 1)

	logPath := filepath.Join(dir, "console-log.jsonl")
	runOK(t, "", "export", "--config", cfgPath, "--out", logPath)

	// An auditor's trust file: one key, the one the chain started with.
	trusted := trustFor(t, cfg)
	if trusted["warden-e1"] == nil {
		t.Fatal("the retired key is missing from the trust file")
	}
	set, err := json.Marshal(keys.Set{Keys: []keys.JWK{keys.PublicJWK("warden-e1", trusted["warden-e1"])}})
	if err != nil {
		t.Fatal(err)
	}
	genesisOnly := filepath.Join(dir, "genesis-only.json")
	if err := os.WriteFile(genesisOnly, set, 0o644); err != nil {
		t.Fatal(err)
	}

	state := func(t *testing.T, rootPath string) stateReply {
		t.Helper()
		c := &console{token: "test-token", logPath: logPath, keysPath: genesisOnly,
			chainID: cfg.ChainID, rootPath: rootPath}
		rec := get(t, c.handler(), "/api/state?token=test-token")
		if rec.Code != http.StatusOK {
			t.Fatalf("state = %d: %s", rec.Code, rec.Body.String())
		}
		var got stateReply
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("with the root", func(t *testing.T) {
		got := state(t, filepath.Join(dir, "pki", "ca.pem"))
		if !got.Verify.OK {
			t.Fatalf("a healthy rotated log was reported as failing: %+v", got.Verify)
		}
		if got.Verify.Receipts != 4 || got.Verify.Rotations != 1 {
			t.Fatalf("verify %+v, want 4 receipts and 1 rotation", got.Verify)
		}
		// The feed must show what the incoming key signed, not silently drop it.
		if len(got.Receipts) != 4 {
			t.Fatalf("the feed shows %d of 4 receipts", len(got.Receipts))
		}
	})

	t.Run("without the root", func(t *testing.T) {
		got := state(t, "")
		if got.Verify.OK {
			t.Fatal("a rotated log verified with nothing to vouch for the incoming key")
		}
		if !strings.Contains(got.Verify.Detail, "uncertified_key") {
			t.Fatalf("detail %q does not explain why", got.Verify.Detail)
		}
		// summarize skips receipts it cannot resolve, so the last one is missing:
		// this is exactly what the root is for.
		if len(got.Receipts) != 3 {
			t.Fatalf("the feed shows %d receipts, want the 3 the retired key signed", len(got.Receipts))
		}
	})
}
