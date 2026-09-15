package gate

import (
	"bytes"
	"context"
	"testing"

	agentwarden "github.com/fkadusei/agent-warden"
	"github.com/fkadusei/agent-warden/internal/scenario"
)

// TestCorpusGate is the Phase 3 gate: every scenario holds against the example
// deployment, driven by an agent that makes every attack call.
func TestCorpusGate(t *testing.T) {
	all, err := agentwarden.Scenarios()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	results := RunCorpus(context.Background(), &out, all, CorpusOptions{})
	t.Log("\n" + out.String())
	if len(results) != len(all) {
		t.Fatalf("ran %d of %d scenarios", len(results), len(all))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s: %v", r.Scenario.ID, r.Err)
		}
		if len(r.Steps) != len(r.Scenario.Steps) {
			t.Errorf("%s: ran %d of %d steps", r.Scenario.ID, len(r.Steps), len(r.Scenario.Steps))
		}
	}
}

// The gate must be able to fail: with a policy that permits everything, every attack
// scenario fails (its attack calls reach the tools) while benign work still passes.
func TestCorpusGateCatchesPermissivePolicy(t *testing.T) {
	all, err := agentwarden.Scenarios()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	results := RunCorpus(context.Background(), &out, all, CorpusOptions{
		Policy: `@id("permit_everything") permit (principal, action, resource);`,
	})
	t.Log("\n" + out.String())
	for _, r := range results {
		blocked, attacks := r.Blocked()
		switch r.Scenario.Category {
		case scenario.Benign:
			if r.Err != nil {
				t.Errorf("%s: benign scenario failed under a permissive policy: %v", r.Scenario.ID, r.Err)
			}
		default:
			if r.Err == nil {
				t.Errorf("%s: attack scenario passed under a permissive policy", r.Scenario.ID)
			}
			if blocked != 0 {
				t.Errorf("%s: %d of %d attacks reported blocked with nothing blocking them", r.Scenario.ID, blocked, attacks)
			}
		}
	}
}
