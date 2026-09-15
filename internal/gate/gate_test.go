package gate

import (
	"bytes"
	"context"
	"testing"
)

// TestGate is the Phase 2 gate: every scenario must hold.
func TestGate(t *testing.T) {
	var out bytes.Buffer
	results, err := Run(context.Background(), &out)
	t.Log("\n" + out.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(Scenarios) {
		t.Fatalf("ran %d of %d scenarios", len(results), len(Scenarios))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s %s: %v", r.ID, r.Name, r.Err)
		}
	}
}
