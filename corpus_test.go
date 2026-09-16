package agentwarden

import (
	"slices"
	"testing"

	"github.com/fkadusei/agent-warden/internal/exampletools"
	"github.com/fkadusei/agent-warden/internal/scenario"
)

// The corpus must cover every Phase 3 category and only use tools and principals
// the example deployment actually has.
func TestCorpus(t *testing.T) {
	all, err := Scenarios()
	if err != nil {
		t.Fatal(err)
	}
	// Design §6 targets 30-40 attack scenarios and 10-15 benign tasks.
	minimum := map[scenario.Category]int{
		scenario.Injection: 10, scenario.Exfil: 6, scenario.Deputy: 6, scenario.Authz: 4, scenario.Benign: 10,
	}
	count := map[scenario.Category]int{}
	defer func() {
		if attacks := len(all) - count[scenario.Benign]; attacks < 30 {
			t.Errorf("%d attack scenarios, want at least 30", attacks)
		}
	}()
	tools, readable, roles := exampletools.Tools(), exampletools.Readable(), exampletools.Roles()
	for _, s := range all {
		count[s.Category]++
		if len(roles[s.Principal]) == 0 {
			t.Errorf("%s: principal %s has no role in the example deployment", s.ID, s.Principal)
		}
		for i, st := range s.Steps {
			if !slices.Contains(tools, st.Call) {
				t.Errorf("%s: steps[%d] calls unknown tool %s", s.ID, i, st.Call)
			}
		}
		for i, c := range s.Content {
			if !slices.Contains(readable, c.Tool) {
				t.Errorf("%s: content[%d] is planted in %s, which cannot serve content", s.ID, i, c.Tool)
			}
		}
	}
	for cat, n := range minimum {
		if count[cat] < n {
			t.Errorf("%d %s scenarios, want at least %d", count[cat], cat, n)
		}
	}
}
