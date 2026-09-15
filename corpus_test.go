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
	minimum := map[scenario.Category]int{scenario.Injection: 4, scenario.Exfil: 3, scenario.Deputy: 3, scenario.Benign: 3}
	count := map[scenario.Category]int{}
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
