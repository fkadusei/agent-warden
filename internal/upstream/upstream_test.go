package upstream

import (
	"slices"
	"strings"
	"testing"
)

func TestAuthors(t *testing.T) {
	got, err := Authors(map[string]any{AuthorsMetaKey: []any{"bob@tenant-b", "alice@tenant-a"}})
	if err != nil || !slices.Equal(got, []string{"bob@tenant-b", "alice@tenant-a"}) {
		t.Fatalf("Authors() = %v, %v", got, err)
	}
	for name, meta := range map[string]map[string]any{
		"nil meta":   nil,
		"no key":     {"other": "x"},
		"empty list": {AuthorsMetaKey: []any{}},
	} {
		if got, err := Authors(meta); err != nil || len(got) != 0 {
			t.Errorf("%s: Authors() = %v, %v; want none", name, got, err)
		}
	}
}

// Provenance that is present but unreadable must fail, never pass as unlabeled.
func TestAuthorsRejectsMalformed(t *testing.T) {
	many := make([]any, maxAuthors+1)
	for i := range many {
		many[i] = "p@tenant"
	}
	for name, v := range map[string]any{
		"string not list": "bob@tenant-b",
		"number entry":    []any{float64(7)},
		"empty entry":     []any{""},
		"too long":        []any{strings.Repeat("a", maxAuthorLen+1)},
		"control char":    []any{"bob\n@tenant-b"},
		"too many":        many,
		"null":            nil,
	} {
		if _, err := Authors(map[string]any{AuthorsMetaKey: v}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
