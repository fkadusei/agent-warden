package scenario

import (
	"strings"
	"testing"
)

const withMatch = `{
  "v": 1,
  "id": "authz-large-refund",
  "category": "authz",
  "threat": "W2",
  "title": "A refund above the limit",
  "principal": "alice@tenant-a",
  "task": "Refund 2500 on payment p-2500.",
  "steps": [
    {"call": "payments.refund", "args": {"payment_id": "p-2500", "amount": 2500}, "attack": true,
     "expect": "pending_approval", "match": ["payment_id"]},
    {"call": "web.fetch", "args": {"url": "https://x.example"}, "attack": true, "expect": "denied", "match": []}
  ]
}`

func TestMatchAndAuthz(t *testing.T) {
	s, err := Parse([]byte(withMatch))
	if err != nil {
		t.Fatal(err)
	}
	if s.Category != Authz {
		t.Fatalf("category %q", s.Category)
	}
	if m := s.Steps[0].Match; m == nil || len(*m) != 1 || (*m)[0] != "payment_id" {
		t.Fatalf("match %v", m)
	}
	if m := s.Steps[1].Match; m == nil || len(*m) != 0 {
		t.Fatalf("an empty match list must be kept, got %v", m)
	}
	if s.Steps[0].Match != nil && s.Steps[0].Args["amount"] == nil {
		t.Fatal("args lost")
	}

	r := func(old, new string) string { return strings.Replace(withMatch, old, new, 1) }
	for name, data := range map[string]string{
		"match names a missing argument": r(`"match": ["payment_id"]`, `"match": ["to"]`),
		"match repeats an argument":      r(`"match": ["payment_id"]`, `"match": ["payment_id", "payment_id"]`),
		"authz without a threat":         r(`"threat": "W2",`, ``),
	} {
		t.Run(name, func(t *testing.T) {
			if data == withMatch {
				t.Fatal("mutation did not apply")
			}
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
