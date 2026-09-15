package main

import (
	"encoding/json"
	"testing"

	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// The example policy written by `warden init` must stop the injection, deputy, and
// exfiltration follow-on calls while leaving ordinary work alone.
func TestExamplePolicy(t *testing.T) {
	eng, err := policy.Load("policy.cedar", []byte(examplePolicy))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		server   string
		tool     string
		args     string
		taint    []string
		want     receipt.DecisionResult
		wantRule string
	}{
		{"small refund", "payments", "refund", `{"payment_id":"p-1","amount":50}`, nil, receipt.Allow, ""},
		{"small refund after planted instructions", "payments", "refund", `{"payment_id":"p-1","amount":50}`, []string{"flag:instruction"}, receipt.RequireApproval, ""},
		{"small refund after another principal's ticket", "payments", "refund", `{"payment_id":"p-1","amount":50}`, []string{"foreign_principal"}, receipt.RequireApproval, ""},
		{"large refund", "payments", "refund", `{"payment_id":"p-1","amount":500}`, nil, receipt.RequireApproval, ""},
		{"email inside tenant", "mail", "send", `{"to":"bob@tenant-a.example","body":"hi"}`, nil, receipt.Allow, ""},
		{"customer data to a colleague", "mail", "send", `{"to":"bob@tenant-a.example","body":"hi"}`, []string{"pii"}, receipt.Allow, ""},
		{"customer data outside the tenant", "mail", "send", `{"to":"x@evil.example","body":"hi"}`, []string{"pii"}, receipt.Deny, "no_pii_outside_tenant"},
		{"lookalike tenant domain", "mail", "send", `{"to":"x@tenant-a.example.evil.example","body":"hi"}`, []string{"pii"}, receipt.Deny, "no_pii_outside_tenant"},
		{"email after planted instructions", "mail", "send", `{"to":"bob@tenant-a.example","body":"hi"}`, []string{"flag:instruction"}, receipt.RequireApproval, ""},
		{"email after web content", "mail", "send", `{"to":"bob@tenant-a.example","body":"hi"}`, []string{"web"}, receipt.Deny, "no_email_while_tainted"},
		{"customer data, no recipient", "mail", "send", `{"body":"hi"}`, []string{"pii"}, receipt.Deny, ""},
		{"CRM lookup after planted instructions", "crm", "lookup", `{"id":"c-1"}`, []string{"flag:instruction", "foreign_principal"}, receipt.Allow, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := eng.Decide(policy.Input{
				Principal: "alice@tenant-a", Roles: []string{"support"}, Agent: "support-agent-7", TaskID: "t1",
				Server: tc.server, Tool: tc.tool, Args: json.RawMessage(tc.args), Taint: tc.taint,
			})
			if err != nil {
				t.Fatal(err)
			}
			if d.Result != tc.want || (tc.wantRule != "" && d.Rule != tc.wantRule) {
				t.Fatalf("got %s (rule %q, errors %v), want %s (rule %q)", d.Result, d.Rule, d.Errors, tc.want, tc.wantRule)
			}
		})
	}
}
