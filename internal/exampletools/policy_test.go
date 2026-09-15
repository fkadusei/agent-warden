package exampletools

import (
	"encoding/json"
	"testing"

	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// The example policy must stop injection, deputy, and exfiltration follow-on calls
// while leaving ordinary work alone.
func TestPolicy(t *testing.T) {
	eng, err := policy.Load("policy.cedar", []byte(Policy))
	if err != nil {
		t.Fatal(err)
	}
	refund := `{"payment_id":"p-1","amount":50}`
	internal := `{"to":"bob@tenant-a.example","body":"hi"}`
	cases := []struct {
		name     string
		server   string
		tool     string
		args     string
		taint    []string
		want     receipt.DecisionResult
		wantRule string
	}{
		{"small refund", "payments", "refund", refund, nil, receipt.Allow, ""},
		{"small refund after planted instructions", "payments", "refund", refund, []string{"flag:instruction"}, receipt.RequireApproval, ""},
		{"small refund after another principal's ticket", "payments", "refund", refund, []string{"foreign_principal"}, receipt.RequireApproval, ""},
		{"small refund after incoming email", "payments", "refund", refund, []string{"email"}, receipt.RequireApproval, ""},
		{"small refund after a web page", "payments", "refund", refund, []string{"web"}, receipt.RequireApproval, ""},
		{"large refund", "payments", "refund", `{"payment_id":"p-1","amount":500}`, nil, receipt.RequireApproval, ""},
		{"read a ticket", "tickets", "get", `{"id":"T-1"}`, []string{"foreign_principal"}, receipt.Allow, ""},
		{"read the inbox", "mail", "inbox", `{}`, nil, receipt.Allow, ""},
		{"email inside tenant", "mail", "send", internal, nil, receipt.Allow, ""},
		{"customer data to a colleague", "mail", "send", internal, []string{"pii"}, receipt.Allow, ""},
		{"customer data outside the tenant", "mail", "send", `{"to":"x@evil.example","body":"hi"}`, []string{"pii"}, receipt.Deny, "no_pii_outside_tenant"},
		{"lookalike tenant domain", "mail", "send", `{"to":"x@tenant-a.example.evil.example","body":"hi"}`, []string{"pii"}, receipt.Deny, "no_pii_outside_tenant"},
		{"email after planted instructions", "mail", "send", internal, []string{"flag:instruction"}, receipt.RequireApproval, ""},
		{"email after incoming email", "mail", "send", internal, []string{"email"}, receipt.RequireApproval, ""},
		{"email after web content", "mail", "send", internal, []string{"web"}, receipt.Deny, "no_email_while_tainted"},
		{"customer data, no recipient", "mail", "send", `{"body":"hi"}`, []string{"pii"}, receipt.Deny, ""},
		{"web request", "web", "fetch", `{"url":"https://shop.example"}`, nil, receipt.Allow, ""},
		{"web request carrying customer data", "web", "fetch", `{"url":"https://collector.example/?c=1"}`, []string{"pii"}, receipt.Deny, "no_web_with_pii"},
		{"CRM lookup after planted instructions", "crm", "lookup", `{"id":"c-1"}`, []string{"flag:instruction", "foreign_principal"}, receipt.Allow, ""},
		{"salaries", "hr", "salaries", `{}`, nil, receipt.Deny, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := eng.Decide(policy.Input{
				Principal: "alice@tenant-a", Roles: Roles()["alice@tenant-a"], Agent: "support-agent-7", TaskID: "t1",
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
