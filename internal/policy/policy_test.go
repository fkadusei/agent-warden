package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const policies = `
@id("support_crm")
permit (principal in Role::"support", action == Action::"call", resource in Server::"crm");

@id("support_crm_unattended")
permit (principal in Role::"support", action == Action::"call_unattended", resource in Server::"crm");

@id("refunds_need_approval")
permit (principal in Role::"support", action == Action::"call", resource == Tool::"payments/refund");

@id("small_refunds_unattended")
permit (principal in Role::"support", action == Action::"call_unattended", resource == Tool::"payments/refund")
when { context.args.amount <= 100 };

@id("mail_allowed")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"mail/send");

@id("no_email_while_tainted")
forbid (principal, action, resource == Tool::"mail/send")
when { context.taint.contains("web") };

@id("no_external_mail")
forbid (principal, action, resource == Tool::"mail/send")
when { context.args.to like "*@external.example" };

@id("crm_export_only_for_approved_agent")
forbid (principal, action, resource == Tool::"crm/export")
unless { context.agent == "cert-sha256:approved" };

@id("tagged_tickets")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"tickets/update")
when { context.args.tags.contains("customer") && context.args.meta.priority < 3 };
`

func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := Load("warden.cedar", []byte(policies))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func call(server, tool, args string) Input {
	return Input{
		Principal: "alice@tenant-a",
		Roles:     []string{"support"},
		Agent:     "cert-sha256:ab12",
		TaskID:    "t1",
		Server:    server,
		Tool:      tool,
		Args:      json.RawMessage(args),
	}
}

func TestDecisions(t *testing.T) {
	e := engine(t)
	tainted := call("mail", "send", `{"to":"bob@tenant-a.example"}`)
	tainted.Taint = []string{"web"}
	noRole := call("crm", "lookup", `{}`)
	noRole.Roles = nil
	approvedAgent := call("crm", "export", `{}`)
	approvedAgent.Agent = "cert-sha256:approved"

	cases := []struct {
		name   string
		in     Input
		result receipt.DecisionResult
		rule   string
	}{
		{"read-only CRM call runs unattended", call("crm", "lookup", `{"id":"c-100"}`), receipt.Allow, "support_crm_unattended"},
		{"small refund runs unattended", call("payments", "refund", `{"amount":50}`), receipt.Allow, "small_refunds_unattended"},
		{"large refund needs approval", call("payments", "refund", `{"amount":500}`), receipt.RequireApproval, "refunds_need_approval"},
		{"internal email allowed", call("mail", "send", `{"to":"bob@tenant-a.example"}`), receipt.Allow, "mail_allowed"},
		{"email forbidden while tainted", tainted, receipt.Deny, "no_email_while_tainted"},
		{"email to external domain forbidden", call("mail", "send", `{"to":"x@external.example"}`), receipt.Deny, "no_external_mail"},
		{"unknown tool denied by default", call("fs", "delete", `{}`), receipt.Deny, ""},
		{"principal without role denied", noRole, receipt.Deny, ""},
		{"export forbidden for other agents", call("crm", "export", `{}`), receipt.Deny, "crm_export_only_for_approved_agent"},
		{"export allowed for the approved agent", approvedAgent, receipt.Allow, "support_crm_unattended"},
		{"nested args and sets", call("tickets", "update", `{"tags":["customer","vip"],"meta":{"priority":1}}`), receipt.Allow, "tagged_tickets"},
		{"nested args fail condition", call("tickets", "update", `{"tags":["internal"],"meta":{"priority":1}}`), receipt.Deny, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := e.Decide(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Result != c.result || d.Rule != c.rule {
				t.Fatalf("got %s rule=%q errors=%v, want %s rule=%q", d.Result, d.Rule, d.Errors, c.result, c.rule)
			}
			if d.PolicyRevision != e.Revision() {
				t.Fatal("decision does not carry the policy revision")
			}
		})
	}
}

// Cedar skips a policy that errors. An erroring forbid must not let a call through.
func TestEvaluationErrorsFailClosed(t *testing.T) {
	e := engine(t)

	t.Run("erroring forbid denies instead of allowing", func(t *testing.T) {
		// no_external_mail reads context.args.to, which is missing. Without fail
		// closed, mail_allowed would allow this call.
		d, err := e.Decide(call("mail", "send", `{"subject":"hi"}`))
		if err != nil {
			t.Fatal(err)
		}
		if d.Result != receipt.Deny || !strings.HasPrefix(d.Rule, "error:") || !strings.Contains(d.Rule, "no_external_mail") || len(d.Errors) == 0 {
			t.Fatalf("got %s rule=%q errors=%v, want deny with error:no_external_mail", d.Result, d.Rule, d.Errors)
		}
	})

	t.Run("erroring unattended permit denies instead of requiring approval", func(t *testing.T) {
		d, err := e.Decide(call("payments", "refund", `{}`))
		if err != nil {
			t.Fatal(err)
		}
		if d.Result != receipt.Deny || d.Rule != "error:small_refunds_unattended" {
			t.Fatalf("got %s rule=%q, want deny with error:small_refunds_unattended", d.Result, d.Rule)
		}
	})
}

func TestInvalidInputDenies(t *testing.T) {
	e := engine(t)
	deep := strings.Repeat(`{"a":`, 20) + `1` + strings.Repeat(`}`, 20)
	cases := map[string]Input{
		"float amount":       call("payments", "refund", `{"amount":50.5}`),
		"integer too large":  call("payments", "refund", `{"amount":9007199254740993}`),
		"null value":         call("payments", "refund", `{"amount":null}`),
		"duplicate key":      call("payments", "refund", `{"amount":500,"amount":5}`),
		"args not an object": call("payments", "refund", `[1,2]`),
		"trailing garbage":   call("payments", "refund", `{"amount":5} x`),
		"too deep":           call("crm", "lookup", deep),
		"missing principal":  func() Input { c := call("crm", "lookup", `{}`); c.Principal = ""; return c }(),
		"missing agent":      func() Input { c := call("crm", "lookup", `{}`); c.Agent = ""; return c }(),
		"slash in server":    call("crm/x", "lookup", `{}`),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			d, err := e.Decide(in)
			if !errors.Is(err, ErrInput) {
				t.Fatalf("got err %v, want ErrInput", err)
			}
			if d.Result != receipt.Deny || d.Rule != "invalid_input" || d.PolicyRevision != e.Revision() {
				t.Fatalf("invalid input produced %+v", d)
			}
		})
	}
	t.Run("absent args are an empty object", func(t *testing.T) {
		if d, err := e.Decide(call("crm", "lookup", ``)); err != nil || d.Result != receipt.Allow {
			t.Fatalf("got %+v, %v", d, err)
		}
	})
}

func TestLoad(t *testing.T) {
	e := engine(t)
	if e.Revision() != digest.SHA256([]byte(policies)) {
		t.Fatal("revision is not the digest of the document")
	}
	e2, err := Load("warden.cedar", []byte(policies+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e2.Revision() == e.Revision() {
		t.Fatal("revision did not change with the document")
	}

	cases := map[string]string{
		"no @id":        `permit (principal, action, resource);`,
		"duplicate @id": `@id("a") permit (principal, action, resource); @id("a") forbid (principal, action, resource);`,
		"bad @id":       `@id("has space") permit (principal, action, resource);`,
		"syntax error":  `@id("a") permit (principal, action, resource`,
		"empty":         ``,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load("bad.cedar", []byte(text)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRuleFitsReceipt(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString(`@id("permit_number_` + strings.Repeat("x", 20) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + `") permit (principal, action, resource);` + "\n")
	}
	e, err := Load("many.cedar", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Decide(call("crm", "lookup", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Result != receipt.Allow || len(d.Rule) > maxRuleLen || !strings.Contains(d.Rule, "more") {
		t.Fatalf("rule of %d bytes: %q", len(d.Rule), d.Rule)
	}
	// The decision must still be receipt-valid.
	r := &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, ChainID: "c", Seq: 0, Prev: digest.SHA256(nil),
		TS: "2026-09-14T15:04:05.000Z", Type: receipt.TypeDecision, TaskID: "t1",
		Actor:    &receipt.Actor{Agent: "a", Principal: "p"},
		Call:     &receipt.Call{Tool: "crm/lookup", Manifest: digest.SHA256(nil), ArgsCommitment: digest.SHA256(nil)},
		Decision: &receipt.Decision{Result: d.Result, PolicyRevision: d.PolicyRevision, Rule: d.Rule},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("long rule makes an invalid receipt: %v", err)
	}
}
