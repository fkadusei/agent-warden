package exampletools

// Policy is the Cedar policy `warden init` writes for the example servers. Every
// policy needs a unique @id.
const Policy = `// Example policy for the example tool servers. Every policy needs a unique @id.

// Support staff can use the CRM and read tickets without approval.
@id("support_crm")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource in Server::"crm");

@id("support_tickets")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"tickets/get");

// Refunds need a human approver...
@id("refunds_need_approval")
permit (principal in Role::"support", action == Action::"call", resource == Tool::"payments/refund");

// ...unless they are small.
@id("small_refunds_unattended")
permit (principal in Role::"support", action == Action::"call_unattended", resource == Tool::"payments/refund")
when { context.args.amount <= 100 };

@id("web_fetch")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"web/fetch");

@id("mail_read")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"mail/inbox");

@id("mail_allowed")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"mail/send");

// Once untrusted web content is in the task, no email goes out.
@id("no_email_while_tainted")
forbid (principal, action, resource == Tool::"mail/send")
when { context.taint.contains("web") };

// Untrusted content (web pages, incoming email, another principal's writing, or
// planted instructions) can still be read, but refunds and email then need a human
// approver. This holds even when the inspector finds nothing suspicious.
@id("untrusted_content_needs_approval")
forbid (principal, action == Action::"call_unattended", resource)
when {
  (resource == Tool::"payments/refund" || resource == Tool::"mail/send") &&
  (context.taint.contains("web") || context.taint.contains("email") ||
   context.taint.contains("foreign_principal") || context.taint.contains("flag:instruction"))
};

// Customer data never leaves the tenant by email...
@id("no_pii_outside_tenant")
forbid (principal, action, resource == Tool::"mail/send")
when { context.taint.contains("pii") && !(context.args.to like "*@tenant-a.example") };

// ...or inside a web request.
@id("no_web_with_pii")
forbid (principal, action, resource == Tool::"web/fetch")
when { context.taint.contains("pii") };
`

// Broker is the credential broker configuration `warden init` writes.
const Broker = `{
  "v": 1,
  "bindings": [
    {"server": "payments", "tool": "*", "inject": "header", "name": "Authorization", "prefix": "Bearer ", "secret": "env:WARDEN_SECRET_PAYMENTS"}
  ]
}
`

// Roles returns the example principals and their roles.
func Roles() map[string][]string {
	return map[string][]string{"alice@tenant-a": {"support"}}
}

// Taint returns the label each server's output adds.
func Taint() map[string]string {
	return map[string]string{"web": "web"}
}

// ToolTaint returns the label each tool's output adds: customer records are personal
// data, and incoming email is untrusted.
func ToolTaint() map[string]string {
	return map[string]string{"crm/lookup": "pii", "mail/inbox": "email"}
}
