# ADR-0007: Cedar for tool-call authorization

- **Status:** Accepted
- **Date:** 2026-09-14
- **Related:** threats W1, W2, W4, W6; ADR-0006 (Go gateway); design §2, §9

## Context

Every tool call is authorized on the principal, the agent, the tool, the arguments
(e.g. amount limits, recipient domains), and the taint state of the agent's context.
The engine must be embeddable in the Go gateway, deny by default, and produce a
decision that can be recorded and reproduced from a receipt (`policy_revision`,
`rule`).

The candidates were OPA/Rego (`github.com/open-policy-agent/opa`, v1.20.2) and Cedar
(`github.com/cedar-policy/cedar-go`, v1.8.0). Both embed as Go libraries.

## Decision

**Use Cedar via `cedar-go`.**

- **Entities:** principal (human), agent, tool, task.
- **Context:** tool arguments (after validation), taint sources, and approval state.
- **Default deny.** `forbid` overrides `permit`, so hard limits cannot be relaxed by a
  later `permit`.
- **Three outcomes from a two-outcome engine.** Cedar returns only allow or deny, so
  Warden evaluates two actions per call:
  1. `Action::"call"` — if denied, the decision is **deny**;
  2. `Action::"call_unattended"` — if allowed, the decision is **allow**; otherwise
     **require_approval**.
- **Receipts record** the policy set digest as `policy_revision` and the IDs of the
  determining policies as `rule`.

## Consequences

- Policies read as authorization rules rather than general programs, which makes them
  easier for a security reviewer to audit.
- `forbid`-wins semantics give a clean way to express limits that must never be
  overridden (e.g. no external email while tainted content is in context).
- The two-action pattern must be tested explicitly: a call permitted for `call` but
  not `call_unattended` must always yield `require_approval`, never `allow`.
- Cedar's formal analysis tooling lives mainly in the Rust ecosystem. Which schema
  validation and analysis features `cedar-go` supports must be checked before
  Phase 2, and documented rather than assumed.
- Complex data joins are harder than in Rego. Anything beyond entity attributes and
  request context must be computed by the gateway before evaluation.

## Alternatives considered

- **OPA/Rego** — very flexible, widely deployed, and supports multi-valued decisions
  directly. But Rego is a general-purpose policy language, harder to audit for
  authorization mistakes, and its flexibility is more than Warden needs.
- **Hand-written Go rules** — simplest to start, but policy changes become code
  changes, and decisions are hard to review independently of the gateway.

## Implementation notes (2026-09-14, `internal/policy`)

Confirmed against `cedar-go` v1.8.0 before and during implementation:

- **Cedar skips a policy that fails to evaluate.** When a `forbid` errors (for
  example, it reads an argument the agent left out), it simply stops applying, and a
  `permit` elsewhere can allow the call. Warden therefore treats **any** evaluation
  error on either action as a deny, recorded as `rule: "error:<policy ids>"`. A test
  pins this down: an erroring `no_external_mail` forbid denies a call that
  `mail_allowed` would otherwise allow.
- **Every policy needs a unique `@id("...")` annotation.** Cedar reports the
  determining policies in `Diagnostic.Reasons`; Warden records their IDs as the
  receipt's `rule` (sorted, comma-separated, capped to the receipt field limit). A
  default deny has no determining policy, so `rule` is empty.
- **`policy_revision` is the SHA-256 of the policy document bytes**, so an auditor
  can hash the file they were given and match it to receipts.
- **Request shape:** `principal` is `User::"<principal>"` with a `Role` parent per
  role; `resource` is `Tool::"<server>/<tool>"` with a `Server` parent; `context` is
  `{agent, task, args, taint}`.
- **Arguments are converted strictly.** Cedar has no floats or nulls, so anything it
  cannot represent exactly is refused, not approximated: non-integer numbers,
  integers beyond ±(2^53 − 1), nulls, duplicate keys, and nesting deeper than 16.
  Refused input yields a deny with `rule: "invalid_input"`.
- `cedar.Authorize` is used; `PolicySet.IsAuthorized` is deprecated in v1.8.0.
