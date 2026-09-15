# Phase 2 plan — the gateway

- **Status:** In progress
- **Date:** 2026-09-14
- **Goal (design §7):** identity, policy, approvals, credential broker, tool registry,
  and write-ahead receipts, with the `authz`, `approval`, `poison`, and fail-closed
  tests passing.

## Build order

Each step is usable and tested on its own before the next starts. The MCP wiring
comes last, so every security decision is testable without a protocol in the way.

| Step | Component | Package | Threats | Depends on |
|---|---|---|---|---|
| 2.1 | **Durable write-ahead receipt store** | `internal/store` | W8, W9 | Phase 1 |
| 2.2 | **Tool registry** — pin each tool manifest by digest; refuse changed manifests | `internal/registry` | W5 | 2.1 |
| 2.3 | **Policy** — Cedar, two-action pattern, `policy_revision` = digest of the policy set | `internal/policy` | W1, W2, W4 | — |
| 2.4 | **Approvals** — approval receipts, single-use, distinct approver, bound to the call and an expiry | `internal/approval` | W6 | 2.1, **ADR-0009** |
| 2.5 | **Identity** — short-lived task credentials (plain ML-DSA-65 X.509) naming agent, principal, and task | `internal/identity` | W3, W4 | **OID decision** |
| 2.6 | **Credential broker** — inject tool credentials at execution; the agent never holds them | `internal/broker` | W3 | 2.5 |
| 2.7 | **Enforcement pipeline** — identify → pin → decide → receipt → approve → execute → inspect → receipt, as a plain Go API | `internal/gateway` | all of the above | 2.1–2.6 |
| 2.8 | **MCP transport** — MCP server to the agent (one untyped `AddTool` handler per registered tool), MCP client to upstream tools (`ClientSession.CallTool`) | `cmd/warden` | W7 | 2.7 |
| 2.9 | **Phase gate** — `authz`, `approval`, `poison`, fail-closed scenarios | tests | — | 2.8 |

## Decisions needed from the owner

1. **OID arc for the Ed25519 binding extension (ADR-0008).** Proposal: use a
   UUID-based OID under `2.25` (ITU-T X.667 / RFC 4122 §4.1 via ISO/IEC 9834-8). It
   needs no registration, is globally unique, and can be generated once and fixed in
   the code. The alternative is registering an IANA Private Enterprise Number, which
   takes time and ties the OID to an organization.
2. **Approval receipts (ADR-0009, to write before step 2.4).** Proposed body:
   `approval: {decision_seq, call_digest, approver, expires_ts}` where `call_digest`
   covers tool, manifest, and args commitment; the approver must differ from the
   principal; one approval per decision; a result for a `require_approval` decision
   is valid only after a matching, unexpired approval. `warden-verify`'s
   `missing_approval` check then becomes a real check instead of always failing.
3. **How approvers approve in the demo.** Proposal: a small CLI
   (`warden approve <decision_seq>`) authenticated by the approver's own key, rather
   than a web UI.

## Library facts checked (2026-09-14)

- **`cedar-go` v1.8.0:** `NewPolicySetFromBytes`, `PolicySet.IsAuthorized(entities,
  Request)` returns a `Decision` and a `Diagnostic` whose `Reasons` carry the IDs of
  the determining policies (recorded as `rule`) and whose `Errors` carry evaluation
  errors (which must fail closed). Schema validation exists only under
  `x/exp/schema` (experimental), so policies are tested, not schema-validated, for now.
- **MCP Go SDK v1.8.0:** `Server.AddTool(*Tool, ToolHandler)` receives raw JSON
  arguments, so Warden validates and commits to them itself; `ClientSession.ListTools`
  and `CallTool` reach upstream servers; `NewInMemoryTransports` supports tests;
  `CommandTransport` runs stdio tool servers.
- **`modernc.org/sqlite` v1.58.0:** pure Go (keeps `warden-verify` static), with
  validated DSN settings `_journal_mode=WAL` and `_synchronous=FULL`.
