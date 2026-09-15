# ADR-0009: Approval receipts

- **Status:** Accepted
- **Date:** 2026-09-14
- **Related:** threat W6; ADR-0004, ADR-0007 (require_approval); design §4.1, §5

## Context

Policy can return `require_approval` (ADR-0007). Until now there was no receipt that
records an approval, so `warden-verify` treats every result for a
`require_approval` decision as `missing_approval`. The threat model (W6) requires
that gated calls execute only with a recorded approval that names the exact call,
comes from someone other than the requester, expires, and cannot be reused.

## Decision

### Receipt

An `approval` receipt carries the same `task_id`, `actor`, and `call` as the decision
it answers, plus:

```json
"approval": {
  "decision_seq": 6,
  "outcome": "approved",
  "approver": "bob@tenant-a",
  "statement": "sha256:…",
  "expires_ts": "2026-09-14T15:34:05.000Z"
}
```

| Field | Meaning |
|---|---|
| `decision_seq` | The `require_approval` decision this answers |
| `outcome` | `approved` or `rejected` |
| `approver` | The approver's identity; must differ from `actor.principal` |
| `statement` | Digest of the approver's own signed approval statement (below) |
| `expires_ts` | After this, the approval can no longer authorize execution; must be later than the receipt's `ts` |

### Approver statement

The approver signs a statement with **their own** key, not Warden's:

```json
{"domain":"agent-warden/approval-statement/v1","chain_id":…,"decision_seq":…,
 "call_digest":…,"outcome":…,"approver":…,"expires_ts":…,"ts":…}
```

`call_digest` is the SHA-256 of the canonical `{task_id, actor, call}` the approver
was shown. Warden verifies the statement against its list of trusted approver keys
before writing the approval receipt, and stores the full statement separately
(like commitment openings, ADR-0005). The receipt holds its digest, so the approval
can later be proven without trusting Warden.

### Rules enforced by `warden-verify`

1. An approval must reference an earlier `require_approval` decision with the same
   task, actor, and call. Otherwise: `bad_reference`.
2. At most one approval per decision. Otherwise: `duplicate_approval`.
3. `approver` must differ from `actor.principal`. Otherwise: `self_approval`.
4. A result for a `require_approval` decision needs an earlier approval with outcome
   `approved`. Otherwise: `missing_approval`. If the outcome was `rejected`:
   `rejected_call_executed`.
5. The result's `ts` must not be after the approval's `expires_ts`. Otherwise:
   `approval_expired`.

Checking the approver's signature on the statement needs the stored statements and
the approver keys; this is an optional, separate verification step.

### Approver experience (demo)

A small command, `warden approve <decision_seq>` (and `--reject`), shows the call,
signs the statement with the approver's key, and submits it. No web UI in Phase 2.

## Consequences

- `missing_approval` becomes a real check, and self-approval, reuse, rejection, and
  expiry become detectable from the log alone.
- Approver keys are a second trust list to manage. Compromise of an approver key
  allows false approvals, but not execution of calls that policy denies.
- Expiry is checked against receipt timestamps, which Warden writes. A compromised
  Warden could backdate a result; anchored checkpoints bound how far.
- Receipt types `key_rotation` and `checkpoint` remain reserved.

## Alternatives considered

- **Approval recorded only by Warden, no approver signature** — simpler, but the
  approval is only as trustworthy as Warden, which defeats the point of W6.
- **Approver signs the receipt itself** — mixes two signers in the chain and
  complicates verification; a separate statement keeps receipts uniform.
- **Web approval queue** — nicer for a real deployment, but UI work unrelated to the
  security claims being demonstrated.
