# Phase 6 plan — key rotation and revocation

- **Status:** In progress
- **Date:** 2026-09-16
- **Goal:** close the largest gap in `docs/not-done.md`: retire a signing key on a
  schedule, and react to a compromised one, without abandoning the chain.
- **Design:** ADR-0016 — rotation is signed by the outgoing key *and* certified by the
  CA; revocation is effective from a named checkpoint.

## What must stay true

- **One trusted key still verifies a whole chain.** A verifier starts from the trust file
  (or the root) and learns each subsequent key from the log. The trust file does not grow.
- **The genesis binding is untouched.** `NewParams` still hashes the chain's first key;
  rotation adds to that history rather than rewriting it.
- **Old logs keep verifying byte for byte.** A chain that never rotates must behave
  exactly as it does today, including its `warden-verify` output.
- **Fail closed.** An unverifiable rotation, an uncertified key, or a receipt signed after
  its key was revoked is a verification failure, not a warning.

## Build order

| Step | Component | Where | Depends on |
|---|---|---|---|
| 6.1 ✅ | **The rotation receipt** — `receipt.Rotation` (from kid, to kid, incoming key digest, incoming key-epoch certificate as base64url DER, optional reason) with validation: both kids present and different, a real sha256 key digest, a bounded base64url certificate, and no task, actor, call, decision, result, or approval section. The other three types now reject a stray rotation section too. `TypeKeyRotation` is specified; `checkpoint` remains reserved | `internal/receipt` | ADR-0016 |
| 6.2 ✅ | **Rotation-aware verification** — one key signs a chain at a time: the key bound into the genesis parameters until a `key_rotation` receipt hands over, the incoming key after it. A handover must be signed by the outgoing key, and the incoming key's epoch certificate must chain to the CA roots — judged at the rotation's timestamp, so a log stays verifiable after the epoch it records expires. `keys.Rotating` learns each later key from the log, so the trust file still holds one; `chain.VerifyWithKeys` is the rotation-aware entry point and plain `Verify` fails closed on a rotation rather than trusting an uncertified key. New reasons: `wrong_key`, `bad_rotation`, `uncertified_key`. `Report.Rotations` lists the handovers for 6.6 | `internal/chain`, `internal/keys` | 6.1 |
| 6.3 | **Appending a rotation** — the store and appender switch keys atomically: the rotation receipt is the last one signed by the outgoing key, and the next receipt uses the incoming key. Resume after restart must pick up the current key | `internal/chain`, `internal/store` | 6.2 |
| 6.4 | **Revocation records** — a signed revocation naming a kid and the last checkpoint believed good, published to the anchor; parsing, verification, and the rule that receipts by that kid after that checkpoint are refused | `internal/checkpoint` or `internal/revocation` | 6.2 |
| 6.5 | **`warden rotate-key` and `warden revoke-key`** — issue the new epoch certificate from the CA, append the rotation, write the new key 0600, and publish a revocation | `cmd/warden` | 6.3, 6.4 |
| 6.6 | **`warden-verify --revocations`** — check revocations alongside the anchor, fail a log whose tail was signed after the effective checkpoint, and report rotations and revocations in both text and JSON | `cmd/warden-verify` | 6.4 |
| 6.7 | **Gate scenarios** — rotation mid-chain verifies; a rotation signed by the wrong key fails; a rotation whose incoming key is uncertified fails; receipts after a revocation's checkpoint fail; a log ending at the checkpoint still verifies; an unrotated chain is unchanged | `internal/gate`, tests | 6.5, 6.6 |
| 6.8 | **Docs** — threat W11 rewritten (it currently has no mitigation), design §4.5, `docs/not-done.md`, README | docs | 6.7 |

## Open questions

1. **Where do revocations live on disk?** Beside the anchor as a second file
   (`revocations.jsonl`), or as lines in the anchor itself. The anchor is append-only by
   convention; a second file keeps existing anchors byte-identical.
2. **Who signs a revocation?** The CA (it is the only thing a compromised signing key
   cannot impersonate) seems right, but it means revocation needs the CA key, which is
   offline in any sensible deployment. The alternative is an approver key.
