# Phase 6 plan — key rotation and revocation

- **Status:** Complete
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
| 6.3 ✅ | **Appending a rotation** — `store.Rotate` signs the handover with the outgoing key and commits the receipt row together with the record of which key signs now, so a crash cannot leave the database claiming one key while the log has already handed over to another. `meta.kid` keeps its meaning as the genesis key; a new `meta.current_kid` is the key signing now, and a log written before rotation existed has no such row and defaults to its genesis key, so existing stores open unchanged. `Append` refuses a `key_rotation` receipt so the switch cannot happen non-atomically, and the store refuses to hand over to a key it does not itself hold. Reopening resumes under the current key and refuses the retired one. `store.VerifyWithKeys` follows rotations | `internal/store` | 6.2 |
| 6.4 ✅ | **Revocation records** — `internal/revocation`: a record naming a chain, a kid, and the last checkpoint believed good by its size *and* head, so it is pinned to one history and cannot be re-aimed at a fork of the same length. Signed by the root CA with plain ML-DSA-65 in its own envelope, with an ML-DSA context string bound in so a root signature made for another purpose cannot be replayed as a revocation, and published to a file beside the anchor. `chain.Revoked`, with `VerifyAll` and `Options`, enforces it: a receipt at or after the effective size signed by that kid fails with `revoked_key`, and everything the checkpoint covers still verifies | `internal/revocation`, `internal/chain` | 6.2 |
| 6.5 ✅ | **`warden rotate-key` and `warden revoke-key`** — `rotate-key` generates the incoming key, has the CA certify it, appends the handover signed by the outgoing key, writes the new key 0600 to files of its own, adds its public key to the trust file, and updates `kid`, `receipt_key` and `receipt_cert` in the configuration. A key ID names one key for the life of a chain, so rotating back to a retired one is refused before anything is written. `revoke-key` picks the anchored checkpoint (the newest, or `--size`), signs the revocation with the root, and publishes it beside the anchor after confirming what it will cost. A new optional `revocations` config field is defaulted on load, so existing configurations keep working | `cmd/warden`, `internal/config` | 6.3, 6.4 |

### Staleness rotation exposed

Adding rotation turned three pieces of code that assumed one key per chain into latent
bugs. Two are fixed in 6.5; the third is 6.6's.

1. **The configured key ID** (found in 6.3). `serve.go` and `admin.go` pass `cfg.Kid` to
   `store.Open`, so a rotated chain refuses to open until the configuration is updated
   alongside it. Refusing is right — it will not sign with a key the log has retired — but
   it must not be left for the operator to discover, so `rotate-key` updates the key ID,
   the key path and the certificate path together. *Fixed.*
2. **The checkpointer's anchor reader** (found in 6.5). `newCheckpointer` resolved only the
   current `kid`, so after a rotation the anchor's older checkpoints — signed by the key
   that was current when they were made — stopped resolving, and `serve` refused to start
   with `existing anchor: unknown key`. It now reads the anchor with every key the chain
   has used. *Fixed.*
3. **The console's verifier — and, more quietly, its feed** (found in 6.5).
   `console.verify` called `chain.VerifyWithCheckpoints` with a plain resolver, which fails
   closed on a rotation receipt, so the console would report a healthy rotated log as
   FAILED. The quieter half was worse: `summarize` skips any receipt whose key it cannot
   resolve, so the feed dropped everything the incoming key had signed and said nothing
   about it. A verifier that fails loudly is a nuisance; a feed that silently omits
   receipts is a lie. Both follow rotations now, given `--root`. *Fixed.*

A fourth was avoided rather than found. `warden-verify` reads the anchor before the log,
but a rotated chain's newer checkpoints are signed by keys only the log can introduce, so
in that order a healthy chain fails to verify. The log is read once first to learn those
keys — which is why `Rotating.Accept` was built to treat re-accepting a key it already
holds as a no-op rather than a conflict.
| 6.6 ✅ | **`warden-verify --root` and `--revocations`** — `--root` follows key rotations, so one trusted key and the root verify a whole rotated chain. `--revocations` enforces published revocations, but only after matching each to the anchored checkpoint it names: one naming a checkpoint that is not anchored, or one of that size in another history, is refused rather than applied. Rotations and revocations are reported in text and JSON. The anchor is read only *after* the log has introduced the chain's later keys, because a rotated chain's newer checkpoints are signed by keys the trust file has never seen. The console takes `--root` too, for its feed as much as its verify panel | `cmd/warden-verify`, `cmd/warden`, `internal/revocation` | 6.4 |
| 6.7 ✅ | **Gate scenarios** — six gates, K1–K6, against a live deployment rather than a reconstructed log: a chain that rotates mid-session still verifies from the key it began with; a stolen signing key alone cannot introduce a new one; a retired key cannot sign after handing over; revoking a key costs the tail and not the anchored history; a revocation cannot condemn a checkpoint nobody anchored; and a chain that never rotates is unaffected by any of it. Each was mutation-tested: removing the defence a gate rests on makes that gate, and no other, fail | `internal/gate` | 6.5, 6.6 |
| 6.8 ✅ | **Docs** — W11 rewritten to describe what was actually built, with a residual-risk note saying plainly that rotation shortens future exposure and does not repair the past; design §4.4/§4.5, the receipt-type list, the `warden-verify` flags, the failure reasons and the phase table, in both `design.md` and its hand-maintained HTML twin; `docs/not-done.md`; README | docs | 6.7 |

## Questions this phase had to settle

Both are now decided and written into ADR-0016.

1. **Where do revocations live on disk?** *Their own file beside the anchor.* Every line
   of an anchor is a checkpoint — `checkpoint.ReadVerified` parses it as one — so adding a
   second record type would break existing anchors and every reader of them. The property
   that matters is where the file lives, not which file it is.
2. **Who signs a revocation?** *The root CA.* It is the one authority a stolen
   receipt-signing key cannot impersonate, and it already decides which keys are
   legitimate for a chain by issuing their key-epoch certificates. The cost is that
   revoking a key needs the offline root. That is the right price for the single statement
   an attacker most wants to forge, at a moment that is already an incident.

One consequence worth recording: the root signs with plain ML-DSA-65, not the composite
suite receipts use. Receipt verification hardcodes its algorithm on purpose — that check
is what stops algorithm-confusion attacks — so rather than loosen it to admit a second
algorithm, a revocation carries its own envelope of the same shape. The cost is a second
envelope in the codebase; the alternative was weakening receipts to serve a peripheral
record.
