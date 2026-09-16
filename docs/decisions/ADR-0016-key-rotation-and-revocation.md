# ADR-0016: Key rotation and revocation

- **Status:** Accepted
- **Date:** 2026-09-16
- **Related:** threats W10 (rollback, forked history), W11 (signing key compromise),
  W12 (harvest now, forge later); ADR-0002 (composite signatures), ADR-0003 (chain and
  checkpoints), ADR-0010 (key-epoch certificates), ADR-0014 (timestamps)

## Context

A chain is signed by one key for its whole life. `receipt.TypeKeyRotation` was reserved
in ADR-0003 but never specified, and `Validate` rejects it. Two things are therefore
impossible today: retiring a key on a schedule, and reacting to a compromised one. The
only remedy is starting a new chain, which throws away continuity with the old evidence.

Three facts shape the design:

- **The genesis `prev` binds the chain to its first key.** `NewParams(chainID, kid, pub)`
  hashes the chain ID, the algorithm, the key ID, *and* the key digest. A chain is
  cryptographically tied to the key it started with, and rotation must not break that.
- **Key-epoch certificates already exist** (ADR-0010): the root CA issues a certificate
  binding a `kid` to a composite public key, and `identity.VerifyKeyEpoch` checks it.
- **Verification resolves a key per receipt** by `kid` through a static `KeyResolver`, so
  every key must be known to the verifier in advance.

And one uncomfortable fact: **whoever holds a signing key can sign a rotation with it.**
Rotation cannot, by itself, recover from compromise.

## Decision

### Rotation: signed by the outgoing key, certified by the CA

A `key_rotation` receipt sits in the chain like any other. Its body names the outgoing
`kid`, the incoming `kid`, the incoming key, and the incoming key-epoch certificate. It
is **signed by the outgoing key**, so the chain's continuity is unbroken, and the
incoming key is **independently certified by the root CA**, so the outgoing key alone is
not enough to introduce a new one. Receipts after it are signed by the incoming key.

A verifier therefore needs **one trusted key (or the root) and the log**: it walks
forward, and each rotation teaches it the next key. The trust file does not grow.

Forging a rotation requires the outgoing signing key **and** the CA. That is a strictly
higher bar than either alone, and it is the reason for choosing both over either.

### Revocation: effective from a named checkpoint

Revoking a key cannot un-sign what it signed. A revocation therefore names the **last
checkpoint believed good**, and means: receipts covered by that checkpoint keep
verifying; anything signed by that key after it is rejected.

This is honest about what a compromise costs — **you lose the tail, not the history** —
and it is only meaningful because checkpoints are anchored outside Warden's control and
timestamped by a third party (ADR-0014). The anchored, timestamped checkpoint is what
makes "believed good up to here" a statement an auditor can check rather than a claim
Warden makes about itself.

Revocations are published **to the anchor**, beside the checkpoints, not into the receipt
log: a compromised Warden must not be able to quietly drop the notice that its key is
compromised.

### What a verifier reports

`warden-verify` takes the revocations alongside the anchor. A log whose tail was signed
by a revoked key after its effective checkpoint **fails**, naming the receipt and the
revocation. A log that stops at or before that checkpoint verifies, with the revocation
reported.

## Consequences

- Rotation becomes routine: scheduled, verifiable, and visible in the log itself.
- An auditor's trust file stays at one key for the life of a chain, however many times it
  rotates.
- **Compromise still costs the tail.** Everything after the last good anchored checkpoint
  is unprovable, and the exposure window is the checkpoint interval — a stated, tunable
  parameter (ADR-0003). Rotation shortens the *future* exposure; it does not repair the
  past.
- A rotation receipt cannot be issued by the CA alone, so a CA compromise does not
  silently re-key a live chain; and it cannot be issued by the signing key alone, so key
  theft does not either.
- The genesis binding still names the chain's first key, which stays the anchor of the
  whole sequence: the chain is "the one that began with this key and rotated in this
  recorded order".
- Revocation depends on anchoring being real. Against an operator who controls the anchor
  as well as the key, a revocation can be withheld — the threat model already says the
  anchor must live where Warden's operator cannot rewrite it (ADR-0003).
