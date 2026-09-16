# ADR-0014: RFC 3161 timestamps for checkpoints

- **Status:** Accepted
- **Date:** 2026-09-16
- **Related:** threats W10 (truncation, rollback, forked history), W12 (harvest now,
  forge later); ADR-0003 (chain, checkpoints, anchoring); design §4.4 and open
  question 5; Phase 4 step 4.5

## Context

Signed checkpoints in an anchor file detect truncation, rewrites, and forked histories,
but every timestamp in them is Warden's own. A Warden that backdates its clock, or a key
holder rewriting history later, can produce a consistent log with false times. RFC 3161
timestamps fix that: an authority that is not Warden signs a statement that a digest
existed before a given moment.

Checked on 2026-09-16: `github.com/digitorus/timestamp` (BSD-2-Clause, ~950 lines, 57
importers) with `github.com/digitorus/pkcs7` (MIT, ~2500 lines, no further dependencies)
covers both sides: building requests and parsing responses, and parsing requests and
signing responses, which a local authority needs. Neither module has a tagged release;
both are pinned by pseudo-version and checksum in `go.sum`. Design §9 had flagged this
library as "to vet, or write the client".

## Decision

1. **Use the two libraries, isolated.** They are reached only through `internal/tsa`.
   The alternative, writing CMS parsing and verification in Warden, puts several hundred
   lines of ASN.1 on the trust path where a parsing bug is a security bug.
2. **Anchoring is an addition, never a dependency.** The hash chain and the signed
   checkpoints stand on their own. Tokens live in their own file, keyed by the digest of
   the exact anchor line, so anchors and logs written before this change keep verifying
   byte for byte.
3. **Best effort at runtime.** An authority that is slow, rate-limited, or down is
   logged and the next checkpoint tries again. It never blocks a tool call: fail-closed
   applies to receipts (ADR-0004), not to third-party evidence.
4. **Verification is opt-in and strict.** `warden-verify` checks tokens only when given
   trusted roots. A token that does not cover the anchored bytes, or does not chain to a
   trusted authority with the timestamping usage, fails verification.
5. **The demo and tests use a local authority** (`tsa.Authority`: its own root and
   timestamping certificate, served over HTTP), so runs stay offline and reproducible.
   The authority's URL is configuration, so a deployment can point at a public one.

## Consequences

- An auditor can show a checkpoint existed before a stated time, without trusting
  Warden's clock.
- **The timestamp is not post-quantum.** RFC 3161 tokens are CMS signed by the
  authority, in practice with RSA or ECDSA, and Warden does not choose that algorithm.
  Against an adversary who breaks those, a token is no longer evidence, while the
  receipts and checkpoints remain ML-DSA-65 + Ed25519 (ADR-0002). Timestamps narrow the
  window for backdating today; they are not part of Warden's long-term guarantee.
- `warden-verify` links two unreleased modules. They are pinned by checksum, used only
  behind `internal/tsa`, and only when the operator passes TSA roots; the verifier's
  result for a log without tokens is unchanged.
- The local authority's policy OID is synthetic and its key is ECDSA P-256: it exists to
  exercise the path offline, not to be trusted by anyone.
