# ADR-0002: Hybrid composite ML-DSA-65 + Ed25519 receipt signatures

- **Status:** Proposed
- **Date:** 2026-09-14
- **Related:** threat W12 (harvest now, forge later), ADR-0003

## Context

Receipts are evidence and may need to hold up for years. Classical signatures
(Ed25519, ECDSA) are expected to become forgeable by a cryptographically relevant
quantum computer. ML-DSA (FIPS 204) is standardized, and its JOSE/COSE encoding is
published as **RFC 9964** (May 2026), but it is young, and implementation or
parameter flaws are still plausible. A hybrid signature stays unforgeable as long as
**either** component holds.

Standards status as of this ADR:

- `draft-ietf-jose-pq-composite-sigs-04` (September 2026) defines
  `ML-DSA-65-Ed25519` for JOSE, with COSE value -58 requested. Active draft, not an
  RFC.
- `draft-ietf-lamps-pq-composite-sigs-19` defines composite ML-DSA for X.509.
  Active draft.

## Decision

**Sign receipts with composite `ML-DSA-65-Ed25519`** as constructed in
`draft-ietf-jose-pq-composite-sigs-04`, inside a JWS envelope. Pin the draft
revision in the protected header (`alg_ref`). Build on the Go standard library's
ML-DSA-65 and Ed25519 primitives (ADR-0006); implement only the composite construction, and
**gate it on the draft's test vectors**. Verification requires **both** components;
there is no single-component fallback for receipts.

## Consequences

- Receipts remain verifiable and unforgeable if either algorithm breaks (W12).
- Signature overhead is about 3.4 KB per receipt; measured in the benchmark.
- The composite construction is still a draft. If it changes, Warden bumps the
  receipt version, and old receipts stay verifiable under their pinned `alg_ref`.
- ML-DSA-65 alone (RFC 9964) is the fallback if the composite draft stalls. Changing
  to it would be a new receipt version, not a silent downgrade.

## Alternatives considered

- **Ed25519 only** — small and fast, but does not address W12.
- **ML-DSA-65 only (RFC 9964)** — standardized encoding, but no hedge against an
  early flaw in a young algorithm.
- **Two independent signatures ("dual signing")** — simple, but without a bound
  label a stripped component is harder to detect, and there is no standard encoding.
- **SLH-DSA** — conservative hash-based security, but signatures of roughly 8–50 KB
  and slow signing make it a poor fit for per-call receipts. Still under
  consideration for checkpoints (design open question 4).
- **HMAC-signed logs** (common in gateways today) — only holders of the shared secret
  can verify, and any holder can forge. Rejected.
