# ADR-0003: Hash chain, signed checkpoints, and external anchoring

- **Status:** Proposed
- **Date:** 2026-09-14
- **Related:** threats W9, W10, W11; ADR-0002

## Context

Signing each receipt proves each receipt is authentic, but not that the **set** of
receipts is complete or in order. A hash chain detects edits, insertions, deletions,
and reordering inside the log. It does **not** detect:

- the newest receipts being cut off (truncation);
- the key holder rewriting and re-signing the entire log;
- different logs being shown to different verifiers (a fork).

Those require a commitment that Warden's operator cannot later change.

## Decision

1. **Chain:** each receipt carries `seq` and `prev` = SHA-256 of the previous signed
   receipt.
2. **Checkpoints:** every *N* receipts or *T* seconds, Warden signs
   `{chain_id, size, root}`, where `root` is a Merkle root over receipt hashes.
3. **Anchoring:** each checkpoint is sent outside Warden's control. v1 supports a
   write-once file target and RFC 3161 timestamp tokens. A witness network is future
   work.
4. **Verification** checks the log against the most recent anchored checkpoint and
   reports the exposure window explicitly.

## Consequences

- Tampering anywhere before the last anchored checkpoint is detectable, even by
  someone holding the signing key (bounds W11).
- Receipts after the last anchor are exposed to truncation. This window is a named,
  configurable parameter (default 100 receipts / 60 seconds), not a hidden gap.
- Merkle roots allow proving that one receipt is in the log without sharing the
  entire log, which supports selective disclosure (ADR-0005).
- Anchoring adds an external dependency. Anchor failure is receipted and alerts, but
  does not stop tool calls (unlike receipt writes, ADR-0004); the growing exposure
  window is reported instead.

## Alternatives considered

- **Hash chain only** — misses truncation, rewrite, and forks. Rejected as
  insufficient evidence.
- **Public transparency log (e.g. Sigstore Rekor) for every receipt** — strong, but
  leaks activity metadata publicly and adds per-call external latency. Possible
  future anchor target for checkpoints only.
- **Blockchain anchoring** — adds cost and complexity without improving on a
  timestamp authority or witness for this purpose.
