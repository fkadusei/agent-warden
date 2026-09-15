# ADR-0008: Plain ML-DSA-65 certificates; receipts stay hybrid

- **Status:** Accepted (2026-09-14); **superseded in part by ADR-0010** (2026-09-15).
  Go 1.27 cannot create or parse extensions under the OID below, so the Ed25519
  component moves to a SAN URI and the OID becomes Warden's arc for certificate
  policies. Plain ML-DSA-65 certificate signatures are unchanged.
- **Date:** 2026-09-14
- **Related:** ADR-0002 (composite receipt signatures), ADR-0003, threats W11, W12;
  design §4.5

## Context

Warden uses X.509 certificates for its root, for each receipt-signing key epoch,
and (Phase 2) for task credentials. Checked on 2026-09-14:

- Composite X.509 signatures (`draft-ietf-lamps-pq-composite-sigs`) are not supported
  by Go 1.27 `crypto/x509`, pyca `cryptography` 50.0.1, or OpenSSL 3.6.4.
- Plain ML-DSA-65 certificates (RFC 9881) are supported, and were verified locally in
  Go 1.27.1.

Receipts keep the hybrid composite `ML-DSA-65-Ed25519` signature (ADR-0002). This
creates a binding problem: the receipt-signing public key is **composite** (an
ML-DSA-65 key plus an Ed25519 key), but a standard certificate's subject public key
can only hold one key type Go understands.

## Decision

1. **All certificate signatures use plain ML-DSA-65** (RFC 9881): the root, key-epoch
   certificates, and task credentials.
2. **Key-epoch certificates** carry the **ML-DSA-65 component** as the standard
   subject public key, and bind the **Ed25519 component** in a critical,
   Warden-defined X.509 extension containing the raw 32-byte Ed25519 public key. The
   root's ML-DSA-65 signature covers both.
3. A verifier builds the composite public key as `ML-DSA-65 key ‖ Ed25519 key` from
   the certificate, and rejects a key-epoch certificate that lacks the extension.
4. The extension's OID is a UUID-based OID under the `2.25` arc
   (ITU-T X.667 | ISO/IEC 9834-8), which needs no registration:

   ```
   id-warden-ed25519-binding  OBJECT IDENTIFIER ::= { 2 25 319797216735078154913038669087058524786 }
   ```

   It is derived from the version 4 UUID `f096b41e-17bb-4d1e-bac6-81117bcd7a72`,
   generated once on 2026-09-14. It must never be regenerated; a different binding
   format would get a new OID.

## Consequences

- Only standard, widely supported certificate formats are used; any RFC 9881-capable
  tool can parse and verify the chain.
- **No classical hedge on the certificate chain.** If ML-DSA were broken, an attacker
  could forge a key-epoch certificate. This is limited because certificates are
  internal and short-lived, anchored checkpoints (ADR-0003) bound history already
  recorded, and the receipts themselves remain hybrid.
- The critical extension means generic X.509 tools will reject key-epoch certificates
  as containing an unknown critical extension unless told to ignore it. Warden's own
  verifier handles it.
- Revisit when mainstream libraries support composite X.509: switching to composite
  certificates would be a new certificate profile, not a change to receipts.

## Alternatives considered

- **Hand-built composite certificates** — full hybrid chain, but no mainstream tool
  can read or verify them.
- **Parallel certificates per key epoch** (one ML-DSA-65, one Ed25519) — standard
  formats with a classical hedge, but two chains to issue, distribute, revoke, and
  keep in sync.
- **No X.509 for receipt keys** (a root-signed JSON key manifest instead) — simpler to
  parse, but loses standard revocation, validity periods, and tooling.
- **Non-critical extension** — generic tools would accept the certificate, but a
  verifier could silently ignore the Ed25519 binding and accept a downgraded key.
