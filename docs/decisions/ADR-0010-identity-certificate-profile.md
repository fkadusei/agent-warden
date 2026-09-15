# ADR-0010: Identity and certificate profile

- **Status:** Accepted
- **Date:** 2026-09-15
- **Supersedes in part:** ADR-0008 (how the Ed25519 component is bound, and what the
  OID is used for)
- **Related:** threats W3, W4, W11; design §2, §4.5; Phase 2 step 2.5

## Context

ADR-0008 bound a key epoch's Ed25519 public key in a critical X.509 extension under
the UUID-based OID `2.25.319797216735078154913038669087058524786`. Before any
certificate code was written, a probe against Go 1.27 showed:

| Use of the 2.25 UUID OID | Go 1.27 `crypto/x509` |
|---|---|
| Extension ID (`pkix.Extension.Id` is `asn1.ObjectIdentifier`, a `[]int`) | Cannot be created; a certificate carrying one is **rejected by `ParseCertificate`** ("malformed extension OID field") |
| Custom extended key usage (`UnknownExtKeyUsage` is `[]asn1.ObjectIdentifier`) | Same limitation |
| Certificate policy (`Certificate.Policies` is `[]x509.OID`) | **Works:** creates, parses, round-trips exactly, and passes `Verify` |

The 128-bit UUID arc does not fit in an `int`. The owner chose to keep the OID and
move to parts of X.509 that Go supports, rather than register an IANA Private
Enterprise Number or hand-encode certificates.

## Decision

### OIDs

`2.25.319797216735078154913038669087058524786` is **Warden's OID arc**. Sub-arcs
are allocated here and never reused:

| OID | Meaning |
|---|---|
| `…4786.1` | Certificate policy: **key-epoch certificate** (a receipt-signing key) |
| `…4786.2` | Certificate policy: **task credential** |

They appear only as certificate policies, which Go handles fully.

### Certificates

All certificates are signed with plain ML-DSA-65 (ADR-0008, unchanged).

| | Root | Key-epoch certificate | Task credential |
|---|---|---|---|
| Subject key | ML-DSA-65 | ML-DSA-65 component of the composite receipt key | ML-DSA-65 key held by the agent |
| CA | yes, path length 0 | no | no |
| Policy | none | exactly `…4786.1` | exactly `…4786.2` |
| Key usage | cert sign | digital signature | digital signature |
| Extended key usage | none | none | client authentication |
| SAN URIs | none | `urn:warden:kid:<kid>`, `urn:warden:ed25519:<base64url public key>` | `urn:warden:agent:<id>`, `urn:warden:principal:<id>`, `urn:warden:task:<id>` |
| Other SANs | not allowed | not allowed | not allowed |
| Lifetime | set by operator | set by operator | at most 15 minutes, plus 1 minute of clock skew |

- Identity is read **only** from `urn:warden:` SAN URIs, each exactly once. An unknown
  `urn:warden:` URI, a DNS name, email address, or IP address makes the certificate
  invalid. The subject common name is informational only.
- Identifier values use `A–Z a–z 0–9 . _ ~ @ : + -`, 1–256 bytes.
- A verifier rebuilds the composite receipt key as the certificate's ML-DSA-65 key
  followed by the Ed25519 key from the SAN URI.
- A task credential's fingerprint, `cert-sha256:<hex>`, identifies the exact
  credential used for a call.

## Consequences

- Every certificate is standard X.509 that Go and common tools parse and verify.
- **The Ed25519 binding is no longer a critical extension.** ADR-0008 made it critical
  so a verifier could not ignore it and accept a downgraded key. That risk does not
  arise here: every receipt signature needs both the ML-DSA-65 and Ed25519 halves
  (ADR-0002), so a verifier without the Ed25519 key cannot verify any receipt, and a
  key-epoch certificate without the URI is rejected outright.
- Purpose is enforced by policy: a task credential cannot be used as a key-epoch
  certificate, or the reverse.
- Certificate policies are normally about issuance practice; using them to mark
  purpose is a Warden convention, documented here.
- Revocation (`revoked_key`) is still deferred.

## Alternatives considered

- **IANA Private Enterprise Number** — keeps a critical extension and a custom EKU
  with small OIDs, but waits on registration and ties the OIDs to an organization.
- **Hand-encoded certificates** — keeps ADR-0008 exactly, but reimplements X.509
  encoding, extension parsing, and chain validation, which the project avoids.
- **Sub-arcs as extension IDs** — same limitation as the arc itself.
