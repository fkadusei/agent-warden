# ADR-0005: Commitments, not raw data, in receipts

- **Status:** Proposed
- **Date:** 2026-09-14
- **Related:** threat W13; ADR-0003

## Context

Receipts exist to be shown to verifiers — auditors, counterparties, courts. Tool
arguments and results often contain personal or confidential data. Putting raw data
in receipts makes every verifier a data recipient. Redaction alone loses the ability
to prove what a call actually contained.

## Decision

Receipts carry **salted commitments**:
`commitment = SHA-256(salt ‖ JCS(value))`, with a fresh 32-byte random salt per value.
Raw values and their salts are stored separately under access control, keyed by
receipt `seq`. To prove what a specific call contained, disclose that value and its
salt; the verifier recomputes the commitment against the signed receipt.

## Consequences

- Receipts can be shared widely without sharing the data they describe.
- Disclosure is selective: one call can be proven without revealing any other.
- The salt prevents confirming guesses about low-entropy values from a receipt alone.
- Deleting a value and its salt (e.g. for data-retention obligations) leaves the
  receipt verifiable while making its contents unrecoverable.
- The separate data store is a new asset to protect; losing it means contents can no
  longer be proven, though the receipts still verify.

## Alternatives considered

- **Raw values in receipts** — simplest; turns the evidence log into a sensitive-data
  store. Rejected.
- **Unsalted hashes** — low-entropy values (amounts, short IDs) can be brute-forced.
  Rejected.
- **HMAC with a secret key** — prevents guessing, but reintroduces a shared secret
  and disclosure requires trusting the key holder. Rejected.
- **Encrypting values inside receipts** — ciphertext is still data under retention
  and harvest-now-decrypt-later risk, and key management grows. Rejected for v1.
