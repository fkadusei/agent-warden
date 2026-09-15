# agent-warden

**A zero-trust enforcement layer for AI agent tool calls — with post-quantum
signed receipts that prove what an agent did, for whom, and why it was allowed.**

An agent never calls a tool directly. Every call goes through Warden, which
identifies the caller, checks policy, pauses for human approval when the risk
warrants it, treats tool output as untrusted, and writes a **signed,
hash-chained receipt** that anyone holding the public key can verify offline.

> **Status: Phase 1 complete — the receipt library and `warden-verify`.** The
> gateway, demo agent, and benchmark come next. See the build phases in
> [`docs/design.md`](docs/design.md#7-build-phases).

## What works today

- **Hybrid post-quantum signatures:** composite ML-DSA-65 + Ed25519, per
  `draft-ietf-jose-pq-composite-sigs-04`, passing the draft's test vectors.
- **Receipts:** strict, canonical (RFC 8785) signed records of policy decisions and
  results, with salted commitments instead of raw data.
- **Hash chain:** detects edited, inserted, deleted, reordered, and spliced receipts,
  and results for calls that were denied or never approved.
- **Checkpoints:** RFC 9162 Merkle roots, signed and anchored, which detect
  truncation, full rewrites by the key holder, and forked histories.
- **`warden-verify`:** checks all of the above offline, from public keys alone.

Not yet: RFC 3161 anchoring, key-epoch certificates, key rotation and revocation,
approval receipts.

## Verify a receipt log

Requires Go 1.27.

```sh
CGO_ENABLED=0 go build -trimpath -o bin/warden-verify ./cmd/warden-verify
bin/warden-verify --log receipts.jsonl --chain CHAIN_ID --keys trusted-keys.json --anchor anchor.jsonl
```

Exit status is `0` when the log verifies, `1` when verification fails, and `2` for
usage or file errors. Add `--json` for machine-readable output.

## Run the tests

```sh
go test ./...
```

## Why

Agent audit logs today are, at best, HMAC-signed JSON. That proves nothing to
anyone who doesn't hold the shared secret, and it says nothing about whether
entries were deleted. When an agent moves money or touches customer data, the
record of what it did is **evidence** — and evidence needs integrity, origin,
completeness, and a lifetime longer than classical signatures may last.

Warden makes the record verifiable by a third party (an auditor, a regulator, a
court) using only public keys, and signs it with **ML-DSA-65 + Ed25519** so the
record stays trustworthy even after a cryptographically relevant quantum
computer exists.

## Read in this order

1. [`docs/threat-model.md`](docs/threat-model.md) — what Warden defends against, and what it doesn't
2. [`docs/design.md`](docs/design.md) — components, the receipt format, verification
3. [`docs/decisions/`](docs/decisions/) — why each choice was made (ADRs)

## License

MIT — see [LICENSE](LICENSE).
