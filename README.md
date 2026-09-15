# agent-warden

**A zero-trust enforcement layer for AI agent tool calls — with post-quantum
signed receipts that prove what an agent did, for whom, and why it was allowed.**

An agent never calls a tool directly. Every call goes through Warden, which
identifies the caller, checks policy, pauses for human approval when the risk
warrants it, treats tool output as untrusted, and writes a **signed,
hash-chained receipt** that anyone holding the public key can verify offline.

> **Status: Design phase.** No code yet, by design — the threat model and the
> receipt format come first. See [`docs/design.md`](docs/design.md) and
> [`docs/threat-model.md`](docs/threat-model.md).

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

MIT (to be added with the first code).
