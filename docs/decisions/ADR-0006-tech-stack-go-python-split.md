# ADR-0006: Go for the trust path, Python for the demo and benchmark

- **Status:** Accepted
- **Date:** 2026-09-14
- **Related:** ADR-0001 (scope), ADR-0002 (signatures), design §9

## Context

Warden has two kinds of code with different needs:

- **The trust path** — the receipt library, composite signer, chain and
  checkpoints, `warden-verify`, and the gateway. It must be correct, have few
  dependencies, keep per-call latency low, and give third-party verifiers a tool
  they can run without setting up an environment.
- **The demo and benchmark** — the demo agent, synthetic tools, and scenario harness.
  They must be quick to write and change, and live where the agent ecosystem is.

As of 2026-09-14, both Go and Python have what the trust path needs:

- **Go 1.27** (released 2026-08-19) adds `crypto/mldsa` and ML-DSA support in
  `crypto/x509` and `crypto/tls`. Verified locally on Go 1.27.1: ML-DSA-65 signs and
  verifies (3,309-byte signatures) and issues self-verifying X.509 certificates.
- **Python** pyca `cryptography` 49+ supports ML-DSA signing and ML-DSA certificates.
  Verified locally on 50.0.1.
- **Neither** implements composite ML-DSA signatures, for JWS or X.509.
- Official MCP SDKs exist for both.

## Decision

- **Go 1.27** for the receipt library, the composite signer, chain and checkpoints,
  `warden-verify`, and the gateway.
- **Python 3.13+** for the demo agent, synthetic tools, and benchmark harness.
- The two sides interact only through **MCP** and the **receipt format**
  (JSON + RFC 8785 + JWS), which is language-neutral.
- Prefer the Go standard library for all cryptography. Every third-party Go
  dependency on the trust path is pinned and justified in design §9.

## Consequences

- `warden-verify` ships as a single static binary per platform. Auditors don't need
  Python, pip, or a virtual environment. This requires a pure-Go SQLite driver
  (`modernc.org/sqlite`), not a cgo one.
- Cryptography comes from Go's standard library, which also offers a FIPS 140-3 mode.
  `crypto/mldsa` requires Go Cryptographic Module v1.26.0 or later; it is unavailable
  under module v1.0.0.
- The compiler catches type errors in the encoding, chain, and signature code.
- Two languages mean two toolchains and CI setups.
- Slower to prototype than an all-Python build.
- Benchmark results depend on Go and Python agreeing on the receipt format.
  Cross-language tests are required: receipts produced by Go must be parsed and
  checked by the Python harness, and `warden-verify` must be run by the harness as a
  black box.

## Alternatives considered

- **All Python** — fastest to build and one toolchain. But the verifier needs a
  Python environment to run, the gateway's latency is weaker, and there are more
  dependencies on the trust path.
- **All Go** — one language, but the demo agent and benchmark are much more work,
  away from the agent ecosystem.
- **Rust for the trust path** — strong safety guarantees, but a less mature ML-DSA and
  MCP ecosystem than Go's, and a steeper build.
