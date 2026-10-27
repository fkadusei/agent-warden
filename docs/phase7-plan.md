# Phase 7 plan — claims made true, and anchoring that leaves the host

- **Status:** Proposed
- **Date:** 2026-10-27
- **Goal:** two gaps between what Warden says and what it does. First, the design
  promises engineering practice the repository does not have: fuzzing, static analysis
  and secret scanning in CI, reproducible releases, and a signer interface. Second,
  truncation detection, rotation and revocation all rest on checkpoints published
  "where Warden's operator cannot rewrite them", and the only anchor today is a file on
  the same host.
- **Design:** ADR-0017, written at step 7.6, chooses the external anchor.

## Where things stand

Checked on 2026-10-27 against the code, not the documents:

| The design says | The repository has |
|---|---|
| Native fuzzing for tamper and parser tests (§9) | No fuzz targets |
| CI runs `staticcheck`, `govulncheck`, gitleaks, Semgrep (§9) | `govulncheck` only, plus ruff and mypy for the Python agent |
| Reproducible `warden-verify` binaries for macOS, Linux, Windows (§9) | No release workflow |
| Receipt keys held "behind an interface" (§2, §4.5) | No signer interface; private keys are passed as `*composite.PrivateKey` through the appender, store, checkpointer and commands |
| Checkpoints anchored outside the operator's control (§4.4, W10) | `checkpoint.FileAnchor` only: a local file |
| Tech-stack table (§9) | Five rows describe plans since replaced: the timestamp library "to vet", the demo model "still to be chosen", tools "built with the official MCP Python SDK", a "pytest" benchmark harness, JCS "to vet" |

`internal/doccheck` cannot catch any of this: these claims are wrong in both copies of
the design, not different between them.

## What must stay true

- **Old logs, checkpoints, anchors and revocations verify byte for byte.** Nothing here
  changes a signed format. A chain written before Phase 7 gets the same `warden-verify`
  result after it.
- **A tool call never waits on a third party.** Fail closed applies to receipts
  (ADR-0004); an external anchor that is slow or down is reported, the exposure window
  grows, and the next checkpoint tries again — as for timestamps (ADR-0014).
- **Every claim in the design is either backed or removed.** Each practice the design
  names has a test, a CI job, or a workflow behind it by the end of the phase, or the
  sentence goes.
- **A fuzzer finding stops the line.** A crash or an accepted non-canonical input found
  in 7.1 is fixed before any later step, with the input kept as a regression seed.
- **No new dependency on the trust path without an ADR**, isolated behind one package as
  `internal/tsa` isolates the timestamp libraries.

## Build order

### Part A — make the design's claims true

| Step | Component | Where | Depends on |
|---|---|---|---|
| 7.1 ✅ | **Fuzz the parsers** — fourteen targets over every function that reads bytes an attacker can control: receipt, checkpoint, revocation and approval-statement lines; the whole log through `chain.VerifyAll`; `canonical.Transform` and `DecodeStrict`; trust files; timestamp token files and the CMS tokens the `digitorus` modules parse; key-epoch and task certificates; and composite signature verification. Properties: nothing panics; anything accepted re-encodes to exactly its input; a signed receipt or revocation with any one byte changed does not verify; no signature verifies over a message never signed. Signing is randomized, so a malleated signature cannot be told from a second honest one and is not checked. Seeds run under `go test`; `scripts/fuzz.sh` fuzzes every target and refuses to pass if it finds none; CI runs it for 30 seconds per target on each push. A 45-second local run found nothing, and two deliberately broken parsers were each caught within a second | `internal/*`, `scripts/fuzz.sh`, `.github/workflows` | — |
| 7.2 ✅ | **Static analysis and secret scanning in CI** — `staticcheck` v0.8.2 in the test job and gitleaks v8.30.1 over the whole history in a job of its own, both through `go run` at a pinned version so Go's checksum database verifies the code. `staticcheck` reported nothing; a planted bug proved it was analyzing. gitleaks found four hits for two values, both invented test credentials (`tok_gate_…` for the gate's fake payments server, `tok_live_…` for the tests that prove a credential is scrubbed before the agent sees it); `.gitleaks.toml` allows exactly those two values, and a different token-shaped value in the same kind of file is still caught. Semgrep is question 2 | `.github/workflows`, `.gitleaks.toml` | — |
| 7.3 ✅ | **Reproducible releases** — `scripts/release-build.sh` builds `warden-verify` for macOS, Linux and Windows on amd64 and arm64 with `CGO_ENABLED=0 -trimpath` and writes `SHA256SUMS`. The release workflow builds independently on Linux and on macOS, which differ in both OS and CPU, then a third time on the publishing runner, and publishes only if all three match byte for byte; only checksum lists pass between jobs, so no artifact action is needed. The toolchain is pinned to Go 1.27.3 and named in every release. A run started by hand is a dry run; only a `v*` tag publishes. `warden-verify -version` names the commit and toolchain of any binary from Go's own build information. Locally, builds at two paths with separate caches were identical, and no file system path survives in the binaries | `scripts/release-build.sh`, `.github/workflows/release.yml`, `cmd/warden-verify` | 7.1, 7.2 |
| 7.4 | **A signer interface** — `Signer` (sign, public key, key ID) replaces the private keys passed through the appender, store, checkpointer and commands, with the file signer as its only implementation. No behaviour change: the gates and the demo log verify unchanged. A hardware or KMS backend is a later phase; this step makes the design's sentence true and gives that backend a seam | `internal/chain`, `internal/store`, `cmd/warden` | — |
| 7.5 | **Docs for Part A** — the tech-stack table, the signer and CI claims, and `docs/not-done.md` (whose "a signer interface, but only one signer" is itself inaccurate) | docs | 7.1–7.4 |

### Part B — anchoring that leaves the host

| Step | Component | Where | Depends on |
|---|---|---|---|
| 7.6 | **ADR-0017: the external anchor** — which store, what an anchored entry contains, how a verifier fetches it, and what the operator can still do to it (see question 1) | `docs/decisions` | — |
| 7.7 | **The anchor** — an implementation of `checkpoint.Anchor` for the chosen store, isolated in its own package. The file anchor stays, and both can be configured at once. Publishing is best effort: a failure is logged and retried at the next checkpoint, never blocking a call | `internal/anchor/…`, `cmd/warden` | 7.6 |
| 7.8 | **Verifying against it** — `warden-verify` reads checkpoints from the external anchor, not only from a file the operator hands over, and reports which anchor each checkpoint came from and when it was anchored | `cmd/warden-verify`, `internal/checkpoint` | 7.7 |
| 7.9 | **Gate scenarios** — an operator with root rewrites the local log *and* the local anchor file consistently: caught against the external anchor. The external anchor is unreachable: calls still run, and the report shows the exposure window growing. Each scenario mutation-tested, as in 6.7 | `internal/gate` | 7.8 |
| 7.10 | **Docs for Part B** — W10 rewritten around the anchor that exists, design §4.4, README, `docs/not-done.md` | docs | 7.9 |

Parts A and B are independent; A goes first because it is cheaper and because 7.1's
fuzzers cover the parsers 7.8 extends.

## Open questions

1. **Which external anchor?** The candidates trade independence against cost and privacy:
   - *A write-once object store* (for example S3 Object Lock in compliance mode). Nobody,
     the account's root user included, can delete or overwrite an object before its
     retention ends. Cheap and private, but it is still the operator's account: it stops
     rewriting, not a quiet decision never to anchor at all.
   - *A public transparency log* (for example Sigstore's Rekor). Fully independent and
     publicly auditable, with inclusion proofs. But every entry is public — a checkpoint
     reveals the chain ID, the log's size, and how fast it grows — and verification
     depends on a service Warden does not run.
   - *A witness* — another party countersigns each checkpoint. The strongest guarantee,
     and the only one that also catches a fork shown to different verifiers, but it needs
     a second organisation to run one.

   Recommendation: the object store, because it is the only one a single operator can
   deploy today without publishing their activity, with the anchor interface left open
   for the other two. To be settled in ADR-0017 before 7.7.
2. **Semgrep.** The design names it, but for this codebase its Go rules overlap
   `staticcheck` and `go vet`. Add it only with a rule worth having; otherwise remove the
   claim in 7.5.
3. **Fuzzing budget.** A short run on every push catches regressions; a long nightly run
   finds new bugs. Proposed: 30 seconds per target on push, and a nightly job running
   longer, with any finding opened as a failing run.
4. **Hardware-backed keys.** Deferred to a later phase on purpose: 7.4 builds the seam,
   and ML-DSA support in HSMs and KMSs still varies by vendor. To be confirmed.
