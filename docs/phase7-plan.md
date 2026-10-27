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
| 7.4 ✅ | **A signer interface** — `composite.Signer` (`Public`, `Sign`) is what receipts, checkpoints, approval statements, the chain appender, the store and `serve`'s checkpointer take; `*composite.PrivateKey` satisfies it, so no caller changed. Only `keyfile.WriteComposite`, which writes the seed, still needs the private key itself. The key ID stays outside the interface, unlike the plan's first draft: it is Warden's name for a key epoch, set in configuration and changed by rotation, not a property of where the key is held. Tests run a whole chain, a rotation and a checkpoint through a signer that never exposes its key, and show that a signer that cannot sign stops the call with nothing written. Two things surfaced and were fixed: a nil key passed as a `Signer` is a non-nil interface, so the old `next == nil` check let it through to a panic (the full suite caught it); and nothing tested a write that fails after a rotation, whose recovery must not bring the retired key back, which now has a test. Gates, corpus and the demo log are unchanged | `internal/composite`, `internal/receipt`, `internal/checkpoint`, `internal/chain`, `internal/store`, `internal/approval`, `cmd/warden` | — |
| 7.5 ✅ | **Docs for Part A** — design §9 rewritten from the code: the five stale rows now say what was built (JCS checked against RFC 8785 and wrapped; the timestamp modules vetted in ADR-0014; the agent's adapters and benchmark model; synthetic tools written in Go; `warden-bench` and its report), and the quality rows name versions, the fuzz budget, and that no release is published yet. Semgrep is removed (question 2). The Signer component, W11 and design §7 (a Phase 7 row) no longer claim hardware custody. `govulncheck` was the one CI tool installed at `@latest`; it is now pinned to v1.9.0. `docs/not-done.md` replaces the inaccurate signer entry with hardware-backed keys and the local-only anchor, and adds unsigned releases and the short fuzz budget. README status updated | `docs/design.md`, `docs/design.html`, `docs/threat-model.md`, `docs/not-done.md`, `README.md`, `.github/workflows/go.yml` | 7.1–7.4 |

### Part B — anchoring that leaves the host

| Step | Component | Where | Depends on |
|---|---|---|---|
| 7.6 ✅ | **ADR-0017: the external anchor** — an S3-compatible store with Object Lock in compliance mode, chosen by the owner. Object Lock protects versions, not names, so the verifier lists every version and delete marker and fails on an unlocked version or two different sets of bytes under one name. Objects hold the exact checkpoint line, so tokens and file anchors keep working. Conditional PUTs make retries safe. The store's own `LastModified` bounds each checkpoint's time. The client and SigV4 are written in Warden instead of adding the AWS SDK to `warden-verify`. What the operator can still do is listed, starting with simply not anchoring | `docs/decisions` | — |
| 7.7 ✅ | **The anchor** — `internal/anchor/s3`: SigV4 signing, checked against AWS's four documented examples (one exposed a bug: Go leaves `$` bare in a path, SigV4 needs `%24`); a client with a conditional locked PUT, GET, a paginated version listing and retention; and `s3.Anchor`, which stores the exact checkpoint line at `<prefix>/<chain_id>/<size>.json` and treats identical bytes under the name as published and different bytes as a fork. `checkpoint.Anchor.Publish` now takes a context and the checkpoint. `serve` takes an `anchor_store` section (https only, except loopback) with the access key from `WARDEN_ANCHOR_ACCESS_KEY_ID` and `WARDEN_ANCHOR_SECRET_ACCESS_KEY`, offers each new checkpoint after it is file-anchored, retries the newest one with waits from 2 s to 5 min, offers the last file-anchored checkpoint again on restart, and reports a conflicting stored checkpoint without retrying it. `s3fake` is an in-process store with versions, delete markers, compliance and governance locks, server-set times, conditional writes and signature checks; tests show what an operator can and cannot do to a locked checkpoint. The listing parser is the fifteenth fuzz target. Seven deliberate breaks were each caught. Not yet run against a real provider | `internal/anchor/s3`, `internal/config`, `cmd/warden` | 7.6 |
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
   for the other two. **Decided 2026-10-27: the object store** (ADR-0017).
2. ~~**Semgrep.**~~ **Decided at 7.5: removed.** Its Go rules overlap `staticcheck` and
   `go vet`, and no rule specific to Warden was worth a second analyzer and a Python
   toolchain in the Go job. The design no longer names it.
3. **Fuzzing budget.** A short run on every push catches regressions; a long nightly run
   finds new bugs. Proposed: 30 seconds per target on push, and a nightly job running
   longer, with any finding opened as a failing run.
4. **Hardware-backed keys.** Deferred to a later phase on purpose: 7.4 builds the seam,
   and ML-DSA support in HSMs and KMSs still varies by vendor. Checked on 2026-10-27: a
   local SoftHSM 2.7.0 (Homebrew, on OpenSSL 3) implements `CKM_EDDSA` but no ML-DSA
   mechanism, so it can hold the Ed25519 half of a composite key and not the ML-DSA half.
   It is still useful for testing a PKCS#11 signer's plumbing — sessions, login, key
   lookup, an unreachable token failing closed — but a signer that keeps half the key in
   a file is not hardware custody and must not be described as such. A PKCS#11 signer
   also means cgo in `warden` (not `warden-verify`), which needs an ADR. To be confirmed.
