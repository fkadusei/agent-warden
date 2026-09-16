# Phase 5 plan — making it legible

- **Status:** In progress
- **Date:** 2026-09-16
- **Goal (design §7):** README, demo, write-up. Everything works; this phase makes it
  understandable to someone who lands on the repo cold and has five minutes.

## What a first-time reader needs

1. **What is this and what does it stop?** In the first screen, without jargon.
2. **Proof it works.** The benchmark result and the attack gate, with their limits stated.
3. **A way to try it** in one command.
4. **A way to judge the engineering:** the design, the threat model, the decisions.

The repo currently answers 3 well, 2 in scattered places, and 1 last.

## Build order

| Step | Component | Where | Depends on |
|---|---|---|---|
| 5.1 ✅ | **README as the front door** — the benchmark table now sits near the top, a "How a call is decided" section explains the pipeline in one screen, and the walkthroughs moved below. Three stale claims fixed while restructuring: the status said Phase 3, the "not yet" list still named RFC 3161 anchoring and the benchmark (both done), and the gate was described as 25 attacks when it runs 26. Every count and link re-checked against the code | `README.md` | — |
| 5.2 ✅ | **CI and supply chain** (design §9) — `.github/workflows/go.yml`: gofmt, `go vet`, `go test ./...`, `warden-gate`, the race detector on the enforcement path, a demo-and-verify round trip, and `govulncheck`; `agent.yml`: `uv sync --locked`, ruff format and lint, mypy, pytest. Actions pinned by commit SHA | `.github/workflows/` | — |
| 5.3 | **The write-up** — why policy rather than detection, why receipts commit rather than copy, why hybrid post-quantum signatures, what the benchmark does and does not prove. For a reader who will not read 14 ADRs | `docs/writeup.md` + `docs/writeup.html` | 5.1 |
| 5.4 | **Demo recording** — a short screen capture: `warden-demo`, then `warden-gate`, then editing a receipt and watching `warden-verify` catch it. I can produce the script, the commands, and the terminal recording; publishing a video is the owner's call | `docs/demo.md`, recording | 5.1 |
| 5.5 | **Web console (optional)** — `warden console`: live receipts, pending approvals with approve/reject, verify, and a scenario runner. Proposed twice and still unanswered; it would make 5.4 far more watchable | `cmd/warden/console.go` | owner decision |
| 5.6 | **Close-out** — ADR-0012 accepted or rejected; deferred items written down honestly (key rotation and revocation, fuller output inspection, RFC 3161 against a public authority); the agent's `Event loop is closed` teardown noise cleaned up | docs, `agent/` | owner decision |

## Rules for this phase

- **No new claims.** Everything in the README and write-up must point at something that
  runs: a command, a test, a generated page, or a committed result.
- **Limits stay next to the claims,** not in a footnote: what the benchmark measures, what
  the gate guarantees, what the example policy does and does not cover.
- **The reader is not assumed to know MCP, Cedar, or ML-DSA.**

## Open decisions

1. **Web console (5.5)** — build it, or leave it out?
2. **ADR-0012** — accept (scenario tools stay in Go, the agent is model-agnostic) or revisit?
3. **Demo (5.4)** — a terminal recording (asciinema, committable) or a screen video?
