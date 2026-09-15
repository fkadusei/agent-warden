# ADR-0004: Fail closed with write-ahead receipts

- **Status:** Proposed
- **Date:** 2026-09-14
- **Related:** threat W8

## Context

Many audit pipelines are best-effort: if the collector is down, events are dropped and the action proceeds.
For ordinary logs that is a reasonable availability trade-off. For evidence it means
the most important actions can happen with no record exactly when something is
already going wrong.

## Decision

**No receipt, no action.** A tool call executes only after its `decision` receipt is
durably written (flushed and fsynced, or acknowledged by a durable store). If the
write fails, the call is refused and the refusal is reported to the agent. The
`result` receipt is written after execution; if that write fails, the gap is
detectable (a `decision` with no matching `result`) and raises an alert.

## Consequences

- Every executed call has a prior signed record of the decision that allowed it.
- Receipt storage becomes part of the availability path; an outage stops agent tool
  use. This is intentional and documented.
- Signing and fsync add latency to every call; the benchmark measures p50/p99.
- Anchoring (ADR-0003) is deliberately *not* on this path, so an external anchor
  outage degrades evidence strength rather than stopping work.

## Alternatives considered

- **Best-effort asynchronous logging** — lower latency, but actions can go
  unrecorded. Rejected for the decision record.
- **Write after execution only** — a crash between execution and write leaves no
  record of an action that happened.
