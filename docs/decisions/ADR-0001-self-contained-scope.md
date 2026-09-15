# ADR-0001: A self-contained enforcement gateway, receipt log, and benchmark

- **Status:** Accepted
- **Date:** 2026-09-14
- **Related:** `threat-model.md`, `design.md`

## Context

Warden has to demonstrate three claims: that it **prevents** harmful agent tool
calls, that it leaves **verifiable evidence** of every call, and that both hold up
**measurably** against realistic attacks. Each claim needs a different piece: an
enforcement point, a receipt log with an offline verifier, and a benchmark that can
run the same scenarios with and without Warden.

## Decision

**Build one self-contained repository** containing:

1. the **gateway** — identity, policy, approvals, credential brokering, tool pinning,
   and output inspection — as the only path from agent to tools;
2. the **receipt library** and `warden-verify`, packaged so they have no dependency
   on the gateway and can be used by any agent harness;
3. a **demo agent and synthetic tools**, so the whole system and the benchmark run
   with no external infrastructure beyond a model endpoint.

Identity is deliberately minimal: a small internal CA issuing short-lived,
task-scoped X.509 credentials.

## Consequences

- Anyone can clone, run, and reproduce the benchmark on a laptop.
- The receipt library stands alone, so its security claims can be reviewed and
  tested separately from the gateway.
- The minimal identity layer is not a general-purpose identity system; production
  deployments would connect an organization's own identity infrastructure to the
  gateway's identity interface.

## Alternatives considered

- **Receipt library only, no gateway** — smaller, but cannot demonstrate enforcement
  or run the with/without benchmark.
- **Gateway only, conventional logging** — demonstrates prevention but not
  evidence, which is the project's main contribution.
- **Build on a full identity stack (service mesh, external IdP, Kubernetes)** —
  closer to production, but adds heavy setup that obscures the core ideas and makes
  the benchmark hard to reproduce.
