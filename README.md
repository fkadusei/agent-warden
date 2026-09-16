# agent-warden

**A zero-trust enforcement layer for AI agent tool calls — with post-quantum signed
receipts that prove what an agent did, for whom, and why it was allowed.**

An agent never calls a tool directly. Every call goes through Warden, which identifies
the caller, checks the arguments against the tool's reviewed schema, checks policy,
pauses for human approval when the risk warrants it, treats tool output as untrusted,
and writes a **signed, hash-chained receipt** that anyone holding the public key can
verify offline.

The agent is untrusted by design: it proposes actions, and Warden decides them.

> **Status: Phase 4 complete.** The gateway runs as a real MCP server, the attack gate
> passes, and the with/without-Warden benchmark is published below. Phase 5 (write-up,
> demo, CI) is in progress. See [`docs/design.md`](docs/design.md#7-build-phases).

## Does it change the outcome?

The same agent, model, prompts, and planted content, run over 41 scenarios twice: once
calling the tools directly, once through Warden.

| | Attacks succeeded | Attacks attempted | Benign tasks completed | Latency p50 | p99 | Receipt bytes/call |
|---|---|---|---|---|---|---|
| **Without Warden** | **47/62 (76%)** | 47/62 | 20/20 | 4.4 ms | 18 ms | — |
| **With Warden** | **0/62 (0%)** | 45/62 | 20/20 | 11 ms | 28 ms | ~7,000 |

`qwen3:30b-a3b` (context fixed at 16384 tokens), two full passes, 2026-09-16. On the 45
attack scenarios where the model took the bait in **both** modes — the only comparison
that separates the guard from the model's own inconsistency — **45 of 45 succeeded
without Warden and 0 with it**, while every benign task still completed and both receipt
logs verified. Per-scenario detail: [`docs/benchmark.html`](docs/benchmark.html).

Attacks *attempted* is published beside attacks *succeeded* on purpose: a model that
ignores a bait scores well without the guard doing anything. Here the model ignored
about a quarter of them, and took a different set in each pass. These are measurements
of one model, not the guarantee — that is the gate below.

## Try it

Requires Go 1.27.

```sh
go run ./cmd/warden-demo
```

The demo sends a support agent's tool calls through the real pipeline (only the tools
and one API token are simulated) and prints what Warden decided at each step:

- a CRM lookup and a small refund run straight away;
- a $500 refund waits for approval, refuses to run early, rejects the requester
  approving it themselves, then runs once a second person approves;
- a web page with hidden instructions taints the task, so the next email is blocked;
- a tool that changes its description after being reviewed is refused;
- a tool that echoes its API token has the token scrubbed before the agent sees it;
- a tool no policy permits is denied.

It writes the signed receipt log, an anchored checkpoint with its RFC 3161 timestamp,
the public key, and three tampered copies of the log to `demo-output/`, then prints the
`warden-verify` commands to run. The real log prints **VERIFIED**; each tampered copy
prints **FAILED** with the line and the reason (`bad_signature`, `seq_gap`,
`checkpoint_mismatch`). Edit `demo-output/receipts.jsonl` yourself and run the command
again to see what Warden catches. Delete `demo-output/` to run the demo again.

## Attack it

```sh
go run ./cmd/warden-gate
```

Runs 26 attacks, each against a fresh, complete deployment: an agent connecting over MCP
with mutual TLS, the gateway, the approver API, and real MCP tool servers that count
every execution. A scenario passes only if Warden refuses for the right reason **and**
the tool never ran. Covered: calls no policy permits, wrong roles, unreviewed tools, and
arguments outside the pinned schema; resuming early, self-approval, untrusted approvers,
approvals for different arguments, replays, another agent resuming, and expired or
rejected approvals; tool descriptions or schemas changed after review (including between
approval and execution) and tools added later; a failed receipt store, a missing tool
credential, a dead tool server, a client without a credential, a forged identity header;
and an edited receipt log.

It then plays all 41 scenarios in `scenarios/` (31 attacks, 10 benign) against the
example deployment with an agent that obeys every planted instruction: each attack call
must be denied or held for approval without reaching a tool, and each benign task must
complete. It exits `1` if any defense fails, and `go test ./...` runs the same gates,
including a check that a permit-everything policy makes every attack scenario fail.

## How a call is decided

```
agent ──propose──► identify → pin → check args → policy → RECEIPT → approve?
                                                              │
                   agent ◄── result (scrubbed, tagged) ◄── execute ◄── RECEIPT
```

- **Identity:** a short-lived task credential (ML-DSA-65 X.509) naming agent, principal,
  and task, proven by mutual TLS 1.3.
- **Pinned tools:** every tool's manifest is reviewed and pinned by digest; a changed
  description or schema is refused (ADR-0009).
- **Arguments:** checked against the pinned input schema before policy sees them
  (ADR-0013).
- **Policy:** Cedar, deny by default, evaluated on principal, agent, tool, arguments, and
  the task's taint labels. Any evaluation error denies.
- **Write-ahead receipts:** the decision is durably recorded *before* anything runs. No
  receipt, no action (ADR-0004).
- **Approval:** high-risk calls wait for a second person's signed statement, bound to the
  exact call, single-use, with an expiry (ADR-0009).
- **Credentials:** tool secrets are injected by Warden at execution and scrubbed from
  results; the agent never holds them.
- **Output inspection:** results are scanned for planted instructions, hidden text,
  directives naming exposed tools, and encoded blobs. Findings become taint labels that
  policy can act on; the matched text is never stored. Detection informs policy — it is
  never the guarantee.
- **Evidence:** receipts are canonical JSON (RFC 8785), signed with composite
  **ML-DSA-65 + Ed25519** (`draft-ietf-jose-pq-composite-sigs-04`), hash-chained, and
  checkpointed into an anchor with RFC 9162 Merkle roots and optional RFC 3161
  timestamps (ADR-0014).

Not yet: key rotation and revocation, richer output inspection, and CI.

## Run Warden locally

This runs the real gateway: agents connect over MCP with mutual TLS, calls go to
separate tool servers, and an approver signs from another command. Use two terminals,
both in the repository root.

**Terminal 1 — set up and start the servers**

```sh
go run ./cmd/warden init                      # creates warden-local/ (keys are 0600)
EXAMPLE_PAYMENTS_TOKEN=demo go run ./cmd/example-tools &
go run ./cmd/warden pin                       # review the tools...
go run ./cmd/warden pin --write               # ...then pin them
go run ./cmd/warden add-approver --id bob@tenant-a --out warden-local/bob.key
WARDEN_SECRET_PAYMENTS=demo go run ./cmd/warden serve
```

**Terminal 2 — act as the agent and the approver**

```sh
go run ./cmd/warden issue-task --agent support-agent-7 --principal alice@tenant-a \
  --task ticket-4821 --out warden-local/agent        # valid for 15 minutes
go run ./cmd/warden call --list
go run ./cmd/warden call --tool payments.refund --args '{"payment_id":"p-10","amount":500}'
#   -> needs human approval ... Decision receipt #N
go run ./cmd/warden approve --key warden-local/bob.key --id bob@tenant-a
go run ./cmd/warden approve --key warden-local/bob.key --id bob@tenant-a --decision N
go run ./cmd/warden call --tool warden.resume --args '{"decision_seq":N}'
go run ./cmd/warden call --tool web.fetch --args '{"url":"https://shop.example"}'
go run ./cmd/warden call --tool mail.send --args '{"to":"x@tenant-a.example","body":"hi"}'
#   -> Denied by Warden (rule "no_email_while_tainted")
```

Stop `serve` with Ctrl+C (it writes a final checkpoint), then check the evidence:

```sh
go run ./cmd/warden export --out warden-local/receipts.jsonl   # prints the verify command
```

`warden-local/` holds private keys and is ignored by git; delete it to start over.

**Serve a scenario.** `scenarios/` holds attack and benign scenarios (planted
instructions, another tenant's ticket, customer data leaving). Start the tools with
`go run ./cmd/example-tools --scenario deputy-ticket-refund` and the read-only tools
return that scenario's planted content; `--list` shows them all. Each file lists the
calls a compromised agent would make and the outcome Warden must produce.

**Drive it with a model.** [`agent/`](agent/README.md) is a model-agnostic Python agent
that reaches tools only through Warden: Claude through the Anthropic API, or any
OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, LM Studio). `warden-bench` runs the
whole corpus with and without Warden and writes the table above. `--adapter script`
replays a scenario's calls with no model at all.

## Verify a receipt log

```sh
CGO_ENABLED=0 go build -trimpath -o bin/warden-verify ./cmd/warden-verify
bin/warden-verify --log receipts.jsonl --chain CHAIN_ID --keys trusted-keys.json --anchor anchor.jsonl
```

Exit status is `0` when the log verifies, `1` when verification fails, and `2` for usage
or file errors. Add `--json` for machine-readable output.

If Warden was configured with a timestamp authority (`tsa.url`), add
`--tsa-tokens tokens.jsonl --tsa-roots tsa-roots.pem`: each anchored checkpoint's
RFC 3161 timestamp is checked against the exact anchored bytes, and the report names the
earliest. That is evidence about *when* a checkpoint existed from a party other than
Warden, so a Warden that backdates its own clock is caught. The authority signs with its
own classical key, so this is not part of the post-quantum guarantee (ADR-0014).

## Run the tests

```sh
go test ./...                      # every package, including both gates
uv run --project agent pytest      # the Python agent and benchmark harness
```

## Why

Agent audit logs today are, at best, HMAC-signed JSON. That proves nothing to anyone who
doesn't hold the shared secret, and it says nothing about whether entries were deleted.
When an agent moves money or touches customer data, the record of what it did is
**evidence** — and evidence needs integrity, origin, completeness, and a lifetime longer
than classical signatures may last.

Warden makes the record verifiable by a third party (an auditor, a regulator, a court)
using only public keys, and signs it with **ML-DSA-65 + Ed25519** so the record stays
trustworthy even after a cryptographically relevant quantum computer exists.

## Read in this order

1. [`docs/threat-model.md`](docs/threat-model.md) — what Warden defends against, and what it doesn't
2. [`docs/design.md`](docs/design.md) — components, the receipt format, verification
3. [`docs/benchmark.html`](docs/benchmark.html) — the with/without comparison, per scenario
4. [`docs/decisions/`](docs/decisions/) — why each choice was made (ADRs 0001–0014)

## License

MIT — see [LICENSE](LICENSE).
