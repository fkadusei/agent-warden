# agent-warden

**A zero-trust enforcement layer for AI agent tool calls — with post-quantum
signed receipts that prove what an agent did, for whom, and why it was allowed.**

An agent never calls a tool directly. Every call goes through Warden, which
identifies the caller, checks policy, pauses for human approval when the risk
warrants it, treats tool output as untrusted, and writes a **signed,
hash-chained receipt** that anyone holding the public key can verify offline.

> **Status: Phase 2 complete — Warden runs as a real MCP gateway and passes its
> attack gate.** Full output inspection and the benchmark come next. See the build phases in
> [`docs/design.md`](docs/design.md#7-build-phases) and
> [`docs/phase2-plan.md`](docs/phase2-plan.md).

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

It writes the signed receipt log, an anchored checkpoint, the public key, and three
tampered copies of the log to `demo-output/`, then prints the `warden-verify`
commands to run. The real log prints **VERIFIED**; each tampered copy prints
**FAILED** with the line and the reason (`bad_signature`, `seq_gap`,
`checkpoint_mismatch`). Edit `demo-output/receipts.jsonl` yourself and run the
command again to see what Warden catches. Delete `demo-output/` to run the demo again.

## Run Warden locally

This runs the real gateway: agents connect over MCP with mutual TLS, calls go to
separate tool servers, and an approver signs from another command. Use two
terminals, both in the repository root.

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

## Attack it

```sh
go run ./cmd/warden-gate
```

Runs 25 attacks, each against a fresh, complete deployment: an agent connecting over
MCP with mutual TLS, the gateway, the approver API, and real MCP tool servers that
count every execution. A scenario passes only if Warden refuses for the right reason
**and** the tool never ran. Covered: calls no policy permits, wrong roles, unreviewed
tools, and wrongly typed arguments; resuming early, self-approval, untrusted approvers,
approvals for different arguments, replays, another agent resuming, and expired or
rejected approvals; tool descriptions or schemas changed after review (including
between approval and execution) and tools added later; a failed receipt store, a
missing tool credential, a dead tool server, a client without a credential, a forged
identity header; and an edited receipt log. It exits `1` if any defense fails, and
`go test ./...` runs the same gate.

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
- **Enforcement pipeline (`internal/gateway`):** every call is checked against a
  short-lived task credential, a pinned tool manifest, and Cedar policy; the decision
  is receipted before anything runs; high-risk calls wait for an approver's signed
  statement; tool credentials are injected by Warden and scrubbed from results;
  untrusted output taints the task.
- **MCP transport (`internal/mcpgw`, `internal/upstream`):** agents connect over MCP on
  mutual TLS 1.3, proving their task credential with its key; pinned tools appear as
  `server.tool`. Warden reaches tool servers as an MCP client and delivers their
  credentials itself.
- **`warden` binary:** `init`, `pin`, `add-approver`, `issue-task`, `serve`, `call`,
  `approve`, and `export`. The approver API authenticates signed requests, and
  `warden approve` checks the arguments it shows against the decision's commitment
  before signing.
- **Attack gate (`cmd/warden-gate`):** 25 authorization, approval, tool-poisoning,
  fail-closed, identity, and evidence attacks against the full stack, all refused.

Not yet: RFC 3161 anchoring, key rotation and revocation, full output inspection, and
the benchmark.

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
