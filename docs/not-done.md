# What is not done

Written down rather than left for a reader to discover. Everything here is a real gap,
not a rough edge: none of it is hidden by the tests or the benchmark.

## Designed, not built

**Approver key handling.** Approvers hold a key file. There is no hardware backing, no
per-approval device confirmation, and no rotation story for approver keys — receipt
signing keys rotate and can be revoked (ADR-0016); these cannot.

**A signer interface, but only one signer.** Receipt keys live in a file at mode 0600.
The design calls for a signer interface with PKCS#11 or KMS behind it, and nothing here
implements one, so custody is as good as the host's filesystem.

## Deliberately shallow

**Output inspection.** `internal/inspect` looks for planted instructions, hidden text,
directives naming exposed tools, and encoded blobs. It is pattern matching, and a
rephrased instruction passes it — the corpus contains one on purpose
(`injection-paraphrased-refund`). Findings are labels policy can use, never the reason a
call is refused. Making detection deeper would not change what Warden guarantees.

**Argument schemas are only as good as the tool's.** Validation enforces the pinned
schema (ADR-0013). A tool whose schema is `{"type": "object"}` gets nothing from it;
schema quality is part of reviewing a tool before pinning it.

## Not exercised against the real thing

**RFC 3161 against a public authority.** The demo, tests, and benchmark run a local
authority so runs stay offline and reproducible. The URL is configuration, but no public
authority has been used, so their quirks (rate limits, policy OIDs, certificate chains)
are unmet.

**Tools and secrets are synthetic.** Every tool in this repository is a stand-in, and the
"payments token" protects nothing. Warden has never sat in front of a real API.

**One machine, one model.** The published benchmark is `qwen3:30b-a3b` on a laptop over
loopback. Latency is a floor, not a production figure, and the attack numbers describe
one model's behaviour and this example policy.

## Structural limits, by design

**Warden is trusted at runtime.** It decides and signs. The threat model says so. The
mitigation is that its decisions are externally verifiable, not that it cannot be wrong —
a compromised Warden can allow what it likes, and the log will faithfully record that it
did.

**A timestamp is not post-quantum evidence.** RFC 3161 tokens are signed by the authority
with classical algorithms (ADR-0014). They narrow backdating today; against an adversary
who breaks those signatures they stop being evidence, while the receipts themselves do
not.

**Policy is the guarantee, so a permissive policy is a permissive system.** Warden stops
what its policy forbids. The gate proves this by running the corpus against a
permit-everything policy and requiring every policy-dependent attack to succeed.

## Smaller things

- Rotating a key means stopping Warden first: the running server holds the receipt key and
  the store, and `warden rotate-key` opens the same store. It refuses rather than
  corrupting anything, but it is a restart, not a hot swap.
- `warden revoke-key` needs the root's private key, which a sensible deployment keeps
  offline. That is the intended cost of revocation, not an oversight, but it does mean
  revoking is a break-glass errand rather than a command you can script.
- `warden-verify` and the console follow rotations only when given `--root`. Without it a
  rotated log fails closed — correct, but it is a flag an auditor has to know to pass.
- The console shows an exported snapshot, not a live tail; refreshing is one command.
- The console has no authentication beyond a loopback bind and a startup token, and holds
  an approver key in memory while it runs with one (ADR-0015).
- `warden-verify` links two unreleased modules (`digitorus/timestamp`, `digitorus/pkcs7`),
  pinned by checksum, used only behind `internal/tsa` and only when TSA roots are passed.
- The scenario corpus is 41 scenarios; the design targets 30–40 attacks and 10–15 benign,
  which it meets, but breadth is not depth: each attack is one shape of one idea.
