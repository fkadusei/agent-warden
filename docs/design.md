# Design

- **Status:** Draft for review
- **Date:** 2026-09-14
- **Threat model:** [`threat-model.md`](threat-model.md) (threat IDs `W1`–`W14`
  are referenced below)

---

## 1. The idea in one paragraph

An agent proposes a tool call. Warden decides whether it happens, performs it with
credentials the agent never sees, inspects what comes back, and — before and after
— writes receipts. Each receipt is signed with a hybrid post-quantum signature and
linked to the one before it. Periodically, Warden publishes a signed checkpoint to
somewhere it doesn't control. Anyone with the public key and a checkpoint can run
`warden-verify` and know that the record is authentic, in order, and complete up to
that checkpoint.

## 2. Components

| Component | Job | Threats |
|---|---|---|
| **Gateway** | The only path from agent to tools. Speaks MCP to the agent. | W7 |
| **Identity** | Issues a short-lived, task-scoped X.509 credential naming the agent, the principal, and the task. Expires with the task. | W3, W4 |
| **Policy** | Deny-by-default decision on principal + agent + tool + arguments + taint state → `allow` / `deny` / `require_approval`. | W1, W2, W4 |
| **Approvals** | Single-use approvals bound to a call digest and a distinct approver. | W6 |
| **Credential broker** | Injects tool credentials at execution; the agent never holds them. | W3 |
| **Tool registry** | Pins each tool manifest by digest. | W5 |
| **Output inspector** | Tags results with a taint source; flags instruction-like content. | W1 |
| **Receipt log** | Write-ahead, signed, hash-chained receipts. | W8, W9, W13, W14 |
| **Checkpointer** | Signed checkpoints, sent to an external anchor. | W10, W11 |
| **Signer** | Holds receipt signing keys behind an interface (file for dev; PKCS#11 / KMS for production). | W11, W12 |
| **`warden-verify`** | Standalone offline verifier. Needs only public keys and checkpoints. | W9–W14 |
| **Demo agent + tools** | A small agent and synthetic tools (email, payments, repo, CRM) for the demo and benchmark. | — |

## 3. The life of one tool call

```
agent ──propose(call)──► Gateway
                           │ 1. identify   task credential → (agent, principal, task)
                           │ 2. pin        tool manifest digest matches registry?
                           │ 3. decide     policy(principal, agent, tool, args, taint)
                           │ 4. RECEIPT    type=decision   ◄── durably written before anything runs
                           │ 5. approve    if require_approval: wait for approval receipt
                           │ 6. execute    broker injects tool credential, calls tool
                           │ 7. inspect    tag result with taint source, flag instructions
                           │ 8. RECEIPT    type=result
agent ◄──result (tagged)───┘
```

**Write-ahead rule (ADR-0004):** step 4 must succeed before step 6 may start. If
the log is unavailable, the call is refused.

## 4. The receipt

### 4.1 Payload

Receipts are JSON, canonicalized with **RFC 8785 (JCS)** before hashing and
signing, so the same receipt always produces the same bytes.

```json
{
  "v": 1,
  "domain": "agent-warden/receipt/v1",
  "chain_id": "01J9Z3…",
  "seq": 1042,
  "prev": "sha256:9f2c…",
  "ts": "2026-09-14T15:04:05.123Z",
  "type": "decision",
  "task_id": "01J9Z4…",
  "actor": { "agent": "cert-sha256:ab12…", "principal": "alice@tenant-a" },
  "call": {
    "tool": "payments.refund",
    "manifest": "sha256:77e1…",
    "args_commitment": "sha256:c0ff…"
  },
  "decision": {
    "result": "require_approval",
    "policy_revision": "sha256:4d5e…",
    "rule": "refund_over_limit",
    "taint": ["web:example.org"]
  },
  "key": "warden-2026-09-e1"
}
```

| Field | Purpose | Threat |
|---|---|---|
| `domain`, `chain_id`, `task_id` | Prevent splicing a receipt into another chain or context | W14 |
| `seq`, `prev` | Ordering and linkage; `prev` is the SHA-256 of the previous **signed** receipt | W9 |
| `actor` | Who acted and for whom | W4 |
| `manifest` | Which exact tool definition was called | W5 |
| `args_commitment` / `result_commitment` | Salted digests, never raw data | W13 |
| `policy_revision`, `rule` | Why it was allowed — reproducible against that policy version | W2 |
| `taint` | Which untrusted sources were in context | W1 |
| `key` | Which signing key epoch; resolves to a certificate | W11 |

Receipt types: `decision`, `approval`, `result`, `key_rotation`, `checkpoint`.

### 4.2 Commitments (ADR-0005)

`args_commitment = SHA-256(salt ‖ JCS(args))` with a fresh 32-byte random salt per
call. The raw arguments and salt go to a separate, access-controlled store. To prove
what one call contained, disclose that call's args and salt; the verifier recomputes
the commitment. Salting prevents guessing low-entropy arguments ("was the amount
$500?") from the receipt alone.

### 4.3 Signature (ADR-0002)

- **Algorithm:** composite **ML-DSA-65-Ed25519** as defined in
  `draft-ietf-jose-pq-composite-sigs-04` (JOSE `alg` `ML-DSA-65-Ed25519`; COSE
  value requested as -58).
- **Construction (per the draft):** prehash the message with SHA-512; build the
  message representative from the prefix, the algorithm label, a `0x00` byte, and
  the prehash; sign that representative with both ML-DSA-65 and Ed25519; concatenate
  the two signatures.
- **Envelope:** JWS JSON serialization, with the receipt's `key` in the protected
  header.
- **Size:** about 3,373 bytes of signature per receipt (3,309 ML-DSA-65 + 64
  Ed25519). The benchmark reports real storage and latency overhead.
- **Library:** Go 1.27 standard library — `crypto/mldsa` and `crypto/ed25519`
  (verified locally on Go 1.27.1: ML-DSA-65 signs and verifies, 3,309-byte
  signatures). Warden implements only the composite construction on top, and
  **must pass the draft's test vectors** before any receipt is produced (ADR-0006).
- **Test vectors:** the draft's Appendix A.1 includes ML-DSA-65-Ed25519 (Figure 4)
  and ML-DSA-44-Ed25519 (Figure 2). Both are extracted unchanged into
  `testdata/composite/`, and `internal/composite` passes them: public keys derived
  from the seeds, byte-exact M′, and verification of the published signatures.

### 4.4 Chain and checkpoints (ADR-0003)

- **Genesis:** `seq=0`, `prev` = SHA-256 of the chain's parameters (chain ID,
  algorithm, initial key certificate).
- **Checkpoint:** every *N* receipts or *T* seconds (whichever first), Warden signs
  `{chain_id, size, root}` where `root` is a Merkle root over receipt hashes. The
  Merkle root lets a verifier later prove that one receipt is in the log without
  downloading all of it.
- **Anchoring:** each checkpoint is sent to an external anchor. v1 supports a
  write-once file target and an RFC 3161 timestamp token; a witness network is future
  work.
- **Exposure window:** receipts after the last anchored checkpoint are not
  truncation-proof (W10 residual risk). Default *N*=100, *T*=60s, both configurable.

### 4.5 Keys

- Receipt signing keys are held only by the Signer, never by the agent.
- Each key epoch has an X.509 certificate issued by a Warden root, with a dedicated
  extended key usage for receipt signing. Certificates are signed with **plain
  ML-DSA-65** (RFC 9881; ADR-0008), because no mainstream library supports composite
  X.509. The certificate's subject public key is the ML-DSA-65 component; the Ed25519
  component is bound in a critical Warden extension, so the verifier can rebuild the
  composite receipt key.
- **Rotation:** a `key_rotation` receipt signed by the outgoing key names the incoming
  key; the incoming key signs the next receipt. Verification crosses the boundary.
- **Revocation:** receipts under a revoked key dated after the revocation time fail
  verification; receipts before the last anchored checkpoint still verify.

## 5. What `warden-verify` proves

```
warden-verify --log receipts.jsonl --trust root.pem --checkpoint anchored.json
```

| It proves | It does not prove |
|---|---|
| Each receipt was signed by a Warden key chained to the trusted root | That the Warden host was uncompromised at signing time |
| No receipt was altered, inserted, deleted, or reordered | That the tool internally did what it reported |
| The log is complete up to the anchored checkpoint | Completeness after the last anchored checkpoint |
| Both signature components are valid (no downgrade) | That the policy itself was a good policy |
| A disclosed argument or result matches its commitment | Anything about calls whose data was not disclosed |

On failure it names the first failing `seq` and the reason (`bad_signature`,
`chain_break`, `seq_gap`, `revoked_key`, `checkpoint_mismatch`, `wrong_chain`).

## 6. Benchmark

The number that goes in the README: attack success rate **without** Warden vs.
**with** Warden, over the same scenarios, same model, same tools.

| Category | Examples | Maps to |
|---|---|---|
| `injection` | Planted instructions in a web page, email, README, ticket | W1 |
| `authz` | Tools or argument ranges outside the principal's role | W2 |
| `exfil` | Credential disclosure, sending data to external recipients | W3 |
| `deputy` | Another principal's content driving this task | W4 |
| `poison` | Malicious tool descriptions, changed manifests | W5 |
| `approval` | No approval, self-approval, replayed approval | W6 |
| `evidence` | Tamper, truncate, rewrite, splice, downgrade | W9–W14 |
| `benign` | Legitimate tasks that should succeed | False-positive rate |

Metrics: attack success rate, **benign task completion rate** (a guard that blocks
everything is useless), added latency per call (p50/p99), receipt bytes per call.
Target size: 30–40 attack scenarios plus 10–15 benign tasks. Results are published
with the model name and version, because they change with the model.

## 7. Build phases

| Phase | Deliverable | Gate |
|---|---|---|
| **0** | This design, the threat model, ADRs 0001–0008 | Owner review |
| **1** | Receipt library: JCS, composite signer, chain, commitments, `warden-verify` | Draft test vectors pass; all `evidence/*` tamper tests fail verification as expected |
| **2** | Gateway: identity, policy, approvals, broker, registry, write-ahead receipts | `authz`, `approval`, `poison`, fail-closed tests pass |
| **3** | Output inspector + demo agent + synthetic tools | `injection`, `exfil`, `deputy` scenarios run end to end |
| **4** | Benchmark run with/without Warden; checkpoints + anchoring | Published results table incl. benign completion |
| **5** | README, demo video, write-up | — |

## 8. Open questions

1. ~~Policy engine~~ — **decided: Cedar** (ADR-0007).
2. ~~Certificate signatures~~ — **decided: plain ML-DSA-65** (ADR-0008). Still open
   within it: the OID arc for the Ed25519 binding extension.
3. **Draft churn.** The composite draft is at -04. If the construction changes, the
   receipt `v` and `alg` must change with it. Is pinning `alg_ref` in the protected
   header enough?
4. **Stateful ML-DSA alternatives.** Is there a case for SLH-DSA (hash-based, larger
   and slower, more conservative) for checkpoints only, since they are few and
   long-lived?
5. **Checkpoint anchor for the demo.** RFC 3161 needs a TSA; use a public TSA, or run
   a local one and document the trade-off?

## 9. Tech stack (ADR-0006)

**Split by component:** Go for everything on the trust path (receipts, verifier,
gateway); Python for the demo agent, synthetic tools, and benchmark. The two sides
meet only at MCP and at the receipt format (JSON + JCS + JWS), which is
language-neutral.

### Go 1.27 — trust path

| Layer | Choice | Notes |
|---|---|---|
| ML-DSA-65, Ed25519, SHA-2 | Standard library `crypto/mldsa`, `crypto/ed25519`, `crypto/sha512` | Verified locally on Go 1.27.1 |
| X.509 (task credentials, key certificates) | Standard library `crypto/x509` | ML-DSA-65 certificates verified locally |
| Composite ML-DSA-65-Ed25519 | Written in Warden | No library implements it; gated on draft test vectors |
| JWS envelope | Minimal JWS JSON serialization, written in Warden | Mainstream JOSE libraries lack composite algorithms |
| JSON canonicalization (RFC 8785) | `github.com/gowebpki/jcs` v1.0.1 | To vet against the RFC 8785 test data |
| Merkle tree / checkpoints | Written in Warden, RFC 9162 hashing rules | Small, fully tested |
| RFC 3161 timestamps | `github.com/digitorus/timestamp` | No tagged release (pseudo-version only); to vet, or write the client |
| Receipt store + commitment store | SQLite via `modernc.org/sqlite` v1.58.0 | Pure Go, no cgo, so `warden-verify` stays a single static binary |
| MCP | `github.com/modelcontextprotocol/go-sdk` v1.8.0 | Official SDK |
| Policy engine | Cedar via `github.com/cedar-policy/cedar-go` v1.8.0 | ADR-0007; two-action pattern for require_approval |
| CLI | Standard library `flag` | No dependency needed for `warden-verify` |
| Signer | Interface: file keys for dev; PKCS#11 for hardware later | HSM support for ML-DSA varies by vendor |

### Python 3.13+ — demo and benchmark

| Layer | Choice |
|---|---|
| Demo agent | An MCP-capable agent framework; model still to be chosen |
| Synthetic tools | MCP servers built with the official MCP Python SDK |
| Benchmark harness | pytest scenarios; results as JSON, rendered into the README table |
| Environments | uv |

### Quality and supply chain

| Area | Go | Python |
|---|---|---|
| Tests | `go test`, native fuzzing (`go test -fuzz`) for tamper and parser tests | pytest |
| Lint and static analysis | `go vet`, `staticcheck`, `govulncheck` | ruff, mypy |
| CI | GitHub Actions pinned to commit SHAs, gitleaks, Semgrep | same |
| Release | Reproducible `warden-verify` binaries for macOS, Linux, Windows | — |
