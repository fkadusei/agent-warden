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
| **Credential broker** | Injects tool credentials at execution; the agent never holds them. Bindings map a server (or one tool) to an HTTP header or stdio environment variable, read from `WARDEN_SECRET_*` variables or owner-only regular files. A missing secret refuses the call; values print as `[REDACTED]`; `Scrub` removes credentials a tool echoes back (`internal/broker`). | W3 |
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
  }
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
| `kid` (protected header, not the payload) | Which signing key epoch; resolves to a certificate | W11 |

Receipt types: `decision`, `approval`, `result`, `key_rotation`, `checkpoint`.
Implemented in `internal/receipt`: `decision`, `result`, and `approval` (ADR-0009).
`key_rotation` and `checkpoint` are reserved; until implemented, receipts of those
types are refused rather than accepted. Checkpoints (§4.4) turned out not to need a receipt
type: they are separate signed statements, kept outside the log.

A `result` receipt carries the same `task_id`, `actor`, and `call` as its decision,
plus `result: {decision_seq, status, result_commitment, taint}`. `decision_seq` must
be lower than the receipt's own `seq`; `result_commitment` is required when
`status` is `ok`.

**Format rules** (enforced on sign and verify):

- Integers only; `seq` is at most 2^53 − 1, the largest integer JCS keeps exact.
- `ts` has exactly one spelling: UTC with milliseconds, `2006-01-02T15:04:05.000Z`.
- Digests are `sha256:` plus 64 lowercase hex characters.
- **Strict decoding:** a payload, header, or log line is accepted only if it is
  valid UTF-8, already canonical, and decoding then re-encoding it reproduces the
  exact bytes. This rejects unknown or missing fields, duplicate keys, empty
  arrays written instead of omitted, and numbers JCS would change. (The JCS
  library used silently rounds integers above 2^53 and passes invalid UTF-8
  through, so these checks are Warden's, not the library's.)

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
- **Envelope:** flattened JWS JSON serialization, `{"payload", "protected",
  "signature"}`, base64url without padding. The protected header is exactly
  `{"alg":"ML-DSA-65-Ed25519","alg_ref":"draft-ietf-jose-pq-composite-sigs-04","crit":["alg_ref"],"kid":…}`.
  Listing `alg_ref` in `crit` means a verifier that doesn't understand it must
  reject the receipt. Any other header field is rejected.
- **Signing input:** `protected || "." || payload` (the base64url strings), as in JWS.
- **Log line:** the canonical JSON of the envelope, one per line. `prev` in the next
  receipt is `sha256:` of that line.
- **Verification order:** header checks, then signature, and only then is the
  payload decoded. Unauthenticated payload bytes are never parsed.
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

- **Genesis:** `seq=0`, `prev` = SHA-256 of the canonical chain parameters
  `{domain: "agent-warden/genesis/v1", chain_id, alg, alg_ref, kid, key}`, where `key`
  is the digest of the composite public key that signs the first receipt. The chain
  is therefore bound to its first signing key; a validly signed first receipt from
  any other key fails as `chain_break`. (Binding to the key-epoch *certificate*
  follows once certificates are built.)
- **Appending** (`internal/chain.Appender`) assigns `chain_id`, `seq`, and `prev`,
  refuses a timestamp earlier than the previous receipt's, and advances only after
  a successful signature. The caller must durably write each line before appending
  the next (ADR-0004).
- **Checkpoint** (`internal/checkpoint`): every *N* receipts or *T* seconds
  (whichever first, with at least one new receipt), Warden signs
  `{v, domain: "agent-warden/checkpoint/v1", chain_id, size, root, head, ts}`.
  `root` is the RFC 9162 Merkle tree hash over the first `size` log lines (leaf =
  SHA-256(0x00 ‖ line), node = SHA-256(0x01 ‖ left ‖ right)); `head` is the digest of
  line `size − 1`. Checkpoints use the same envelope and key as receipts but are
  **not receipts in the chain**; their domain keeps the two apart, and tests confirm
  neither is accepted as the other. The Merkle implementation (`internal/merkle`) is
  checked against the transparency-dev test vectors, and its inclusion proofs let a
  verifier prove one receipt is in the log without the whole log.
- **Anchoring:** each signed checkpoint is published outside Warden's control.
  Implemented: a file anchor that appends one line per checkpoint and syncs every
  write. It only appends; making the file write-once is the job of where it lives
  (an append-only filesystem flag, WORM storage, or another account). Reading an
  anchor verifies every signature and requires strictly growing sizes and
  non-decreasing timestamps. **Not yet implemented:** RFC 3161 timestamps and
  witnesses.
- **Checking a log against checkpoints** (`chain.VerifyWithCheckpoints`): every
  anchored checkpoint must match the log's prefix of its size. A shorter log means
  receipts were removed; a different root or head means a rewrite, or an anchor
  showing a forked history. The report gives `Checkpointed` (largest size covered)
  and `Unanchored` (receipts after it — the exposure window).
- **Exposure window:** receipts after the last anchored checkpoint are not
  truncation-proof (W10 residual risk). Default *N*=100, *T*=60s, both configurable.

### 4.5 Keys

- Receipt signing keys are held only by the Signer, never by the agent.
- Each key epoch has an X.509 certificate issued by a Warden root (ADR-0010,
  `internal/identity`). Certificates are signed with **plain ML-DSA-65** (RFC 9881;
  ADR-0008), because no mainstream library supports composite X.509. The certificate's
  subject public key is the ML-DSA-65 component; the Ed25519 component is carried in a
  SAN URI, `urn:warden:ed25519:<base64url>`, so the verifier can rebuild the composite
  receipt key. The certificate's purpose is fixed by a certificate policy under
  Warden's OID arc (`…4786.1` key epoch, `…4786.2` task credential). A critical
  extension was the original plan, but Go 1.27 cannot create or parse extensions under
  the 128-bit UUID OID; a missing Ed25519 key still cannot cause a downgrade, because
  every receipt needs both signature halves.
- Task credentials are ML-DSA-65 certificates naming the agent, principal, and task in
  `urn:warden:` SAN URIs, valid for at most 15 minutes plus 1 minute of clock skew,
  with client-authentication key usage.
- **Rotation:** a `key_rotation` receipt signed by the outgoing key names the incoming
  key; the incoming key signs the next receipt. Verification crosses the boundary.
- **Revocation:** receipts under a revoked key dated after the revocation time fail
  verification; receipts before the last anchored checkpoint still verify.

## 5. What `warden-verify` proves

```
warden-verify --log receipts.jsonl --chain CHAIN_ID --keys trusted-keys.json --anchor anchor.jsonl [--json]
```

- **`--keys`** is a JWK Set of public keys in the draft's `AKP` format
  (`kty`, `alg`, `kid`, `pub`). This is interim trust input until key-epoch
  certificates exist (ADR-0008), when it becomes a root certificate. The file is
  rejected if any key contains private key material, has the wrong algorithm, or
  repeats a `kid`.
- **`--chain`** is required, so the log can't choose which chain it claims to be.
- **`--anchor`** is optional but strongly recommended. Without it, the result carries
  a warning that truncation and full rewrites by the key holder are undetectable.
- **Exit status:** `0` verified, `1` verification failed (log or anchor), `2` usage or
  file error. `--json` prints the same result for scripts.
- It builds as a single static binary (`CGO_ENABLED=0`), about 4 MB.

| It proves | It does not prove |
|---|---|
| Each receipt was signed by a Warden key chained to the trusted root | That the Warden host was uncompromised at signing time |
| No receipt was altered, inserted, deleted, or reordered | That the tool internally did what it reported |
| The log is complete up to the anchored checkpoint | Completeness after the last anchored checkpoint |
| Both signature components are valid (no downgrade) | That the policy itself was a good policy |
| A disclosed argument or result matches its commitment | Anything about calls whose data was not disclosed |

On failure it names the first failing line, the `seq` expected there, and the reason.
Implemented in `internal/chain.Verify`:

| Reason | Meaning |
|---|---|
| `empty_log` | No receipts |
| `malformed` | Line is not a canonical envelope, or its header is invalid |
| `unknown_key` | The `kid` is not a trusted key |
| `bad_signature` | Composite signature fails |
| `invalid_receipt` | Signed, but the payload breaks the format rules |
| `wrong_chain` | Receipt belongs to a different chain |
| `seq_gap` | Sequence number is not the next one (deletion, insertion, reorder) |
| `chain_break` | `prev` doesn't match the previous line, or the genesis parameters |
| `time_regression` | Timestamp earlier than the previous receipt |
| `bad_reference` | Result points at something that isn't a matching earlier decision (same task, actor, and call) |
| `duplicate_result` | A decision already has a result |
| `denied_call_executed` | A result exists for a `deny` decision |
| `missing_approval` | A result exists for a `require_approval` decision with no earlier approval |
| `rejected_call_executed` | A result exists for a decision whose approval outcome was `rejected` |
| `approval_expired` | The result's `ts` is after the approval's `expires_ts` |
| `duplicate_approval` | A decision already has an approval |
| `self_approval` | The approver is the principal who requested the call |
| `checkpoint_mismatch` | The log is shorter than an anchored checkpoint, its prefix hashes differently, or the checkpoint is for another chain |

Still to come: `revoked_key` (with certificates). On success, the report also lists
**open decisions** (allowed decisions with no result receipt, which are either still
running or a gap to investigate), plus `Checkpointed` and `Unanchored`.

**What checkpoints add, tested both ways:** without a checkpoint, truncating the
newest receipts and rewriting the whole log with the real key both still verify.
Against an anchored checkpoint, truncation below its size, a full rewrite, and an
anchor showing a forked history all fail as `checkpoint_mismatch`. Changes to
receipts *after* the last checkpoint still verify: that is the exposure window, and
the report states its size. Because ML-DSA signatures are randomized, re-signing
any receipt changes its bytes, so a rewrite can't reproduce a checkpointed prefix
even with the key.

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
| **1** ✅ | Receipt library: JCS, composite signer, chain, commitments, checkpoints, `warden-verify` | Draft test vectors pass; tamper tests fail verification as expected. **Deferred:** RFC 3161 anchoring, key-epoch certificates, key rotation and revocation, approval receipts |
| **2** | Gateway: identity, policy, approvals, broker, registry, write-ahead receipts | `authz`, `approval`, `poison`, fail-closed tests pass |
| **3** | Output inspector + demo agent + synthetic tools | `injection`, `exfil`, `deputy` scenarios run end to end |
| **4** | Benchmark run with/without Warden; checkpoints + anchoring | Published results table incl. benign completion |
| **5** | README, demo video, write-up | — |

## 8. Open questions

1. ~~Policy engine~~ — **decided: Cedar** (ADR-0007).
2. ~~Certificate signatures~~ — **decided: plain ML-DSA-65** (ADR-0008). The UUID-based
   OID `2.25.319797216735078154913038669087058524786` is Warden's arc for certificate
   policies, and the Ed25519 key is bound by SAN URI (ADR-0010).
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
