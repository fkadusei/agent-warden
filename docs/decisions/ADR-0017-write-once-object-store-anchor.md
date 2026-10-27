# ADR-0017: A write-once object store as the external anchor

- **Status:** Accepted
- **Date:** 2026-10-27
- **Related:** threats W10 (truncation, rollback, forked history), W11 (signing key
  compromise); ADR-0003 (chain, checkpoints, anchoring), ADR-0014 (timestamps), ADR-0016
  (rotation and revocation); Phase 7 plan, question 1; steps 7.7–7.10

## Context

Truncation detection, rotation and revocation all rest on checkpoints published where
Warden's operator cannot rewrite them (ADR-0003, ADR-0016). The only anchor today is
`checkpoint.FileAnchor`: a file on the same host. An operator with root can rewrite the
log and that file together, re-sign both with the receipt key, and `warden-verify` will
pass them. The file anchor's own comment says the write-once guarantee "must come from
where the file lives", and nothing so far provides it.

The Phase 7 plan weighed three kinds of external anchor:

- **A write-once object store.** Cheap and private, and one operator can deploy it today.
  It stops rewriting. It does not stop an operator who decides never to anchor at all.
- **A public transparency log.** Independent and publicly auditable, but every entry is
  public, and verification depends on a service Warden does not run.
- **A witness that countersigns.** The strongest option, and the only one that catches
  a fork shown to different verifiers. It needs a second organisation to run it.

The owner chose the object store on 2026-10-27.

What "write-once" means in practice decides the design. This is S3 Object Lock in
**compliance mode**:

- Each locked object version has a retain-until date. Until that date, nobody can delete
  or overwrite that version, the account's root user included, and nobody can shorten
  the retention.
- It locks **versions, not names.** A write to an existing name makes a new version, and
  a delete makes a delete marker. Either one hides the locked version from a plain read,
  even though the locked version still exists.
- The store sets each version's `LastModified` time itself. A client cannot set or
  backdate it.

So an anchor that only writes locked objects and reads them back by name is not
write-once. The guarantee exists only if the verifier looks at every version.

## Decision

### 1. The store

Warden anchors to any store that speaks the S3 API with Object Lock in compliance mode.
The configuration names an endpoint, a region, a bucket, a prefix and a retention period,
so the same code covers AWS S3 and compatible stores (MinIO, Ceph RGW and others), and
tests run against a local fake. The bucket must have Object Lock enabled, which on S3
also enables versioning.

### 2. What an anchored object contains

Each object holds **exactly the signed checkpoint line**, the same bytes `FileAnchor`
writes. Nothing changes in a signed format:

- RFC 3161 tokens (ADR-0014) are keyed by the digest of the anchored line, so they cover
  objects and file lines alike.
- A checkpoint in both anchors is byte-for-byte the same.

Objects are named `<prefix>/<chain_id>/<size>.json`, with the size zero-padded to 20
digits. Names then sort in log order, and each name stands for exactly one checkpoint.

### 3. How Warden writes

- **Explicit lock on every PUT.** Warden sends compliance mode and a retain-until date
  of now plus the configured retention, and does not rely on the bucket's default
  retention. It also sends a SHA-256 checksum, which Object Lock requires.
- **Conditional writes.** Every PUT carries `If-None-Match: *`, so a retry after a lost
  response cannot create a second version. If the store refuses a write because the name
  already exists, Warden reads the object back. Identical bytes count as success;
  anything else is reported as an error.
- **Best effort.** Publishing never blocks a tool call. Fail-closed applies to receipts
  (ADR-0004), not to anchoring. A failed upload is logged and retried for **the latest
  signed checkpoint** on each tick until it succeeds, so an idle log still gets anchored.
  A later checkpoint covers everything an earlier one did, so a missed one never needs
  backfilling.
- **Alongside the file anchor, not instead of it.** The file anchor stays, and it is
  still what `warden serve` reads on startup to resume. Both can be configured at once.
  `checkpoint.Anchor.Publish` gains a context, so a slow store can be cut off.

### 4. How a verifier reads it

`warden-verify` reads the store directly, with read-only credentials of its own. It
does not use a copy handed over by the operator. Under the chain's prefix it lists
**every version and every delete marker**, then applies these rules:

1. **Locked.** Every version must be in compliance mode, with a retain-until date in
   the future. A version in governance mode, or with no lock, is not write-once, and
   verification fails.
2. **One set of bytes per name.**
   - Two versions under one name with different bytes are a rewrite, and fail.
   - Identical duplicates and delete markers are reported, not failed: a delete marker
     shows an attempt to hide a checkpoint, and the locked version still counts.
3. **The earliest version is the anchor.** For each name, the checkpoint is the oldest
   version's bytes. Its signature, chain ID and ordering are checked as
   `checkpoint.ReadVerified` checks them today. The object's name must match the
   checkpoint's size.
4. **The store's time bounds the checkpoint's.** A checkpoint's `ts` must not be later
   than its version's `LastModified`, allowing a few minutes of clock skew. The report
   gives each checkpoint's location and stored time, and how long the newest receipt
   has been waiting for an external anchor.
5. **Agreement with the file anchor.** When both anchors are given, a checkpoint size
   present in both must have identical bytes. Any difference fails.

The log is then checked against every anchored checkpoint, as with the file anchor
today, and revocations (ADR-0016) may name a checkpoint from either anchor.

### 5. Credentials

- **Least privilege.** Warden's credentials need only `PutObject` and `GetObject` under
  its prefix, and must not hold `s3:BypassGovernanceRetention` or any delete permission.
  A verifier needs only `ListBucketVersions`, `GetObject`, `GetObjectVersion` and
  `GetObjectRetention`.
- **Environment only.** Access keys are read from environment variables, never from the
  configuration file or flags, as the demo agent reads model API keys.

### 6. A client written in Warden, not the AWS SDK

The anchor needs three operations (a conditional PUT, a GET, and a version listing) plus
AWS Signature Version 4. The AWS SDK for Go v2 would add more than a dozen modules to
`warden-verify`, a binary built to have very few. Warden writes the client instead:

- It uses `net/http`, `encoding/xml` and standard-library SHA-256 and HMAC.
- It is isolated in `internal/anchor/s3`, as `internal/tsa` isolates the timestamp
  libraries.
- The signer is checked against the worked examples in AWS's SigV4 documentation.

The client never verifies a checkpoint itself; signature checks stay in
`internal/checkpoint`. A bug in the client can at worst make verification fail, or
mis-report a lock. That is why rule 1 reads the lock from each version's own retention
response, not from a bucket setting.

### 7. Room for the other two

The anchor is an interface for writing (`checkpoint.Anchor`) and a source for reading
(versions with provenance). A transparency log or a witness can implement both later
without changing what a checkpoint is.

## Consequences

- An operator with root on the Warden host can no longer rewrite the log and its anchor
  together. Every checkpoint they have already stored stays readable until its retention
  ends, and a rewritten log fails against it.
- A verifier gets a time for each checkpoint that Warden did not choose: the store's
  `LastModified`. It is unsigned, so it means "the provider says, over TLS". It is weaker
  than an RFC 3161 token, but it costs nothing and catches a newly made bucket being
  passed off as an old one.

**What the operator can still do:**
- **Stop anchoring.** This cannot be prevented, only seen. The verifier reports how old
  the newest external anchor is compared with the newest receipt. Truncating the log
  after the last external anchor is undetectable, as it always was. The exposure window
  is the checkpoint interval plus any outage.
- **Point an auditor at a different bucket.** The auditor must get the bucket and prefix
  from somewhere other than the operator, such as a contract or a published statement.
  Stored times show when every object in it was written.
- **Close the cloud account.** Object Lock protects objects inside an account. What
  happens to them when the account closes is up to the provider's terms, not the lock,
  so the guarantee holds for the life of the account.
- **Sign a forged tail with a stolen key and anchor it.** That is W11. Anchoring limits
  it to the tail after the last honest checkpoint, and revocation (ADR-0016) withdraws it.
- **Show different histories to different verifiers.** The store prevents this only if
  every verifier reads the same bucket. Only a witness would detect a fork shown to
  verifiers that read different places.

**Other consequences:**
- The provider is trusted to honour compliance mode and report `LastModified` truthfully.
  Warden checks the lock on every version it reads, but it cannot check the provider.
- Revocations and RFC 3161 tokens still live in local files. Losing a token loses only
  extra evidence. Hiding a revocation helps a key thief, so revocations should be
  published by the root's holder, who is not necessarily the operator. Putting
  revocations in the store too is left for later.
- The client supports static access keys only: no instance roles, no SSO and no web
  identity, because those are what the SDK provides. Deployments on AWS will want roles
  eventually; that is listed in `docs/not-done.md` when 7.10 lands.
- Tests and the gate use an in-process fake store that enforces versions, delete markers,
  compliance retention and server-set times. That proves Warden's side, not a real
  provider's. Running against MinIO or AWS is a separate check, and the docs must say
  which ones have been done.
- Nothing changes for a deployment without a store. A log with only a file anchor gets
  the same `warden-verify` result as before.
