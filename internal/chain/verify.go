package chain

import (
	"bufio"
	"cmp"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/merkle"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// Reason says why verification stopped.
type Reason string

const (
	ReasonEmptyLog           Reason = "empty_log"
	ReasonMalformed          Reason = "malformed"
	ReasonUnknownKey         Reason = "unknown_key"
	ReasonBadSignature       Reason = "bad_signature"
	ReasonInvalidReceipt     Reason = "invalid_receipt"
	ReasonWrongChain         Reason = "wrong_chain"
	ReasonSeqGap             Reason = "seq_gap"
	ReasonChainBreak         Reason = "chain_break"
	ReasonTimeRegression     Reason = "time_regression"
	ReasonBadReference       Reason = "bad_reference"
	ReasonDuplicateResult    Reason = "duplicate_result"
	ReasonDeniedCallExecuted Reason = "denied_call_executed"
	ReasonMissingApproval    Reason = "missing_approval"
	ReasonCheckpointMismatch Reason = "checkpoint_mismatch"
	// Approval rules (ADR-0009).
	ReasonDuplicateApproval    Reason = "duplicate_approval"
	ReasonSelfApproval         Reason = "self_approval"
	ReasonRejectedCallExecuted Reason = "rejected_call_executed"
	ReasonApprovalExpired      Reason = "approval_expired"
	// Key rotation (ADR-0016).
	ReasonWrongKey       Reason = "wrong_key"
	ReasonBadRotation    Reason = "bad_rotation"
	ReasonUncertifiedKey Reason = "uncertified_key"
	ReasonRevokedKey     Reason = "revoked_key"
)

// maxLine bounds a single log line. A receipt line is a few kilobytes.
const maxLine = 1 << 20

// Failure identifies the first line that failed verification.
type Failure struct {
	// Line is the 1-based line number in the log.
	Line int `json:"line"`
	// Seq is the sequence number expected at that line.
	Seq    int64  `json:"seq"`
	Reason Reason `json:"reason"`
	Detail string `json:"detail"`
}

func (f *Failure) Error() string {
	return fmt.Sprintf("chain: line %d (seq %d): %s: %s", f.Line, f.Seq, f.Reason, f.Detail)
}

// KeyResolver returns the verification key for a key ID, or an error if the
// key is unknown or not trusted.
type KeyResolver func(kid string) (*composite.PublicKey, error)

// Keys is what verification needs from a key set when a chain may rotate its
// signing key (ADR-0016): the keys it already trusts, and a judgement on the key
// a rotation introduces. keys.Rotating implements it.
type Keys interface {
	// Resolve returns the verification key for a key ID.
	Resolve(kid string) (*composite.PublicKey, error)
	// Accept decides whether kid may sign the receipts after a rotation.
	// certificate is the DER key-epoch certificate the rotation carries, keyDigest
	// the digest of the incoming composite public key the rotation names, and at
	// the rotation's timestamp: the certificate is judged at the moment it was
	// used. On success Resolve must return the accepted key for kid.
	Accept(kid, keyDigest string, certificate []byte, at time.Time) error
}

// fixedKeys adapts a plain KeyResolver. It knows the keys it was given and can
// never learn another, so a log that rotates its key fails closed rather than
// verifying against a key nothing has vouched for.
type fixedKeys struct{ resolve KeyResolver }

func (f fixedKeys) Resolve(kid string) (*composite.PublicKey, error) { return f.resolve(kid) }

func (fixedKeys) Accept(kid, _ string, _ []byte, _ time.Time) error {
	return fmt.Errorf("no certificate roots were given, so the incoming key %q cannot be checked", kid)
}

// StaticKeys adapts a plain KeyResolver into Keys, for a caller that has a trust
// file and no certificate roots. A log that rotates its key fails closed under
// it; use keys.Rotating to follow rotations.
func StaticKeys(keys KeyResolver) Keys { return fixedKeys{keys} }

// Report summarizes a log that verified.
type Report struct {
	ChainID  string
	Receipts int
	LastSeq  int64
	// Head is the digest of the last line: the prev the next receipt must carry.
	Head string
	// OpenDecisions lists allowed decisions that have no result receipt yet.
	// Each is either still running or a gap that must be investigated (ADR-0004).
	OpenDecisions []int64
	// Checkpointed is the number of receipts covered by the largest checkpoint
	// the log was checked against.
	Checkpointed int64
	// Unanchored is the number of receipts after the last checkpoint. These can
	// still be truncated or rewritten undetectably: the exposure window (W10).
	Unanchored int64
	// Rotations lists the key handovers the log records, in order.
	Rotations []KeyHandover
}

// KeyHandover is one key rotation a verified log records.
type KeyHandover struct {
	Seq    int64  `json:"seq"`
	TS     string `json:"ts"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason,omitempty"`
}

// Revoked withdraws trust in a key from a point in the chain onward (ADR-0016).
// Receipts before EffectiveSize keep verifying; the key signing at or after it
// is a verification failure.
//
// It is the caller's job to turn published revocation records into these, and to
// check each one against the anchored checkpoint it names first. Verification
// takes the judgement, not the evidence for it.
type Revoked struct {
	// Kid is the key that is no longer trusted.
	Kid string
	// EffectiveSize is the size of the last checkpoint believed good, so it is
	// the sequence number from which this key's receipts are refused.
	EffectiveSize int64
}

type decisionInfo struct {
	taskID   string
	actor    receipt.Actor
	call     receipt.Call
	result   receipt.DecisionResult
	resulted bool
	approval *receipt.Approval
}

func (d *decisionInfo) sameCall(r *receipt.Receipt) bool {
	return d.taskID == r.TaskID && d.actor == *r.Actor && d.call == *r.Call
}

// Verify reads a receipt log and checks every line in order: encoding,
// signature, chain membership, sequence, linkage, time order, and that every
// result receipt refers to an earlier allowed decision for the same call.
// It stops at the first failure and returns it as a *Failure.
//
// Verify alone cannot detect truncation of the newest receipts or a full
// rewrite by the key holder; use VerifyWithCheckpoints for that. It cannot
// follow a key rotation either, because it has nothing to judge the incoming
// key against: use VerifyWithKeys for a chain that rotates.
func Verify(log io.Reader, chainID string, keys KeyResolver) (*Report, error) {
	return VerifyWithCheckpoints(log, chainID, keys, nil)
}

// VerifyWithCheckpoints verifies the log as Verify does, then checks it against
// anchored checkpoints. The checkpoints must already be signature-verified, for
// example with checkpoint.ReadVerified. Every checkpoint must match the log's
// prefix of its size: a log shorter than a checkpoint was truncated, and a log
// whose prefix hashes differently was rewritten, or the anchor shows a fork.
func VerifyWithCheckpoints(log io.Reader, chainID string, keys KeyResolver, cps []*checkpoint.Checkpoint) (*Report, error) {
	return VerifyWithKeys(log, chainID, fixedKeys{keys}, cps)
}

// VerifyWithKeys verifies the log as VerifyWithCheckpoints does and follows key
// rotations (ADR-0016). Exactly one key signs the chain at any point: the key
// bound into the genesis parameters until a key_rotation receipt hands over, and
// the incoming key after it. A rotation is accepted only if the outgoing key
// signed it and keys accepts the incoming key, so an auditor's trust file holds
// one key however often the chain rotates.
func VerifyWithKeys(log io.Reader, chainID string, keys Keys, cps []*checkpoint.Checkpoint) (*Report, error) {
	return VerifyAll(log, chainID, Options{Keys: keys, Checkpoints: cps})
}

// Options are everything verification can be given beyond the log itself.
type Options struct {
	// Keys resolves signing keys and judges the keys rotations introduce.
	Keys Keys
	// Checkpoints are anchored, already signature-verified checkpoints.
	Checkpoints []*checkpoint.Checkpoint
	// Revocations withdraw trust in a key from a checkpoint onward.
	Revocations []Revoked
}

// VerifyAll is verification with everything it can be given: rotations to
// follow, checkpoints to check the log against, and revocations to enforce.
func VerifyAll(log io.Reader, chainID string, o Options) (*Report, error) {
	keys, cps := o.Keys, o.Checkpoints
	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	// Heads of the lines each checkpoint covers, by checkpoint size.
	heads := map[int64]string{}
	for _, c := range cps {
		heads[c.Size] = ""
	}

	var (
		lineNo int
		seq    int64
		prev   string
		lastTS string
		// signer is the key ID allowed to sign at this point in the chain.
		signer    string
		rotations []KeyHandover
		leaves    []merkle.Hash
		decisions = map[int64]*decisionInfo{}
	)

	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		fail := func(reason Reason, format string, a ...any) error {
			return &Failure{Line: lineNo, Seq: seq, Reason: reason, Detail: fmt.Sprintf(format, a...)}
		}

		s, err := receipt.ParseLine(line)
		if err != nil {
			return nil, fail(ReasonMalformed, "%v", err)
		}
		kid, err := s.KeyID()
		if err != nil {
			return nil, fail(ReasonMalformed, "%v", err)
		}
		pub, err := keys.Resolve(kid)
		if err != nil || pub == nil {
			return nil, fail(ReasonUnknownKey, "kid %q: %v", kid, err)
		}
		r, err := receipt.Verify(pub, s)
		switch {
		case errors.Is(err, receipt.ErrBadSignature):
			return nil, fail(ReasonBadSignature, "kid %q", kid)
		case errors.Is(err, receipt.ErrInvalid), errors.Is(err, receipt.ErrUnsupportedType):
			return nil, fail(ReasonInvalidReceipt, "%v", err)
		case err != nil:
			return nil, fail(ReasonMalformed, "%v", err)
		}

		if r.ChainID != chainID {
			return nil, fail(ReasonWrongChain, "chain_id %q, want %q", r.ChainID, chainID)
		}
		if r.Seq != seq {
			return nil, fail(ReasonSeqGap, "seq %d, want %d", r.Seq, seq)
		}
		if seq == 0 {
			if prev, err = NewParams(chainID, kid, pub).GenesisPrev(); err != nil {
				return nil, fail(ReasonMalformed, "genesis: %v", err)
			}
		}
		if r.Prev != prev {
			return nil, fail(ReasonChainBreak, "prev does not match the previous line")
		}
		if r.TS < lastTS {
			return nil, fail(ReasonTimeRegression, "ts %s is before %s", r.TS, lastTS)
		}
		// One key signs the chain at a time. A key the chain has retired is as
		// unwelcome here as a key it never used, whatever the trust file says.
		if seq == 0 {
			signer = kid
		} else if kid != signer {
			return nil, fail(ReasonWrongKey, "signed by kid %q, but the chain's current key is %q", kid, signer)
		}
		// A revoked key keeps everything it signed up to the checkpoint believed
		// good, and nothing after it.
		for _, rev := range o.Revocations {
			if rev.Kid == kid && seq >= rev.EffectiveSize {
				return nil, fail(ReasonRevokedKey,
					"kid %q was revoked from seq %d onward", kid, rev.EffectiveSize)
			}
		}

		switch r.Type {
		case receipt.TypeDecision:
			decisions[seq] = &decisionInfo{taskID: r.TaskID, actor: *r.Actor, call: *r.Call, result: r.Decision.Result}
		case receipt.TypeApproval:
			a := r.Approval
			d := decisions[a.DecisionSeq]
			switch {
			case d == nil || d.result != receipt.RequireApproval:
				return nil, fail(ReasonBadReference, "decision_seq %d is not a require_approval decision in this log", a.DecisionSeq)
			case !d.sameCall(r):
				return nil, fail(ReasonBadReference, "task, actor, or call differs from decision %d", a.DecisionSeq)
			case d.approval != nil:
				return nil, fail(ReasonDuplicateApproval, "decision %d already has an approval", a.DecisionSeq)
			case d.resulted:
				return nil, fail(ReasonBadReference, "decision %d already has a result", a.DecisionSeq)
			case a.Approver == d.actor.Principal:
				return nil, fail(ReasonSelfApproval, "principal %q approved their own call", a.Approver)
			}
			copied := *a
			d.approval = &copied
		case receipt.TypeResult:
			d := decisions[r.Result.DecisionSeq]
			switch {
			case d == nil:
				return nil, fail(ReasonBadReference, "decision_seq %d is not a decision in this log", r.Result.DecisionSeq)
			case !d.sameCall(r):
				return nil, fail(ReasonBadReference, "task, actor, or call differs from decision %d", r.Result.DecisionSeq)
			case d.resulted:
				return nil, fail(ReasonDuplicateResult, "decision %d already has a result", r.Result.DecisionSeq)
			case d.result == receipt.Deny:
				return nil, fail(ReasonDeniedCallExecuted, "decision %d was deny", r.Result.DecisionSeq)
			case d.result == receipt.RequireApproval && d.approval == nil:
				return nil, fail(ReasonMissingApproval, "decision %d required approval and has none", r.Result.DecisionSeq)
			case d.result == receipt.RequireApproval && d.approval.Outcome != receipt.Approved:
				return nil, fail(ReasonRejectedCallExecuted, "decision %d was rejected by %q", r.Result.DecisionSeq, d.approval.Approver)
			case d.result == receipt.RequireApproval && r.TS > d.approval.ExpiresTS:
				return nil, fail(ReasonApprovalExpired, "result at %s is after the approval expired at %s", r.TS, d.approval.ExpiresTS)
			}
			d.resulted = true
		case receipt.TypeKeyRotation:
			rot := r.Rotation
			// The outgoing key must sign its own handover, so taking over a chain
			// needs the old key as well as the CA.
			if rot.From != kid {
				return nil, fail(ReasonBadRotation, "hands over from %q but the receipt is signed by %q", rot.From, kid)
			}
			cert, err := base64.RawURLEncoding.Strict().DecodeString(rot.Certificate)
			if err != nil {
				return nil, fail(ReasonBadRotation, "certificate: %v", err)
			}
			// The certificate is judged as of the rotation, not as of now, so a
			// log stays verifiable after the epoch it records has expired.
			at, err := time.Parse(receipt.TimeFormat, r.TS)
			if err != nil {
				return nil, fail(ReasonBadRotation, "ts: %v", err)
			}
			if err := keys.Accept(rot.To, rot.Key, cert, at); err != nil {
				return nil, fail(ReasonUncertifiedKey, "incoming key %q: %v", rot.To, err)
			}
			signer = rot.To
			rotations = append(rotations, KeyHandover{Seq: seq, TS: r.TS, From: rot.From, To: rot.To, Reason: rot.Reason})
		}

		prev = digest.SHA256(line)
		leaves = append(leaves, merkle.LeafHash(line))
		if _, ok := heads[seq+1]; ok {
			heads[seq+1] = prev
		}
		lastTS = r.TS
		seq++
	}
	if err := sc.Err(); err != nil {
		return nil, &Failure{Line: lineNo + 1, Seq: seq, Reason: ReasonMalformed, Detail: err.Error()}
	}
	if lineNo == 0 {
		return nil, &Failure{Line: 0, Seq: 0, Reason: ReasonEmptyLog, Detail: "no receipts"}
	}

	rep := &Report{ChainID: chainID, Receipts: lineNo, LastSeq: seq - 1, Head: prev, Rotations: rotations}

	sorted := slices.Clone(cps)
	slices.SortFunc(sorted, func(a, b *checkpoint.Checkpoint) int { return cmp.Compare(a.Size, b.Size) })
	for _, c := range sorted {
		switch {
		case c.ChainID != chainID:
			return nil, &Failure{Line: 0, Seq: 0, Reason: ReasonCheckpointMismatch,
				Detail: fmt.Sprintf("checkpoint for chain %q", c.ChainID)}
		case c.Size > int64(lineNo):
			return nil, &Failure{Line: lineNo + 1, Seq: int64(lineNo), Reason: ReasonCheckpointMismatch,
				Detail: fmt.Sprintf("log has %d receipts but the checkpoint at %s covers %d: receipts were removed", lineNo, c.TS, c.Size)}
		case merkle.Digest(merkle.Root(leaves[:c.Size])) != c.Root || heads[c.Size] != c.Head:
			return nil, &Failure{Line: int(c.Size), Seq: c.Size - 1, Reason: ReasonCheckpointMismatch,
				Detail: fmt.Sprintf("the first %d receipts differ from the checkpoint at %s", c.Size, c.TS)}
		}
		rep.Checkpointed = c.Size
	}
	rep.Unanchored = int64(lineNo) - rep.Checkpointed
	for s, d := range decisions {
		if d.result == receipt.Allow && !d.resulted {
			rep.OpenDecisions = append(rep.OpenDecisions, s)
		}
	}
	slices.Sort(rep.OpenDecisions)
	return rep, nil
}
