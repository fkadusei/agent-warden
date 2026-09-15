package chain

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
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
)

// maxLine bounds a single log line. A receipt line is a few kilobytes.
const maxLine = 1 << 20

// Failure identifies the first line that failed verification.
type Failure struct {
	// Line is the 1-based line number in the log.
	Line int
	// Seq is the sequence number expected at that line.
	Seq    int64
	Reason Reason
	Detail string
}

func (f *Failure) Error() string {
	return fmt.Sprintf("chain: line %d (seq %d): %s: %s", f.Line, f.Seq, f.Reason, f.Detail)
}

// KeyResolver returns the verification key for a key ID, or an error if the
// key is unknown or not trusted.
type KeyResolver func(kid string) (*composite.PublicKey, error)

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
}

type decisionInfo struct {
	taskID   string
	actor    receipt.Actor
	call     receipt.Call
	result   receipt.DecisionResult
	resulted bool
}

// Verify reads a receipt log and checks every line in order: encoding,
// signature, chain membership, sequence, linkage, time order, and that every
// result receipt refers to an earlier allowed decision for the same call.
// It stops at the first failure and returns it as a *Failure.
func Verify(log io.Reader, chainID string, keys KeyResolver) (*Report, error) {
	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	var (
		lineNo    int
		seq       int64
		prev      string
		lastTS    string
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
		pub, err := keys(kid)
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

		switch r.Type {
		case receipt.TypeDecision:
			decisions[seq] = &decisionInfo{taskID: r.TaskID, actor: *r.Actor, call: *r.Call, result: r.Decision.Result}
		case receipt.TypeResult:
			d := decisions[r.Result.DecisionSeq]
			switch {
			case d == nil:
				return nil, fail(ReasonBadReference, "decision_seq %d is not a decision in this log", r.Result.DecisionSeq)
			case d.taskID != r.TaskID || d.actor != *r.Actor || d.call != *r.Call:
				return nil, fail(ReasonBadReference, "task, actor, or call differs from decision %d", r.Result.DecisionSeq)
			case d.resulted:
				return nil, fail(ReasonDuplicateResult, "decision %d already has a result", r.Result.DecisionSeq)
			case d.result == receipt.Deny:
				return nil, fail(ReasonDeniedCallExecuted, "decision %d was deny", r.Result.DecisionSeq)
			case d.result == receipt.RequireApproval:
				// Approval receipts are not specified yet, so no approval can be shown.
				return nil, fail(ReasonMissingApproval, "decision %d required approval", r.Result.DecisionSeq)
			}
			d.resulted = true
		}

		prev = digest.SHA256(line)
		lastTS = r.TS
		seq++
	}
	if err := sc.Err(); err != nil {
		return nil, &Failure{Line: lineNo + 1, Seq: seq, Reason: ReasonMalformed, Detail: err.Error()}
	}
	if lineNo == 0 {
		return nil, &Failure{Line: 0, Seq: 0, Reason: ReasonEmptyLog, Detail: "no receipts"}
	}

	rep := &Report{ChainID: chainID, Receipts: lineNo, LastSeq: seq - 1, Head: prev}
	for s, d := range decisions {
		if d.result == receipt.Allow && !d.resulted {
			rep.OpenDecisions = append(rep.OpenDecisions, s)
		}
	}
	slices.Sort(rep.OpenDecisions)
	return rep, nil
}
