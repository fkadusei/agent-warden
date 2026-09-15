// Package receipt defines Warden's receipt payload and its signed envelope
// (design §4).
package receipt

import (
	"errors"
	"fmt"
	"time"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/digest"
)

const (
	// Version is the receipt format version.
	Version = 1
	// Domain separates Warden receipts from any other signed JSON (threat W14).
	Domain = "agent-warden/receipt/v1"
	// MaxSeq is the largest sequence number, the largest integer JCS keeps exact.
	MaxSeq = canonical.MaxSafeInteger
	// TimeFormat is the only accepted timestamp spelling: UTC, milliseconds, "Z".
	TimeFormat = "2006-01-02T15:04:05.000Z"

	maxIDLen = 256
)

// Type is the kind of event a receipt records.
type Type string

const (
	TypeDecision    Type = "decision"
	TypeApproval    Type = "approval"
	TypeResult      Type = "result"
	TypeKeyRotation Type = "key_rotation"
	TypeCheckpoint  Type = "checkpoint"
)

// DecisionResult is the policy outcome for a proposed call.
type DecisionResult string

const (
	Allow           DecisionResult = "allow"
	Deny            DecisionResult = "deny"
	RequireApproval DecisionResult = "require_approval"
)

// ResultStatus is the outcome of an executed call.
type ResultStatus string

const (
	StatusOK    ResultStatus = "ok"
	StatusError ResultStatus = "error"
)

// ApprovalOutcome is the approver's answer to a require_approval decision.
type ApprovalOutcome string

const (
	Approved ApprovalOutcome = "approved"
	Rejected ApprovalOutcome = "rejected"
)

var (
	// ErrInvalid wraps every receipt validation failure.
	ErrInvalid = errors.New("receipt: invalid")
	// ErrUnsupportedType is returned for receipt types whose bodies are not
	// specified yet (key_rotation, checkpoint).
	ErrUnsupportedType = errors.New("receipt: type not yet specified")
)

// Receipt is the signed payload. Optional sections are present only for the
// types that use them; Validate enforces which.
type Receipt struct {
	V        int       `json:"v"`
	Domain   string    `json:"domain"`
	ChainID  string    `json:"chain_id"`
	Seq      int64     `json:"seq"`
	Prev     string    `json:"prev"`
	TS       string    `json:"ts"`
	Type     Type      `json:"type"`
	TaskID   string    `json:"task_id,omitempty"`
	Actor    *Actor    `json:"actor,omitempty"`
	Call     *Call     `json:"call,omitempty"`
	Decision *Decision `json:"decision,omitempty"`
	Result   *Result   `json:"result,omitempty"`
	Approval *Approval `json:"approval,omitempty"`
}

// Actor records who acted and on whose behalf (threat W4).
type Actor struct {
	Agent     string `json:"agent"`
	Principal string `json:"principal"`
}

// Call identifies the tool call a receipt is about.
type Call struct {
	Tool           string `json:"tool"`
	Manifest       string `json:"manifest"`
	ArgsCommitment string `json:"args_commitment"`
}

// Decision is the policy outcome recorded before anything executes (ADR-0004).
type Decision struct {
	Result         DecisionResult `json:"result"`
	PolicyRevision string         `json:"policy_revision"`
	Rule           string         `json:"rule,omitempty"`
	Taint          []string       `json:"taint,omitempty"`
}

// Result is the outcome recorded after execution.
type Result struct {
	DecisionSeq      int64        `json:"decision_seq"`
	Status           ResultStatus `json:"status"`
	ResultCommitment string       `json:"result_commitment,omitempty"`
	Taint            []string     `json:"taint,omitempty"`
}

// Approval answers a require_approval decision (ADR-0009).
type Approval struct {
	DecisionSeq int64           `json:"decision_seq"`
	Outcome     ApprovalOutcome `json:"outcome"`
	Approver    string          `json:"approver"`
	// Statement is the digest of the approver's own signed statement.
	Statement string `json:"statement"`
	ExpiresTS string `json:"expires_ts"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Validate checks the receipt's fields for its type.
func (r *Receipt) Validate() error {
	if r.V != Version {
		return invalid("v is %d, want %d", r.V, Version)
	}
	if r.Domain != Domain {
		return invalid("domain is %q", r.Domain)
	}
	if err := validID("chain_id", r.ChainID); err != nil {
		return err
	}
	if r.Seq < 0 || r.Seq > MaxSeq {
		return invalid("seq %d out of range", r.Seq)
	}
	if !digest.Valid(r.Prev) {
		return invalid("prev is not a sha256 digest")
	}
	ts, err := time.Parse(TimeFormat, r.TS)
	if err != nil || ts.UTC().Format(TimeFormat) != r.TS {
		return invalid("ts %q is not in %s", r.TS, TimeFormat)
	}

	switch r.Type {
	case TypeDecision:
		if err := r.validateCallContext(); err != nil {
			return err
		}
		if r.Result != nil || r.Approval != nil {
			return invalid("decision receipt has a result or approval section")
		}
		return r.Decision.validate()
	case TypeResult:
		if err := r.validateCallContext(); err != nil {
			return err
		}
		if r.Decision != nil || r.Approval != nil {
			return invalid("result receipt has a decision or approval section")
		}
		return r.Result.validate(r.Seq)
	case TypeApproval:
		if err := r.validateCallContext(); err != nil {
			return err
		}
		if r.Decision != nil || r.Result != nil {
			return invalid("approval receipt has a decision or result section")
		}
		return r.Approval.validate(r.Seq, r.TS)
	case TypeKeyRotation, TypeCheckpoint:
		return fmt.Errorf("%w: %s", ErrUnsupportedType, r.Type)
	default:
		return invalid("unknown type %q", r.Type)
	}
}

func (r *Receipt) validateCallContext() error {
	if err := validID("task_id", r.TaskID); err != nil {
		return err
	}
	if r.Actor == nil {
		return invalid("missing actor")
	}
	if err := validID("actor.agent", r.Actor.Agent); err != nil {
		return err
	}
	if err := validID("actor.principal", r.Actor.Principal); err != nil {
		return err
	}
	if r.Call == nil {
		return invalid("missing call")
	}
	if err := validID("call.tool", r.Call.Tool); err != nil {
		return err
	}
	if !digest.Valid(r.Call.Manifest) {
		return invalid("call.manifest is not a sha256 digest")
	}
	if !digest.Valid(r.Call.ArgsCommitment) {
		return invalid("call.args_commitment is not a sha256 digest")
	}
	return nil
}

func (d *Decision) validate() error {
	if d == nil {
		return invalid("missing decision")
	}
	switch d.Result {
	case Allow, Deny, RequireApproval:
	default:
		return invalid("unknown decision result %q", d.Result)
	}
	if !digest.Valid(d.PolicyRevision) {
		return invalid("decision.policy_revision is not a sha256 digest")
	}
	return validTaint("decision.taint", d.Taint)
}

func (res *Result) validate(seq int64) error {
	if res == nil {
		return invalid("missing result")
	}
	if res.DecisionSeq < 0 || res.DecisionSeq >= seq {
		return invalid("result.decision_seq %d must precede seq %d", res.DecisionSeq, seq)
	}
	switch res.Status {
	case StatusOK:
		if !digest.Valid(res.ResultCommitment) {
			return invalid("result.result_commitment is required for status ok")
		}
	case StatusError:
		if res.ResultCommitment != "" && !digest.Valid(res.ResultCommitment) {
			return invalid("result.result_commitment is not a sha256 digest")
		}
	default:
		return invalid("unknown result status %q", res.Status)
	}
	return validTaint("result.taint", res.Taint)
}

func (a *Approval) validate(seq int64, ts string) error {
	if a == nil {
		return invalid("missing approval")
	}
	if a.DecisionSeq < 0 || a.DecisionSeq >= seq {
		return invalid("approval.decision_seq %d must precede seq %d", a.DecisionSeq, seq)
	}
	switch a.Outcome {
	case Approved, Rejected:
	default:
		return invalid("unknown approval outcome %q", a.Outcome)
	}
	if err := validID("approval.approver", a.Approver); err != nil {
		return err
	}
	if !digest.Valid(a.Statement) {
		return invalid("approval.statement is not a sha256 digest")
	}
	exp, err := time.Parse(TimeFormat, a.ExpiresTS)
	if err != nil || exp.UTC().Format(TimeFormat) != a.ExpiresTS {
		return invalid("approval.expires_ts %q is not in %s", a.ExpiresTS, TimeFormat)
	}
	// TimeFormat has a fixed width, so string order is time order.
	if a.ExpiresTS <= ts {
		return invalid("approval.expires_ts must be after the receipt's ts")
	}
	return nil
}

func validTaint(field string, taint []string) error {
	for i, s := range taint {
		if err := validID(fmt.Sprintf("%s[%d]", field, i), s); err != nil {
			return err
		}
	}
	return nil
}

// validID accepts a non-empty, bounded string without control characters.
func validID(field, s string) error {
	if s == "" || len(s) > maxIDLen {
		return invalid("%s must be 1-%d bytes", field, maxIDLen)
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return invalid("%s contains a control character", field)
		}
	}
	return nil
}
