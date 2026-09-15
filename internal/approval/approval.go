// Package approval checks approver-signed statements and turns them into
// approval receipts (ADR-0009, threat W6).
//
// An approver signs a Statement with their own key, naming the exact call they
// were shown. Warden accepts it only if the statement verifies under a trusted
// approver key whose kid is the approver's identity, answers a require_approval
// decision for the same call, comes from someone other than the requesting
// principal, and has a bounded expiry that has not passed.
package approval

import (
	"errors"
	"fmt"
	"time"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	// StatementDomain separates approval statements from every other signed object.
	StatementDomain = "agent-warden/approval-statement/v1"
	// CallDomain separates call digests from every other hashed object.
	CallDomain = "agent-warden/call/v1"
)

var (
	// ErrStatement is returned for a statement that is malformed, untrusted, or
	// fails its signature.
	ErrStatement = errors.New("approval: invalid statement")
	// ErrNotPending is returned when the decision does not require approval.
	ErrNotPending = errors.New("approval: decision does not require approval")
	// ErrMismatch is returned when the statement answers a different chain,
	// decision, or call.
	ErrMismatch = errors.New("approval: statement does not match the decision")
	// ErrSelfApproval is returned when the approver is the requesting principal.
	ErrSelfApproval = errors.New("approval: approver is the requesting principal")
	// ErrExpired is returned when the statement has expired or its expiry is too long.
	ErrExpired = errors.New("approval: expired or expiry out of range")
)

// KeyResolver returns the trusted public key of an approver by kid. The kid is
// the approver's identity.
type KeyResolver = func(kid string) (*composite.PublicKey, error)

// Statement is what an approver signs.
type Statement struct {
	Domain      string                  `json:"domain"`
	ChainID     string                  `json:"chain_id"`
	DecisionSeq int64                   `json:"decision_seq"`
	CallDigest  string                  `json:"call_digest"`
	Outcome     receipt.ApprovalOutcome `json:"outcome"`
	Approver    string                  `json:"approver"`
	ExpiresTS   string                  `json:"expires_ts"`
	TS          string                  `json:"ts"`
}

// CallDigest is the digest of the call an approver is shown: its task, actor,
// and call, canonicalized with a domain.
func CallDigest(taskID string, actor receipt.Actor, call receipt.Call) (string, error) {
	b, err := canonical.Encode(struct {
		Domain string        `json:"domain"`
		TaskID string        `json:"task_id"`
		Actor  receipt.Actor `json:"actor"`
		Call   receipt.Call  `json:"call"`
	}{CallDomain, taskID, actor, call})
	if err != nil {
		return "", err
	}
	return digest.SHA256(b), nil
}

func parseTS(field, s string) (time.Time, error) {
	t, err := time.Parse(receipt.TimeFormat, s)
	if err != nil || t.UTC().Format(receipt.TimeFormat) != s {
		return time.Time{}, fmt.Errorf("%w: %s %q is not in %s", ErrStatement, field, s, receipt.TimeFormat)
	}
	return t, nil
}

// Validate checks the statement's fields.
func (s *Statement) Validate() error {
	switch {
	case s.Domain != StatementDomain:
		return fmt.Errorf("%w: domain is %q", ErrStatement, s.Domain)
	case s.ChainID == "":
		return fmt.Errorf("%w: missing chain_id", ErrStatement)
	case s.DecisionSeq < 0 || s.DecisionSeq > receipt.MaxSeq:
		return fmt.Errorf("%w: decision_seq %d out of range", ErrStatement, s.DecisionSeq)
	case !digest.Valid(s.CallDigest):
		return fmt.Errorf("%w: call_digest is not a sha256 digest", ErrStatement)
	case s.Outcome != receipt.Approved && s.Outcome != receipt.Rejected:
		return fmt.Errorf("%w: unknown outcome %q", ErrStatement, s.Outcome)
	case s.Approver == "" || len(s.Approver) > 256:
		return fmt.Errorf("%w: approver must be 1-256 bytes", ErrStatement)
	}
	ts, err := parseTS("ts", s.TS)
	if err != nil {
		return err
	}
	exp, err := parseTS("expires_ts", s.ExpiresTS)
	if err != nil {
		return err
	}
	if !exp.After(ts) {
		return fmt.Errorf("%w: expires_ts must be after ts", ErrStatement)
	}
	return nil
}

// Sign signs a statement with the approver's key. The kid is the approver.
func Sign(k *composite.PrivateKey, s *Statement) (*receipt.Signed, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	payload, err := canonical.Encode(s)
	if err != nil {
		return nil, err
	}
	return receipt.SignPayload(k, s.Approver, payload)
}

// Verify checks a signed statement against trusted approver keys and returns it.
// The key ID must equal the statement's approver.
func Verify(signed *receipt.Signed, keys KeyResolver) (*Statement, error) {
	kid, err := signed.KeyID()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	pub, err := keys(kid)
	if err != nil || pub == nil {
		return nil, fmt.Errorf("%w: approver key %q is not trusted", ErrStatement, kid)
	}
	payload, err := receipt.VerifyPayload(pub, signed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	var s Statement
	if err := canonical.DecodeStrict(payload, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.Approver != kid {
		return nil, fmt.Errorf("%w: signed under key %q but names approver %q", ErrStatement, kid, s.Approver)
	}
	return &s, nil
}

// Limits bound statement timing.
type Limits struct {
	// MaxTTL is the longest allowed time from a statement's ts to its expiry.
	MaxTTL time.Duration
	// ClockSkew is how far in the future a statement's ts may be.
	ClockSkew time.Duration
}

// DefaultLimits allows approvals of up to one hour and one minute of clock skew.
var DefaultLimits = Limits{MaxTTL: time.Hour, ClockSkew: time.Minute}

// Accepted is a verified approval, ready to be stored and receipted.
type Accepted struct {
	// Receipt is the approval receipt, without chain_id, seq, or prev.
	Receipt   *receipt.Receipt
	Statement *Statement
	// StatementDigest is the digest of the signed statement's line, as recorded
	// in the receipt.
	StatementDigest string
	// StatementLine is the signed statement to store (ADR-0009).
	StatementLine []byte
}

// Accept checks signed against decision, the verified receipt the statement
// answers, and returns the approval to record. now is Warden's clock.
func Accept(signed *receipt.Signed, decision *receipt.Receipt, keys KeyResolver, now time.Time, lim Limits) (*Accepted, error) {
	if decision.Type != receipt.TypeDecision || decision.Decision == nil || decision.Decision.Result != receipt.RequireApproval {
		return nil, ErrNotPending
	}
	st, err := Verify(signed, keys)
	if err != nil {
		return nil, err
	}
	if st.ChainID != decision.ChainID || st.DecisionSeq != decision.Seq {
		return nil, fmt.Errorf("%w: statement answers %s seq %d, not %s seq %d",
			ErrMismatch, st.ChainID, st.DecisionSeq, decision.ChainID, decision.Seq)
	}
	callDigest, err := CallDigest(decision.TaskID, *decision.Actor, *decision.Call)
	if err != nil {
		return nil, err
	}
	if st.CallDigest != callDigest {
		return nil, fmt.Errorf("%w: the approver was shown a different call", ErrMismatch)
	}
	if st.Approver == decision.Actor.Principal {
		return nil, ErrSelfApproval
	}

	ts, _ := parseTS("ts", st.TS)
	exp, _ := parseTS("expires_ts", st.ExpiresTS)
	now = now.UTC()
	switch {
	case ts.After(now.Add(lim.ClockSkew)):
		return nil, fmt.Errorf("%w: ts %s is in the future", ErrStatement, st.TS)
	case exp.Sub(ts) > lim.MaxTTL:
		return nil, fmt.Errorf("%w: expiry is %s after ts, more than %s", ErrExpired, exp.Sub(ts), lim.MaxTTL)
	}
	nowTS := now.Format(receipt.TimeFormat)
	if nowTS >= st.ExpiresTS {
		return nil, fmt.Errorf("%w: expired at %s", ErrExpired, st.ExpiresTS)
	}

	line, err := signed.Line()
	if err != nil {
		return nil, err
	}
	statementDigest := digest.SHA256(line)
	actor, call := *decision.Actor, *decision.Call
	r := &receipt.Receipt{
		V:      receipt.Version,
		Domain: receipt.Domain,
		TS:     nowTS,
		Type:   receipt.TypeApproval,
		TaskID: decision.TaskID,
		Actor:  &actor,
		Call:   &call,
		Approval: &receipt.Approval{
			DecisionSeq: decision.Seq,
			Outcome:     st.Outcome,
			Approver:    st.Approver,
			Statement:   statementDigest,
			ExpiresTS:   st.ExpiresTS,
		},
	}
	return &Accepted{Receipt: r, Statement: st, StatementDigest: statementDigest, StatementLine: line}, nil
}
