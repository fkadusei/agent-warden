// Package approverapi is the HTTPS API approvers use (ADR-0011), and its client.
//
// POST /v1/pending lists calls held for approval. The request body is a list
// request signed with a trusted approver key: its timestamp must be within one
// minute of Warden's clock and its nonce is accepted once.
//
// POST /v1/approvals submits an approver's signed statement (ADR-0009). It needs
// no further authentication, because the statement itself is signed.
//
// The client does not trust what the server shows. For every pending call it
// checks the displayed arguments against the decision's commitment, and it
// computes the call digest itself, so an approver only signs the call they saw.
package approverapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/fkadusei/agent-warden/internal/approval"
	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/commit"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/store"
)

const (
	// RequestDomain separates list requests from every other signed object.
	RequestDomain = "agent-warden/approver-request/v1"
	// MaxClockSkew bounds how far a list request's timestamp may be from Warden's clock.
	MaxClockSkew = time.Minute

	maxBody = 64 << 10
)

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

var b64 = base64.RawURLEncoding.Strict()

// ListRequest is what an approver signs to list pending calls.
type ListRequest struct {
	Domain   string `json:"domain"`
	Approver string `json:"approver"`
	Nonce    string `json:"nonce"`
	TS       string `json:"ts"`
}

// Pending is one call held for approval, as sent to approvers.
type Pending struct {
	ChainID     string            `json:"chain_id"`
	DecisionSeq int64             `json:"decision_seq"`
	DecisionTS  string            `json:"decision_ts"`
	TaskID      string            `json:"task_id"`
	Actor       receipt.Actor     `json:"actor"`
	Call        receipt.Call      `json:"call"`
	Rule        string            `json:"rule,omitempty"`
	Taint       []string          `json:"taint,omitempty"`
	Args        json.RawMessage   `json:"args"`
	ArgsSalt    string            `json:"args_salt"`
	Approval    *receipt.Approval `json:"approval,omitempty"`
}

// Submitted is the server's answer to an accepted approval.
type Submitted struct {
	DecisionSeq int64                   `json:"decision_seq"`
	Outcome     receipt.ApprovalOutcome `json:"outcome"`
	Approver    string                  `json:"approver"`
	ExpiresTS   string                  `json:"expires_ts"`
}

// Server serves the approver API.
type Server struct {
	gw        *gateway.Gateway
	store     *store.Store
	approvers approval.KeyResolver
	now       func() time.Time

	mu     sync.Mutex
	nonces map[string]time.Time // nonce -> when it may be forgotten
}

// NewServer returns an approver API server. now is time.Now if nil.
func NewServer(gw *gateway.Gateway, st *store.Store, approvers approval.KeyResolver, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{gw: gw, store: st, approvers: approvers, now: now, nonces: map[string]time.Time{}}
}

// Handler returns the API's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pending", s.list)
	mux.HandleFunc("POST /v1/approvals", s.submit)
	return mux
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("request too large")
	}
	return bytes.TrimSpace(b), nil
}

// authenticate checks a signed list request and consumes its nonce.
func (s *Server) authenticate(body []byte) (string, error) {
	signed, err := receipt.ParseLine(body)
	if err != nil {
		return "", errors.New("malformed request")
	}
	kid, err := signed.KeyID()
	if err != nil {
		return "", errors.New("malformed request")
	}
	pub, err := s.approvers(kid)
	if err != nil || pub == nil {
		return "", errors.New("unknown approver")
	}
	payload, err := receipt.VerifyPayload(pub, signed)
	if err != nil {
		return "", errors.New("bad signature")
	}
	var req ListRequest
	if err := canonical.DecodeStrict(payload, &req); err != nil {
		return "", errors.New("malformed request")
	}
	if req.Domain != RequestDomain || req.Approver != kid || !noncePattern.MatchString(req.Nonce) {
		return "", errors.New("malformed request")
	}
	ts, err := time.Parse(receipt.TimeFormat, req.TS)
	now := s.now()
	if err != nil || ts.Before(now.Add(-MaxClockSkew)) || ts.After(now.Add(MaxClockSkew)) {
		return "", errors.New("request timestamp outside the allowed window")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for n, forget := range s.nonces {
		if now.After(forget) {
			delete(s.nonces, n)
		}
	}
	if _, seen := s.nonces[req.Nonce]; seen {
		return "", errors.New("request already used")
	}
	s.nonces[req.Nonce] = ts.Add(2 * MaxClockSkew)
	return kid, nil
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.authenticate(body); err != nil {
		fail(w, http.StatusUnauthorized, err.Error())
		return
	}
	calls, err := s.gw.ListPending()
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not list pending calls")
		return
	}
	out := make([]Pending, 0, len(calls))
	for _, c := range calls {
		salt, _, err := s.store.Opening(r.Context(), c.Decision.Call.ArgsCommitment)
		if err != nil {
			fail(w, http.StatusInternalServerError, "could not read argument opening")
			return
		}
		d := c.Decision
		out = append(out, Pending{
			ChainID: d.ChainID, DecisionSeq: d.Seq, DecisionTS: d.TS, TaskID: d.TaskID,
			Actor: *d.Actor, Call: *d.Call, Rule: d.Decision.Rule, Taint: d.Decision.Taint,
			Args: c.Args, ArgsSalt: b64.EncodeToString(salt), Approval: c.Approval,
		})
	}
	reply(w, map[string]any{"pending": out})
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	a, err := s.gw.Approve(r.Context(), body)
	switch {
	case errors.Is(err, approval.ErrSelfApproval):
		fail(w, http.StatusForbidden, "an approver cannot approve their own call")
	case errors.Is(err, approval.ErrStatement), errors.Is(err, approval.ErrMismatch), errors.Is(err, approval.ErrExpired), errors.Is(err, approval.ErrNotPending):
		fail(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, gateway.ErrNotPending):
		fail(w, http.StatusNotFound, "no call is waiting under that decision")
	case errors.Is(err, gateway.ErrAlreadyAnswered):
		fail(w, http.StatusConflict, "that call has already been approved or rejected")
	case errors.Is(err, gateway.ErrReceipt):
		fail(w, http.StatusServiceUnavailable, "the approval could not be recorded")
	case err != nil:
		fail(w, http.StatusInternalServerError, "approval failed")
	default:
		reply(w, Submitted{DecisionSeq: a.DecisionSeq, Outcome: a.Outcome, Approver: a.Approver, ExpiresTS: a.ExpiresTS})
	}
}

// ErrTampered means the server showed a call that does not match its own
// commitment. Such a call must not be approved.
var ErrTampered = errors.New("approverapi: pending call does not match its commitment")

// Client talks to the approver API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Key     *composite.PrivateKey
	// Approver is the approver's identity, which is also their key ID.
	Approver string
}

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		return fmt.Errorf("approverapi: %s: %s", resp.Status, e.Error)
	}
	return json.Unmarshal(data, out)
}

// List fetches pending calls and verifies each against its commitment.
func (c *Client) List(ctx context.Context) ([]Pending, error) {
	nonce := make([]byte, 24)
	rand.Read(nonce)
	payload, err := canonical.Encode(ListRequest{
		Domain: RequestDomain, Approver: c.Approver, Nonce: b64.EncodeToString(nonce),
		TS: time.Now().UTC().Format(receipt.TimeFormat),
	})
	if err != nil {
		return nil, err
	}
	signed, err := receipt.SignPayload(c.Key, c.Approver, payload)
	if err != nil {
		return nil, err
	}
	line, err := signed.Line()
	if err != nil {
		return nil, err
	}
	var resp struct {
		Pending []Pending `json:"pending"`
	}
	if err := c.post(ctx, "/v1/pending", line, &resp); err != nil {
		return nil, err
	}
	for _, p := range resp.Pending {
		if err := Check(p); err != nil {
			return nil, err
		}
	}
	return resp.Pending, nil
}

// Check verifies that a pending call's displayed arguments open its commitment.
func Check(p Pending) error {
	salt, err := b64.DecodeString(p.ArgsSalt)
	if err != nil {
		return fmt.Errorf("%w: decision #%d: bad salt", ErrTampered, p.DecisionSeq)
	}
	if err := commit.Verify(p.Call.ArgsCommitment, salt, p.Args); err != nil {
		return fmt.Errorf("%w: decision #%d: %v", ErrTampered, p.DecisionSeq, err)
	}
	return nil
}

// Sign produces a signed statement for p. The call digest is computed here from
// the verified call, never taken from the server.
func (c *Client) Sign(p Pending, outcome receipt.ApprovalOutcome, ttl time.Duration) ([]byte, error) {
	if err := Check(p); err != nil {
		return nil, err
	}
	cd, err := approval.CallDigest(p.TaskID, p.Actor, p.Call)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	signed, err := approval.Sign(c.Key, &approval.Statement{
		Domain: approval.StatementDomain, ChainID: p.ChainID, DecisionSeq: p.DecisionSeq, CallDigest: cd,
		Outcome: outcome, Approver: c.Approver,
		TS: now.Format(receipt.TimeFormat), ExpiresTS: now.Add(ttl).Format(receipt.TimeFormat),
	})
	if err != nil {
		return nil, err
	}
	return signed.Line()
}

// Submit sends a signed statement.
func (c *Client) Submit(ctx context.Context, statement []byte) (*Submitted, error) {
	var out Submitted
	if err := c.post(ctx, "/v1/approvals", statement, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
