// Package gateway is Warden's enforcement pipeline (design §3), as a plain Go
// API. The MCP transport (step 2.8) calls it; tests and the demo call it
// directly.
//
// For every proposed call:
//
//  1. identify  verify the task credential (agent, principal, task)
//  2. pin       fetch the tool's current manifest and check it against its pin
//  3. decide    commit to the arguments and ask policy, with the task's taint
//  4. RECEIPT   write the decision receipt; if that fails, refuse the call
//  5. approve   for require_approval, hold the call until an approver answers
//  6. execute   inject credentials and call the tool (re-checking the manifest)
//  7. inspect   scrub echoed credentials and tag the result's taint
//  8. RECEIPT   write the result receipt; if that fails, withhold the result
package gateway

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fkadusei/agent-warden/internal/approval"
	"github.com/fkadusei/agent-warden/internal/argschema"
	"github.com/fkadusei/agent-warden/internal/broker"
	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/commit"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/store"
)

// ToolResult is what a tool server returned.
type ToolResult struct {
	Content []byte
	IsError bool
	// Authors are the principals who wrote the returned content, as the trusted
	// tool server states them; empty when the server does not say.
	Authors []string
}

// Upstream reaches tool servers.
type Upstream interface {
	// Manifest returns the tool's current definition, as the server offers it now.
	Manifest(ctx context.Context, server, tool string) (registry.Manifest, error)
	// Call runs the tool with canonical JSON arguments and the injected credentials.
	Call(ctx context.Context, server, tool string, args json.RawMessage, creds []broker.Credential) (*ToolResult, error)
}

// Config wires the pipeline's parts together.
type Config struct {
	Store     *store.Store
	Registry  *registry.Registry
	Policy    *policy.Engine
	Broker    *broker.Broker
	Roots     *x509.CertPool
	Approvers approval.KeyResolver
	Upstream  Upstream

	// Roles returns a principal's roles for policy; none if nil.
	Roles func(principal string) []string
	// Taint returns the taint label for a tool's output, or "" if its output is
	// trusted; nothing is tainted if nil.
	Taint func(server, tool string) string
	// Inspect returns taint labels for suspicious content in a tool's scrubbed
	// output (see internal/inspect); nothing is inspected if nil. Labels are
	// heuristic: they inform policy and receipts, and never replace authorization.
	Inspect func(content string) []string
	// Now is Warden's clock; time.Now if nil.
	Now func() time.Time
	// ApprovalLimits bound approver statements; approval.DefaultLimits if zero.
	ApprovalLimits approval.Limits
}

// Status is the outcome of a call as the agent sees it.
type Status string

const (
	StatusOK        Status = "ok"
	StatusDenied    Status = "denied"
	StatusPending   Status = "pending_approval"
	StatusToolError Status = "tool_error"
)

// Taint labels the gateway adds on its own.
const (
	TaintCredentialEcho = "credential_echo"
	// TaintForeignPrincipal: the result holds content another principal wrote.
	TaintForeignPrincipal = "foreign_principal"
)

// Response is what the agent receives.
type Response struct {
	Status      Status
	DecisionSeq int64
	// ResultSeq is the result receipt's seq, when the call executed.
	ResultSeq int64
	Rule      string
	// Result is the tool output after scrubbing; empty unless executed.
	Result []byte
	// Taint lists labels this result added to the task.
	Taint              []string
	CredentialScrubbed bool
	// Detail explains a denial or tool error.
	Detail string
}

var (
	// ErrUnauthenticated means the task credential was rejected. No receipt is
	// written, because the request cannot be attributed.
	ErrUnauthenticated = errors.New("gateway: task credential rejected")
	// ErrReceipt means a receipt could not be durably written, so the call was
	// refused (before execution) or its result withheld (after).
	ErrReceipt = errors.New("gateway: receipt not written")
	// ErrUpstream means the tool server could not be reached or described the
	// tool invalidly. No receipt is written.
	ErrUpstream = errors.New("gateway: tool server unavailable")
	// ErrNotPending means there is no call waiting under that decision.
	ErrNotPending = errors.New("gateway: no pending call")
	// ErrAlreadyAnswered means the pending call already has an approval.
	ErrAlreadyAnswered = errors.New("gateway: call already approved or rejected")
	// ErrNotApproved means the call has no valid, unexpired approval.
	ErrNotApproved = errors.New("gateway: call is not approved")
	// ErrMismatch means the credential is for a different agent, principal, or task.
	ErrMismatch = errors.New("gateway: credential does not match the pending call")
)

type pending struct {
	decision receipt.Receipt // with chain_id and seq filled in
	server   string
	tool     string
	args     json.RawMessage
	approval *receipt.Approval
	running  bool
}

// Gateway runs the pipeline. It is safe for concurrent use.
type Gateway struct {
	cfg Config

	receiptMu sync.Mutex // serializes timestamping and appending receipts

	mu      sync.Mutex
	pending map[int64]*pending
	taint   map[string][]string // task -> taint labels
	// validators caches compiled input schemas by manifest digest.
	validators sync.Map
}

// New checks cfg and returns a gateway.
func New(cfg Config) (*Gateway, error) {
	switch {
	case cfg.Store == nil, cfg.Registry == nil, cfg.Policy == nil, cfg.Broker == nil,
		cfg.Roots == nil, cfg.Approvers == nil, cfg.Upstream == nil:
		return nil, errors.New("gateway: store, registry, policy, broker, roots, approvers, and upstream are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ApprovalLimits == (approval.Limits{}) {
		cfg.ApprovalLimits = approval.DefaultLimits
	}
	return &Gateway{cfg: cfg, pending: map[int64]*pending{}, taint: map[string][]string{}}, nil
}

// appendReceipt timestamps r with Warden's clock and durably writes it. Holding
// receiptMu keeps timestamps in the order receipts are appended.
func (g *Gateway) appendReceipt(ctx context.Context, r *receipt.Receipt) (*store.Appended, error) {
	g.receiptMu.Lock()
	defer g.receiptMu.Unlock()
	r.TS = g.cfg.Now().UTC().Format(receipt.TimeFormat)
	a, err := g.cfg.Store.Append(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReceipt, err)
	}
	return a, nil
}

func (g *Gateway) taintOf(task string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.taint[task])
}

func (g *Gateway) addTaint(task string, labels []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range labels {
		if !slices.Contains(g.taint[task], l) {
			g.taint[task] = append(g.taint[task], l)
		}
	}
	slices.Sort(g.taint[task])
}

// commitArgs canonicalizes the arguments, commits to them, and stores the
// opening. Arguments that are not canonicalizable are committed as a JSON
// string of their raw bytes, so the refusal can still be receipted.
func (g *Gateway) commitArgs(ctx context.Context, args json.RawMessage) (json.RawMessage, string, error) {
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	var value any = json.RawMessage(nil)
	canon, err := canonical.Transform(args)
	if err == nil {
		value = json.RawMessage(canon)
	} else if utf8.Valid(args) {
		value = string(args)
	} else {
		value = fmt.Sprintf("%q", args)
	}
	c, salt, err := commit.New(value)
	if err != nil {
		return nil, "", fmt.Errorf("%w: args commitment: %v", ErrReceipt, err)
	}
	stored, err := canonical.Encode(value)
	if err != nil {
		return nil, "", fmt.Errorf("%w: args commitment: %v", ErrReceipt, err)
	}
	if err := g.cfg.Store.SaveOpening(ctx, c, salt, stored); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrReceipt, err)
	}
	return canon, c, nil
}

// Call runs the pipeline for one proposed call.
func (g *Gateway) Call(ctx context.Context, credential []byte, server, tool string, args json.RawMessage) (*Response, error) {
	task, err := identity.VerifyTask(credential, g.cfg.Roots, g.cfg.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	m, err := g.cfg.Upstream.Manifest(ctx, server, tool)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	if m.Server != server || m.Name != tool {
		return nil, fmt.Errorf("%w: server described %s, not %s/%s", ErrUpstream, m.ID(), server, tool)
	}
	manifestDigest, regErr := g.cfg.Registry.Check(m)
	if manifestDigest == "" {
		return nil, fmt.Errorf("%w: invalid manifest: %v", ErrUpstream, regErr)
	}

	canonArgs, argsCommitment, err := g.commitArgs(ctx, args)
	if err != nil {
		return nil, err
	}

	// Arguments must fit the reviewed schema before policy sees them (ADR-0013).
	var argErr error
	if regErr == nil {
		argErr = g.checkArgs(manifestDigest, m.InputSchema, canonArgs)
	}

	taint := g.taintOf(task.Task)
	var dec policy.Decision
	switch {
	case errors.Is(regErr, registry.ErrUnpinned):
		dec = policy.Decision{Result: receipt.Deny, Rule: "tool_unpinned", PolicyRevision: g.cfg.Policy.Revision()}
	case errors.Is(regErr, registry.ErrChanged):
		dec = policy.Decision{Result: receipt.Deny, Rule: "tool_changed", PolicyRevision: g.cfg.Policy.Revision()}
	case regErr != nil:
		return nil, fmt.Errorf("%w: %v", ErrUpstream, regErr)
	case argErr != nil:
		dec = policy.Decision{Result: receipt.Deny, Rule: RuleInvalidArguments, PolicyRevision: g.cfg.Policy.Revision(),
			Errors: []string{argErr.Error()}}
	default:
		var roles []string
		if g.cfg.Roles != nil {
			roles = g.cfg.Roles(task.Principal)
		}
		// On invalid input, Decide returns a deny with rule invalid_input.
		dec, _ = g.cfg.Policy.Decide(policy.Input{
			Principal: task.Principal, Roles: roles, Agent: task.Agent, TaskID: task.Task,
			Server: server, Tool: tool, Args: args, Taint: taint,
		})
	}

	actor := receipt.Actor{Agent: task.Agent, Principal: task.Principal}
	call := receipt.Call{Tool: m.ID(), Manifest: manifestDigest, ArgsCommitment: argsCommitment}
	r := &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, Type: receipt.TypeDecision,
		TaskID: task.Task, Actor: &actor, Call: &call,
		Decision: &receipt.Decision{Result: dec.Result, PolicyRevision: dec.PolicyRevision, Rule: dec.Rule, Taint: taint},
	}
	a, err := g.appendReceipt(ctx, r)
	if err != nil {
		return nil, err // write-ahead: nothing ran (ADR-0004)
	}
	resp := &Response{DecisionSeq: a.Seq, Rule: dec.Rule}

	r.ChainID, r.Seq = g.cfg.Store.ChainID(), a.Seq
	p := &pending{decision: *r, server: server, tool: tool, args: canonArgs}

	switch dec.Result {
	case receipt.Deny:
		resp.Status = StatusDenied
		if len(dec.Errors) > 0 {
			resp.Detail = strings.Join(dec.Errors, "; ")
		}
		return resp, nil
	case receipt.RequireApproval:
		g.mu.Lock()
		g.pending[a.Seq] = p
		g.mu.Unlock()
		resp.Status = StatusPending
		return resp, nil
	default:
		return g.execute(ctx, p, resp)
	}
}

// RuleInvalidArguments denies calls whose arguments do not fit the pinned input
// schema, or whose schema cannot be used (ADR-0013).
const RuleInvalidArguments = "invalid_arguments"

// checkArgs validates arguments against the pinned schema, compiling it once per
// manifest digest. An unusable schema is an error, so the call is denied.
func (g *Gateway) checkArgs(manifestDigest string, schema any, args json.RawMessage) error {
	if cached, ok := g.validators.Load(manifestDigest); ok {
		return cached.(*argschema.Validator).Validate(args)
	}
	v, err := argschema.Compile(schema)
	if err != nil {
		return err
	}
	g.validators.Store(manifestDigest, v)
	return v.Validate(args)
}

// PendingCall is what an approver is shown.
type PendingCall struct {
	Decision   receipt.Receipt
	CallDigest string
	// Args are the canonical arguments the tool would receive.
	Args json.RawMessage
	// Approval is set once an approver has answered.
	Approval *receipt.Approval
}

func (p *pending) view() (*PendingCall, error) {
	cd, err := approval.CallDigest(p.decision.TaskID, *p.decision.Actor, *p.decision.Call)
	if err != nil {
		return nil, err
	}
	pc := &PendingCall{Decision: p.decision, CallDigest: cd, Args: slices.Clone(p.args)}
	if p.approval != nil {
		a := *p.approval
		pc.Approval = &a
	}
	return pc, nil
}

// Pending returns the call waiting under decisionSeq.
func (g *Gateway) Pending(decisionSeq int64) (*PendingCall, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.pending[decisionSeq]
	if p == nil {
		return nil, ErrNotPending
	}
	return p.view()
}

// ListPending returns every call held for approval that has not run yet, in
// decision order.
func (g *Gateway) ListPending() ([]*PendingCall, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*PendingCall, 0, len(g.pending))
	for _, p := range g.pending {
		if p.running {
			continue
		}
		pc, err := p.view()
		if err != nil {
			return nil, err
		}
		out = append(out, pc)
	}
	slices.SortFunc(out, func(a, b *PendingCall) int { return int(a.Decision.Seq - b.Decision.Seq) })
	return out, nil
}

// Approve accepts an approver's signed statement for a pending call and writes
// the approval receipt. It does not execute the call; the agent calls Resume.
func (g *Gateway) Approve(ctx context.Context, statementLine []byte) (*receipt.Approval, error) {
	signed, err := receipt.ParseLine(statementLine)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", approval.ErrStatement, err)
	}
	st, err := approval.Verify(signed, g.cfg.Approvers)
	if err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.pending[st.DecisionSeq]
	switch {
	case p == nil:
		return nil, ErrNotPending
	case p.approval != nil:
		return nil, ErrAlreadyAnswered
	}

	g.receiptMu.Lock()
	defer g.receiptMu.Unlock()
	acc, err := approval.Accept(signed, &p.decision, g.cfg.Approvers, g.cfg.Now(), g.cfg.ApprovalLimits)
	if err != nil {
		return nil, err
	}
	if _, err := g.cfg.Store.SaveStatement(ctx, acc.StatementLine); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReceipt, err)
	}
	if _, err := g.cfg.Store.Append(ctx, acc.Receipt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReceipt, err)
	}
	p.approval = acc.Receipt.Approval
	return p.approval, nil
}

// Resume executes an approved call. The credential must name the same agent,
// principal, and task as the original call.
func (g *Gateway) Resume(ctx context.Context, credential []byte, decisionSeq int64) (*Response, error) {
	now := g.cfg.Now()
	task, err := identity.VerifyTask(credential, g.cfg.Roots, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	g.mu.Lock()
	p := g.pending[decisionSeq]
	switch {
	case p == nil || p.running:
		g.mu.Unlock()
		return nil, ErrNotPending
	case task.Task != p.decision.TaskID || task.Agent != p.decision.Actor.Agent || task.Principal != p.decision.Actor.Principal:
		g.mu.Unlock()
		return nil, ErrMismatch
	case p.approval == nil:
		g.mu.Unlock()
		return nil, fmt.Errorf("%w: no approval yet", ErrNotApproved)
	case p.approval.Outcome != receipt.Approved:
		g.mu.Unlock()
		return nil, fmt.Errorf("%w: rejected by %s", ErrNotApproved, p.approval.Approver)
	case now.UTC().Format(receipt.TimeFormat) >= p.approval.ExpiresTS:
		g.mu.Unlock()
		return nil, fmt.Errorf("%w: approval expired at %s", ErrNotApproved, p.approval.ExpiresTS)
	}
	p.running = true
	g.mu.Unlock()

	resp, err := g.execute(ctx, p, &Response{DecisionSeq: decisionSeq, Rule: p.decision.Decision.Rule})

	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		p.running = false
		return nil, err
	}
	delete(g.pending, decisionSeq)
	return resp, nil
}

// execute runs an allowed or approved call and writes its result receipt.
func (g *Gateway) execute(ctx context.Context, p *pending, resp *Response) (*Response, error) {
	result := &receipt.Result{DecisionSeq: p.decision.Seq}
	var content []byte
	var labels []string

	fail := func(detail string) {
		result.Status = receipt.StatusError
		resp.Status, resp.Detail = StatusToolError, detail
	}

	creds, credErr := g.cfg.Broker.For(p.server, p.tool)
	m, manErr := g.cfg.Upstream.Manifest(ctx, p.server, p.tool)
	var current string
	if manErr == nil {
		current, manErr = g.cfg.Registry.Check(m)
	}

	switch {
	case credErr != nil:
		fail("credential unavailable")
	case manErr != nil || current != p.decision.Call.Manifest:
		fail("tool manifest changed or unavailable before execution")
	default:
		res, err := g.cfg.Upstream.Call(ctx, p.server, p.tool, p.args, creds)
		switch {
		case err != nil:
			fail("tool server error")
		case !utf8.Valid(res.Content):
			fail("tool returned invalid UTF-8")
		default:
			scrubbed, echoed := broker.Scrub(res.Content, creds)
			content = scrubbed
			if g.cfg.Taint != nil {
				if l := g.cfg.Taint(p.server, p.tool); l != "" {
					labels = append(labels, l)
				}
			}
			if echoed {
				labels = append(labels, TaintCredentialEcho)
				resp.CredentialScrubbed = true
			}
			// Content written by someone other than the task's principal must not
			// steer actions taken with this principal's authority (W4).
			for _, a := range res.Authors {
				if a != p.decision.Actor.Principal {
					labels = append(labels, TaintForeignPrincipal)
					break
				}
			}
			if g.cfg.Inspect != nil {
				labels = append(labels, g.cfg.Inspect(string(content))...)
			}
			slices.Sort(labels)
			labels = slices.Compact(labels)
			c, salt, err := commit.New(string(content))
			if err != nil {
				return nil, fmt.Errorf("%w: result commitment: %v", ErrReceipt, err)
			}
			if err := g.cfg.Store.SaveOpening(ctx, c, salt, content); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrReceipt, err)
			}
			result.ResultCommitment = c
			result.Taint = labels
			if res.IsError {
				fail("tool reported an error")
			} else {
				result.Status = receipt.StatusOK
				resp.Status = StatusOK
			}
		}
	}

	actor, call := *p.decision.Actor, *p.decision.Call
	r := &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, Type: receipt.TypeResult,
		TaskID: p.decision.TaskID, Actor: &actor, Call: &call, Result: result,
	}
	a, err := g.appendReceipt(ctx, r)
	if err != nil {
		return nil, err // the result is withheld when it cannot be receipted
	}
	g.addTaint(p.decision.TaskID, labels)
	resp.ResultSeq = a.Seq
	resp.Result = content
	resp.Taint = labels
	return resp, nil
}
