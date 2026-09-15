// Package policy decides tool calls with Cedar (ADR-0007).
//
// Cedar answers only allow or deny, so every call is evaluated twice:
//
//	Action::"call"             denied  -> deny
//	Action::"call_unattended"  allowed -> allow
//	otherwise                          -> require_approval
//
// Cedar skips a policy that fails to evaluate. If that policy is a forbid, the
// forbid silently stops applying, so Warden treats any evaluation error on
// either action as a deny.
//
// Request shape:
//
//	principal  User::"<principal>"   parents Role::"<role>" for each role
//	resource   Tool::"<server>/<tool>"  parent Server::"<server>"
//	context    { agent: String, task: String, args: Record, taint: Set<String> }
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	// ActionCall is evaluated first; a deny here denies the call.
	ActionCall = "call"
	// ActionUnattended decides whether an allowed call may run without approval.
	ActionUnattended = "call_unattended"

	maxArgsDepth = 16
	maxRuleLen   = 256
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// ErrInput is returned when the call cannot be turned into a Cedar request. The
// accompanying decision is always a deny.
var ErrInput = errors.New("policy: invalid input")

// Engine evaluates one immutable policy set.
type Engine struct {
	set      *cedar.PolicySet
	revision string
}

// Load parses a Cedar policy document. Every policy must carry a unique
// @id("...") annotation; receipts record these IDs as the deciding rule. The
// policy revision is the SHA-256 of the document bytes.
func Load(name string, text []byte) (*Engine, error) {
	list, err := cedar.NewPolicyListFromBytes(name, text)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("policy: no policies")
	}
	set := cedar.NewPolicySet()
	for i, p := range list {
		id, ok := p.Annotations()["id"]
		if !ok {
			return nil, fmt.Errorf("policy: policy %d at %v has no @id annotation", i, p.Position())
		}
		if !idPattern.MatchString(string(id)) {
			return nil, fmt.Errorf("policy: @id %q must match %s", id, idPattern)
		}
		if !set.Add(cedar.PolicyID(id), p) {
			return nil, fmt.Errorf("policy: duplicate @id %q", id)
		}
	}
	return &Engine{set: set, revision: digest.SHA256(text)}, nil
}

// Revision is the digest of the policy document, recorded in every decision.
func (e *Engine) Revision() string { return e.revision }

// Input describes one proposed call.
type Input struct {
	Principal string
	Roles     []string
	Agent     string
	TaskID    string
	Server    string
	Tool      string
	// Args is the tool's JSON arguments object, as proposed by the agent.
	Args  json.RawMessage
	Taint []string
}

// Decision is the policy outcome for a call, ready for a decision receipt.
type Decision struct {
	Result         receipt.DecisionResult
	Rule           string
	PolicyRevision string
	// Errors lists Cedar evaluation errors; non-empty means the call was denied
	// because policy could not be evaluated safely.
	Errors []string
}

// Decide evaluates a call. It never returns allow or require_approval together
// with a non-nil error.
func (e *Engine) Decide(in Input) (Decision, error) {
	deny := Decision{Result: receipt.Deny, PolicyRevision: e.revision}

	req, ents, err := buildRequest(in)
	if err != nil {
		deny.Rule = "invalid_input"
		return deny, err
	}

	req.Action = types.NewEntityUID("Action", ActionCall)
	ok, diag := cedar.Authorize(e.set, ents, req)
	if len(diag.Errors) > 0 {
		return errorDecision(deny, diag), nil
	}
	if !ok {
		deny.Rule = ruleOf(diag.Reasons)
		return deny, nil
	}
	callRule := ruleOf(diag.Reasons)

	req.Action = types.NewEntityUID("Action", ActionUnattended)
	unattended, diag := cedar.Authorize(e.set, ents, req)
	if len(diag.Errors) > 0 {
		return errorDecision(deny, diag), nil
	}
	if unattended {
		return Decision{Result: receipt.Allow, Rule: ruleOf(diag.Reasons), PolicyRevision: e.revision}, nil
	}
	return Decision{Result: receipt.RequireApproval, Rule: callRule, PolicyRevision: e.revision}, nil
}

func errorDecision(deny Decision, diag cedar.Diagnostic) Decision {
	ids := make([]types.PolicyID, 0, len(diag.Errors))
	for _, e := range diag.Errors {
		ids = append(ids, e.PolicyID)
		deny.Errors = append(deny.Errors, e.Message)
	}
	deny.Rule = limitRule("error:" + joinIDs(ids))
	return deny
}

func ruleOf(reasons []types.DiagnosticReason) string {
	ids := make([]types.PolicyID, 0, len(reasons))
	for _, r := range reasons {
		ids = append(ids, r.PolicyID)
	}
	return limitRule(joinIDs(ids))
}

func joinIDs(ids []types.PolicyID) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = string(id)
	}
	slices.Sort(s)
	return strings.Join(slices.Compact(s), ",")
}

// limitRule keeps the rule within the receipt's field limit.
func limitRule(rule string) string {
	if len(rule) <= maxRuleLen {
		return rule
	}
	cut := strings.LastIndex(rule[:maxRuleLen-16], ",")
	if cut < 0 {
		cut = maxRuleLen - 16
	}
	more := strings.Count(rule[cut:], ",")
	return rule[:cut] + ",+" + strconv.Itoa(more) + "more"
}

func buildRequest(in Input) (cedar.Request, types.EntityMap, error) {
	for field, v := range map[string]string{"principal": in.Principal, "agent": in.Agent, "task": in.TaskID, "server": in.Server, "tool": in.Tool} {
		if v == "" {
			return cedar.Request{}, nil, fmt.Errorf("%w: missing %s", ErrInput, field)
		}
	}
	if strings.Contains(in.Server, "/") {
		return cedar.Request{}, nil, fmt.Errorf("%w: server contains '/'", ErrInput)
	}

	args, err := convertArgs(in.Args)
	if err != nil {
		return cedar.Request{}, nil, err
	}
	taint := make([]types.Value, len(in.Taint))
	for i, t := range in.Taint {
		taint[i] = types.String(t)
	}

	principal := types.NewEntityUID("User", types.String(in.Principal))
	roles := make([]types.EntityUID, len(in.Roles))
	for i, r := range in.Roles {
		roles[i] = types.NewEntityUID("Role", types.String(r))
	}
	tool := types.NewEntityUID("Tool", types.String(in.Server+"/"+in.Tool))
	ents := types.EntityMap{
		principal: {UID: principal, Parents: types.NewEntityUIDSet(roles...)},
		tool:      {UID: tool, Parents: types.NewEntityUIDSet(types.NewEntityUID("Server", types.String(in.Server)))},
	}
	req := cedar.Request{
		Principal: principal,
		Resource:  tool,
		Context: types.NewRecord(types.RecordMap{
			"agent": types.String(in.Agent),
			"task":  types.String(in.TaskID),
			"args":  args,
			"taint": types.NewSet(taint...),
		}),
	}
	return req, ents, nil
}

// convertArgs turns a JSON arguments object into a Cedar record. Anything Cedar
// cannot represent exactly is refused rather than approximated: non-integer or
// out-of-range numbers, nulls, duplicate keys, and deep nesting.
func convertArgs(raw json.RawMessage) (types.Record, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return types.NewRecord(types.RecordMap{}), nil
	}
	// Transform rejects duplicate keys and invalid UTF-8; its output is not used,
	// because it would round large integers.
	if _, err := canonical.Transform(raw); err != nil {
		return types.Record{}, fmt.Errorf("%w: args: %v", ErrInput, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return types.Record{}, fmt.Errorf("%w: args: %v", ErrInput, err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return types.Record{}, fmt.Errorf("%w: args must be a JSON object", ErrInput)
	}
	val, err := toValue(obj, 1)
	if err != nil {
		return types.Record{}, err
	}
	return val.(types.Record), nil
}

func toValue(v any, depth int) (types.Value, error) {
	if depth > maxArgsDepth {
		return nil, fmt.Errorf("%w: args nested deeper than %d", ErrInput, maxArgsDepth)
	}
	switch x := v.(type) {
	case nil:
		return nil, fmt.Errorf("%w: args contain null, which policy cannot evaluate", ErrInput)
	case bool:
		return types.Boolean(x), nil
	case string:
		return types.String(x), nil
	case json.Number:
		i, err := x.Int64()
		if err != nil || i > canonical.MaxSafeInteger || i < -canonical.MaxSafeInteger {
			return nil, fmt.Errorf("%w: args number %s is not an integer within ±(2^53-1)", ErrInput, x)
		}
		return types.Long(i), nil
	case []any:
		vals := make([]types.Value, len(x))
		for i, e := range x {
			ev, err := toValue(e, depth+1)
			if err != nil {
				return nil, err
			}
			vals[i] = ev
		}
		return types.NewSet(vals...), nil
	case map[string]any:
		rm := make(types.RecordMap, len(x))
		for k, e := range x {
			ev, err := toValue(e, depth+1)
			if err != nil {
				return nil, err
			}
			rm[types.String(k)] = ev
		}
		return types.NewRecord(rm), nil
	default:
		return nil, fmt.Errorf("%w: unsupported args value %T", ErrInput, v)
	}
}
