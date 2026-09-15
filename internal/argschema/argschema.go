// Package argschema checks tool-call arguments against the input schema pinned for the
// tool (ADR-0013, threat W2). The agent is untrusted: arguments that the reviewed
// schema does not allow never reach policy or the tool.
package argschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("arguments do not match the tool's input schema")

// maxDetail bounds the reason returned to the agent.
const maxDetail = 300

// Validator checks arguments against one compiled schema. It is safe for concurrent use.
type Validator struct {
	resolved *jsonschema.Resolved
}

// Compile prepares a pinned input schema. Only references inside the schema are
// followed: with no loader, a remote $ref is an error, so validation never reaches
// the network.
func Compile(schema any) (*Validator, error) {
	if schema == nil {
		return nil, errors.New("argschema: the tool has no input schema")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("argschema: %w", err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("argschema: invalid schema: %w", err)
	}
	resolved, err := s.Resolve(&jsonschema.ResolveOptions{})
	if err != nil {
		return nil, fmt.Errorf("argschema: invalid schema: %w", err)
	}
	return &Validator{resolved: resolved}, nil
}

// Validate checks a JSON arguments value, which must be an object.
func (v *Validator) Validate(args json.RawMessage) error {
	var instance any
	dec := json.NewDecoder(bytes.NewReader(args))
	if err := dec.Decode(&instance); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after the arguments", ErrInvalid)
	}
	if _, ok := instance.(map[string]any); !ok {
		return fmt.Errorf("%w: arguments must be a JSON object", ErrInvalid)
	}
	if err := v.resolved.Validate(instance); err != nil {
		msg := err.Error()
		if len(msg) > maxDetail {
			msg = msg[:maxDetail] + "..."
		}
		return fmt.Errorf("%w: %s", ErrInvalid, msg)
	}
	return nil
}
