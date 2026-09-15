package argschema

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func compile(t *testing.T, schema string) *Validator {
	t.Helper()
	var s any
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		t.Fatal(err)
	}
	v, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const refund = `{
  "type": "object",
  "properties": {
    "payment_id": {"type": "string"},
    "amount": {"type": "integer", "minimum": 1},
    "note": {"type": "string"}
  },
  "required": ["payment_id", "amount"],
  "additionalProperties": false
}`

func TestValidate(t *testing.T) {
	v := compile(t, refund)
	if err := v.Validate(json.RawMessage(`{"payment_id":"p-1","amount":5}`)); err != nil {
		t.Fatalf("valid arguments rejected: %v", err)
	}
	for name, args := range map[string]string{
		"string amount":         `{"payment_id":"p-1","amount":"5"}`,
		"fractional amount":     `{"payment_id":"p-1","amount":5.5}`,
		"below minimum":         `{"payment_id":"p-1","amount":0}`,
		"missing required":      `{"amount":5}`,
		"extra argument":        `{"payment_id":"p-1","amount":5,"to_account":"x"}`,
		"object for a string":   `{"payment_id":"p-1","amount":5,"note":{"attachments":"[]"}}`,
		"array, not an object":  `[]`,
		"string, not an object": `"p-1"`,
		"null":                  `null`,
		"not JSON":              `{"payment_id":`,
		"trailing data":         `{"payment_id":"p-1","amount":5} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := v.Validate(json.RawMessage(args))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate(%s) = %v, want ErrInvalid", args, err)
			}
		})
	}
}

func TestPermissiveSchemaAllowsAnyObject(t *testing.T) {
	v := compile(t, `{"type":"object"}`)
	if err := v.Validate(json.RawMessage(`{"anything":{"nested":[1,2]}}`)); err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(json.RawMessage(`[1]`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("array accepted: %v", err)
	}
}

func TestLocalReferences(t *testing.T) {
	v := compile(t, `{"$defs":{"id":{"type":"string"}},"type":"object","properties":{"id":{"$ref":"#/$defs/id"}}}`)
	if err := v.Validate(json.RawMessage(`{"id":"c-1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(json.RawMessage(`{"id":7}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong type through $ref accepted: %v", err)
	}
}

// A schema that cannot be used must stop the call, and must never be fetched from
// elsewhere.
func TestCompileRejects(t *testing.T) {
	if _, err := Compile(nil); err == nil {
		t.Error("nil schema accepted")
	}
	for name, schema := range map[string]string{
		"bad type keyword":  `{"type": 5}`,
		"remote reference":  `{"$ref": "https://schemas.example/remote.json"}`,
		"missing reference": `{"type":"object","properties":{"a":{"$ref":"#/$defs/missing"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var s any
			if err := json.Unmarshal([]byte(schema), &s); err != nil {
				t.Fatal(err)
			}
			if _, err := Compile(s); err == nil {
				t.Fatalf("Compile(%s) succeeded", schema)
			}
		})
	}
}

func TestDetailIsBounded(t *testing.T) {
	v := compile(t, `{"type":"object","properties":{"a":{"enum":["x"]}}}`)
	err := v.Validate(json.RawMessage(`{"a":"` + strings.Repeat("y", 5000) + `"}`))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if n := len(err.Error()); n > len(ErrInvalid.Error())+maxDetail+10 {
		t.Fatalf("error is %d bytes", n)
	}
}
