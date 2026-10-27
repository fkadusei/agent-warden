package canonical

import (
	"bytes"
	"testing"
)

// Canonicalizing is idempotent, and whatever it produces passes Check.
func FuzzTransform(f *testing.F) {
	for _, s := range []string{
		`{"b":1,"a":[true,null,"x"]}`, `{"a":1e21}`, `"é"`, `[1.0,2.50,-0]`,
		`{"a":{"c":"😀","b":2}}`, `{"a":"\u001f"}`, ``, `{`, "\xff", `[1e400]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := Transform(b)
		if err != nil {
			return
		}
		again, err := Transform(out)
		if err != nil {
			t.Fatalf("canonical output does not canonicalize: %q: %v", out, err)
		}
		if !bytes.Equal(again, out) {
			t.Fatalf("canonicalizing is not idempotent:\n first: %q\nsecond: %q", out, again)
		}
		if err := Check(out); err != nil {
			t.Fatalf("canonical output fails Check: %q: %v", out, err)
		}
	})
}

type fuzzDoc struct {
	A string   `json:"a"`
	N int64    `json:"n"`
	L []string `json:"l,omitempty"`
}

// Anything DecodeStrict accepts is canonical and re-encodes to exactly its input.
func FuzzDecodeStrict(f *testing.F) {
	for _, s := range []string{
		`{"a":"x","l":["p","q"],"n":3}`, `{"a":"","n":0}`, `{"a":"x","l":[],"n":1}`,
		`{"a":"x","n":1,"z":2}`, `{"n":1,"a":"x"}`, `{"a":"x","n":1.0}`, `{"a":"x","a":"y","n":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var d fuzzDoc
		if err := DecodeStrict(b, &d); err != nil {
			return
		}
		if err := Check(b); err != nil {
			t.Fatalf("accepted non-canonical input %q: %v", b, err)
		}
		again, err := Encode(d)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted %q, which re-encodes as %q (%v)", b, again, err)
		}
	})
}
