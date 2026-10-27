package receipt

import (
	"bytes"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
)

// fuzzKey is deterministic, so every fuzzing worker verifies with the same key.
func fuzzKey(tb testing.TB) *composite.PrivateKey {
	tb.Helper()
	k, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{7}, composite.SeedSize))
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func fuzzLine(tb testing.TB, k *composite.PrivateKey, r *Receipt) []byte {
	tb.Helper()
	s, err := Sign(k, "warden-e1", r)
	if err != nil {
		tb.Fatal(err)
	}
	line, err := s.Line()
	if err != nil {
		tb.Fatal(err)
	}
	return line
}

// No line crashes the parser or the verifier. A line that parses is canonical: it
// re-encodes to exactly its bytes. A line that verifies is a valid receipt.
func FuzzParseLine(f *testing.F) {
	k := fuzzKey(f)
	for _, r := range []*Receipt{decision(7), result(8, 7), rotation(9)} {
		f.Add(fuzzLine(f, k, r))
	}
	for _, s := range []string{`{}`, `{"payload":"","protected":"","signature":""}`, `{"payload":"e30","protected":"e30","signature":"AA"}`, `[]`, ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		s, err := ParseLine(line)
		if err != nil {
			return
		}
		again, err := s.Line()
		if err != nil || !bytes.Equal(again, line) {
			t.Fatalf("parsed %q, which re-encodes as %q (%v)", line, again, err)
		}
		s.KeyID()
		r, err := Verify(k.Public(), s)
		if err == nil {
			if err := r.Validate(); err != nil {
				t.Fatalf("a verified receipt is invalid: %v", err)
			}
		}
	})
}

// Changing any one byte of a signed receipt line makes it fail to verify.
func FuzzTamperedLine(f *testing.F) {
	k := fuzzKey(f)
	good := fuzzLine(f, k, decision(7))
	f.Add(uint(0), byte('x'))
	f.Add(uint(len(good)/2), byte('A'))
	f.Add(uint(len(good)-3), byte('0'))
	f.Fuzz(func(t *testing.T, pos uint, b byte) {
		i := int(pos % uint(len(good)))
		if good[i] == b {
			return
		}
		bad := bytes.Clone(good)
		bad[i] = b
		s, err := ParseLine(bad)
		if err != nil {
			return
		}
		if _, err := Verify(k.Public(), s); err == nil {
			t.Fatalf("byte %d changed from %q to %q, and the line still verifies", i, good[i], b)
		}
	})
}
