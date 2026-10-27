package chain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// No log crashes the verifier, and a log that verifies has one receipt per line.
func FuzzVerifyLog(f *testing.F) {
	k, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{7}, composite.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	keys := StaticKeys(func(id string) (*composite.PublicKey, error) {
		if id == kid {
			return k.Public(), nil
		}
		return nil, errors.New("unknown key")
	})
	a, err := NewAppender(k, kid, chainA)
	if err != nil {
		f.Fatal(err)
	}
	var log []byte
	for _, r := range scenario(0) {
		_, line, err := a.Append(r)
		if err != nil {
			f.Fatal(err)
		}
		log = append(append(log, line...), '\n')
		f.Add(bytes.Clone(log))
	}
	f.Add([]byte{})
	f.Add([]byte("\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := VerifyAll(bytes.NewReader(data), chainA, Options{
			Keys:        keys,
			Revocations: []Revoked{{Kid: kid, EffectiveSize: 4}},
		})
		if err != nil {
			var f *Failure
			if !errors.As(err, &f) {
				t.Fatalf("verification failed without naming a line: %v", err)
			}
			return
		}
		lines := bytes.Count(data, []byte("\n"))
		if len(data) > 0 && data[len(data)-1] != '\n' {
			lines++
		}
		if rep.Receipts != lines {
			t.Fatalf("%d lines but %d receipts verified", lines, rep.Receipts)
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
			s, err := receipt.ParseLine(line)
			if err != nil {
				t.Fatalf("verified a log containing an unparseable line %q", line)
			}
			if again, _ := s.Line(); !bytes.Equal(again, line) {
				t.Fatalf("verified a log containing a non-canonical line %q", line)
			}
		}
	})
}
