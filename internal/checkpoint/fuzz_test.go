package checkpoint

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// No anchor file crashes ReadVerified, and every line it accepts is canonical.
func FuzzReadVerified(f *testing.F) {
	k, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{7}, composite.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	resolve := func(kid string) (*composite.PublicKey, error) {
		if kid == "warden-e1" {
			return k.Public(), nil
		}
		return nil, errors.New("unknown key")
	}
	var anchor []byte
	b := NewBuilder("c1")
	for i := range 3 {
		b.Add([]byte(fmt.Sprintf("line %d", i)))
		cp, err := b.Checkpoint(fmt.Sprintf("2026-09-14T15:04:0%d.000Z", i))
		if err != nil {
			f.Fatal(err)
		}
		s, err := Sign(k, "warden-e1", cp)
		if err != nil {
			f.Fatal(err)
		}
		line, err := s.Line()
		if err != nil {
			f.Fatal(err)
		}
		anchor = append(append(anchor, line...), '\n')
		f.Add(bytes.Clone(anchor))
	}
	f.Add([]byte("\n\n"))
	f.Add([]byte(`{"payload":"","protected":"","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		cps, err := ReadVerified(bytes.NewReader(data), "c1", resolve)
		if err != nil {
			return
		}
		n := 0
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			n++
			s, err := receipt.ParseLine(line)
			if err != nil {
				t.Fatalf("accepted an anchor with an unparseable line %q", line)
			}
			again, _ := s.Line()
			if !bytes.Equal(again, line) {
				t.Fatalf("accepted a non-canonical anchor line %q", line)
			}
		}
		if n != len(cps) {
			t.Fatalf("%d lines but %d checkpoints", n, len(cps))
		}
	})
}
