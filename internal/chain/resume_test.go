package chain

import (
	"bytes"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

func TestResumeContinuesChain(t *testing.T) {
	k := newKey(t)
	rs := scenario(0)

	a, err := NewAppender(k, kid, chainA)
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, r := range rs[:3] {
		_, line, err := a.Append(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}

	// A new appender resumed from the snapshot continues the same chain.
	b, err := ResumeAppender(k, kid, chainA, a.State())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs[3:] {
		_, line, err := b.Append(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	keys := resolver(map[string]*composite.PublicKey{kid: k.Public()})
	if rep, err := Verify(bytes.NewReader(join(lines)), chainA, keys); err != nil || rep.Receipts != 6 {
		t.Fatalf("resumed chain: %+v, %v", rep, err)
	}

	// Resuming a fresh chain's zero state is the same as starting it.
	fresh, err := NewAppender(k, kid, chainA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResumeAppender(k, kid, chainA, fresh.State()); err != nil {
		t.Fatalf("zero state rejected: %v", err)
	}
}

func TestResumeRejectsBadState(t *testing.T) {
	k := newKey(t)
	genesis, err := NewParams(chainA, kid, k.Public()).GenesisPrev()
	if err != nil {
		t.Fatal(err)
	}
	ts := "2026-09-14T15:04:05.000Z"
	cases := map[string]State{
		"seq 0 with a non-genesis prev":   {Next: 0, Prev: digest.SHA256([]byte("x"))},
		"seq 0 with another key's prev":   {Next: 0, Prev: mustGenesis(t, newKey(t))},
		"seq 0 with a timestamp":          {Next: 0, Prev: genesis, LastTS: ts},
		"negative seq":                    {Next: -1, Prev: genesis, LastTS: ts},
		"seq beyond the maximum":          {Next: receipt.MaxSeq + 2, Prev: genesis, LastTS: ts},
		"malformed prev":                  {Next: 3, Prev: "sha256:nope", LastTS: ts},
		"missing timestamp after genesis": {Next: 3, Prev: genesis},
	}
	for name, st := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ResumeAppender(k, kid, chainA, st); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func mustGenesis(t *testing.T, k *composite.PrivateKey) string {
	t.Helper()
	g, err := NewParams(chainA, kid, k.Public()).GenesisPrev()
	if err != nil {
		t.Fatal(err)
	}
	return g
}
