package checkpoint

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/merkle"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	chainID = "01J9Z3CHAIN"
	kid     = "warden-2026-09-e1"
)

func newKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func lines(n int) [][]byte {
	var l [][]byte
	for i := 0; i < n; i++ {
		l = append(l, []byte(fmt.Sprintf(`{"line":%d}`, i)))
	}
	return l
}

func built(t *testing.T, ls [][]byte, ts string) *Checkpoint {
	t.Helper()
	b := NewBuilder(chainID)
	for _, l := range ls {
		b.Add(l)
	}
	c, err := b.Checkpoint(ts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuilder(t *testing.T) {
	ls := lines(5)
	c := built(t, ls, "2026-09-14T15:05:00.000Z")
	var leaves []merkle.Hash
	for _, l := range ls {
		leaves = append(leaves, merkle.LeafHash(l))
	}
	if c.Size != 5 || c.Root != merkle.Digest(merkle.Root(leaves)) || c.Head != digest.SHA256(ls[4]) {
		t.Fatalf("unexpected checkpoint %+v", c)
	}
	if _, err := NewBuilder(chainID).Checkpoint("2026-09-14T15:05:00.000Z"); err == nil {
		t.Fatal("empty builder produced a checkpoint")
	}
}

func TestSignVerify(t *testing.T) {
	k := newKey(t)
	c := built(t, lines(3), "2026-09-14T15:05:00.000Z")
	s, err := Sign(k, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(k.Public(), s)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *c {
		t.Fatalf("round trip changed the checkpoint: %+v vs %+v", got, c)
	}
	if _, err := Verify(newKey(t).Public(), s); !errors.Is(err, receipt.ErrBadSignature) {
		t.Fatalf("other key: got %v, want ErrBadSignature", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	k := newKey(t)
	c := built(t, lines(3), "2026-09-14T15:05:00.000Z")
	s, err := Sign(k, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.Verify(k.Public(), s); err == nil {
		t.Fatal("a checkpoint was accepted as a receipt")
	}

	r := &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, ChainID: chainID, Seq: 0,
		Prev: digest.SHA256(nil), TS: "2026-09-14T15:05:00.000Z", Type: receipt.TypeDecision,
		TaskID:   "t1",
		Actor:    &receipt.Actor{Agent: "a", Principal: "p"},
		Call:     &receipt.Call{Tool: "x", Manifest: digest.SHA256(nil), ArgsCommitment: digest.SHA256(nil)},
		Decision: &receipt.Decision{Result: receipt.Allow, PolicyRevision: digest.SHA256(nil)},
	}
	rs, err := receipt.Sign(k, kid, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(k.Public(), rs); !errors.Is(err, receipt.ErrMalformed) {
		t.Fatalf("receipt as checkpoint: got %v, want ErrMalformed", err)
	}
}

func TestVerifyRejectsValidlySignedBadPayloads(t *testing.T) {
	k := newKey(t)
	good := `{"chain_id":"01J9Z3CHAIN","domain":"agent-warden/checkpoint/v1","head":"` + digest.SHA256(nil) +
		`","root":"` + digest.SHA256(nil) + `","size":3,"ts":"2026-09-14T15:05:00.000Z","v":1}`
	if _, err := Verify(k.Public(), mustSignPayload(t, k, good)); err != nil {
		t.Fatalf("control payload rejected: %v", err)
	}
	cases := map[string]struct {
		payload string
		want    error
	}{
		"unknown field": {strings.Replace(good, `"head":`, `"extra":1,"head":`, 1), receipt.ErrMalformed},
		"missing head":  {strings.Replace(good, `"head":"`+digest.SHA256(nil)+`",`, "", 1), receipt.ErrMalformed},
		"size zero":     {strings.Replace(good, `"size":3`, `"size":0`, 1), ErrInvalid},
		"wrong domain":  {strings.Replace(good, "checkpoint/v1", "receipt/v1", 1), ErrInvalid},
		"bad ts":        {strings.Replace(good, ".000Z", "Z", 1), ErrInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.payload == good {
				t.Fatal("mutation did not apply")
			}
			if _, err := Verify(k.Public(), mustSignPayload(t, k, c.payload)); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func mustSignPayload(t *testing.T, k *composite.PrivateKey, payload string) *receipt.Signed {
	t.Helper()
	s, err := receipt.SignPayload(k, kid, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPolicy(t *testing.T) {
	p := Policy{Every: 3, Interval: time.Minute}
	t0 := time.Date(2026, 9, 14, 15, 0, 0, 0, time.UTC)
	cases := []struct {
		name           string
		lastSize, size int64
		now            time.Time
		want           bool
	}{
		{"nothing new, time passed", 5, 5, t0.Add(time.Hour), false},
		{"few new, little time", 5, 7, t0.Add(time.Second), false},
		{"enough new receipts", 5, 8, t0.Add(time.Second), true},
		{"interval elapsed", 5, 6, t0.Add(time.Minute), true},
	}
	for _, c := range cases {
		if got := p.Due(c.lastSize, c.size, t0, c.now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFileAnchor(t *testing.T) {
	k := newKey(t)
	keys := func(id string) (*composite.PublicKey, error) {
		if id == kid {
			return k.Public(), nil
		}
		return nil, errors.New("unknown")
	}
	path := filepath.Join(t.TempDir(), "anchor.jsonl")
	a := FileAnchor{Path: path}
	ls := lines(6)
	publish := func(n int, ts string) *receipt.Signed {
		t.Helper()
		s, err := Sign(k, kid, built(t, ls[:n], ts))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Publish(s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	publish(2, "2026-09-14T15:05:00.000Z")
	publish(5, "2026-09-14T15:06:00.000Z")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cps, err := ReadVerified(bytes.NewReader(data), chainID, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 2 || cps[0].Size != 2 || cps[1].Size != 5 {
		t.Fatalf("unexpected checkpoints %+v", cps)
	}

	rows := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	t.Run("reordered anchor", func(t *testing.T) {
		swapped := append(append(bytes.Clone(rows[1]), '\n'), append(bytes.Clone(rows[0]), '\n')...)
		if _, err := ReadVerified(bytes.NewReader(swapped), chainID, keys); !errors.Is(err, ErrAnchorOrder) {
			t.Fatalf("got %v, want ErrAnchorOrder", err)
		}
	})
	t.Run("wrong chain", func(t *testing.T) {
		if _, err := ReadVerified(bytes.NewReader(data), "OTHER", keys); err == nil {
			t.Fatal("checkpoint for another chain accepted")
		}
	})
	t.Run("tampered line", func(t *testing.T) {
		bad := bytes.Clone(data)
		i := bytes.Index(bad, []byte(`"signature":"`)) + len(`"signature":"`) + 20
		if bad[i] == 'A' {
			bad[i] = 'B'
		} else {
			bad[i] = 'A'
		}
		if _, err := ReadVerified(bytes.NewReader(bad), chainID, keys); !errors.Is(err, receipt.ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})
	t.Run("untrusted key", func(t *testing.T) {
		none := func(string) (*composite.PublicKey, error) { return nil, errors.New("unknown") }
		if _, err := ReadVerified(bytes.NewReader(data), chainID, none); err == nil {
			t.Fatal("checkpoint with untrusted key accepted")
		}
	})
}
