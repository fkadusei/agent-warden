package chain

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	chainA = "01J9Z3CHAINA"
	chainB = "01J9Z3CHAINB"
	kid    = "warden-2026-09-e1"
)

var base = time.Date(2026, 9, 14, 15, 4, 5, 0, time.UTC)

func ts(i int) string {
	return base.Add(time.Duration(i) * time.Millisecond).Format(receipt.TimeFormat)
}

func newKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func resolver(keys map[string]*composite.PublicKey) KeyResolver {
	return func(id string) (*composite.PublicKey, error) {
		if k, ok := keys[id]; ok {
			return k, nil
		}
		return nil, errors.New("unknown")
	}
}

func call(tool string) *receipt.Call {
	return &receipt.Call{
		Tool:           tool,
		Manifest:       digest.SHA256([]byte("manifest:" + tool)),
		ArgsCommitment: digest.SHA256([]byte("args:" + tool)),
	}
}

func dec(i int, task string, c *receipt.Call, result receipt.DecisionResult) *receipt.Receipt {
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, TS: ts(i), Type: receipt.TypeDecision,
		TaskID: task,
		Actor:  &receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		Call:   c,
		Decision: &receipt.Decision{
			Result:         result,
			PolicyRevision: digest.SHA256([]byte("policy-v1")),
		},
	}
}

func res(i int, task string, c *receipt.Call, decisionSeq int64) *receipt.Receipt {
	r := dec(i, task, c, receipt.Allow)
	r.Type, r.Decision = receipt.TypeResult, nil
	r.Result = &receipt.Result{
		DecisionSeq:      decisionSeq,
		Status:           receipt.StatusOK,
		ResultCommitment: digest.SHA256([]byte(fmt.Sprintf("result:%d", i))),
	}
	return r
}

// scenario is a small, valid log:
//
//	0 decision allow   crm.lookup      1 result for 0
//	2 decision allow   payments.refund 3 result for 2
//	4 decision deny    email.send
//	5 decision allow   tickets.update  (no result yet: open)
func scenario(i int) []*receipt.Receipt {
	crm, pay, mail, tix := call("crm.lookup"), call("payments.refund"), call("email.send"), call("tickets.update")
	return []*receipt.Receipt{
		dec(i+0, "t1", crm, receipt.Allow),
		res(i+1, "t1", crm, 0),
		dec(i+2, "t1", pay, receipt.Allow),
		res(i+3, "t1", pay, 2),
		dec(i+4, "t1", mail, receipt.Deny),
		dec(i+5, "t1", tix, receipt.Allow),
	}
}

func build(t *testing.T, k *composite.PrivateKey, chainID string, rs []*receipt.Receipt) [][]byte {
	t.Helper()
	a, err := NewAppender(k, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, r := range rs {
		_, line, err := a.Append(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	return lines
}

func join(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// forge signs r exactly as given, bypassing the Appender's bookkeeping.
func forge(t *testing.T, k *composite.PrivateKey, keyID string, r *receipt.Receipt) []byte {
	t.Helper()
	s, err := receipt.Sign(k, keyID, r)
	if err != nil {
		t.Fatal(err)
	}
	line, err := s.Line()
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// at returns a receipt placed at seq with the correct prev for lines, so only
// the property under test is wrong.
func at(r *receipt.Receipt, chainID string, seq int, lines [][]byte) *receipt.Receipt {
	r.ChainID, r.Seq = chainID, int64(seq)
	r.Prev = digest.SHA256(lines[seq-1])
	return r
}

func TestAppenderLinksReceipts(t *testing.T) {
	k := newKey(t)
	lines := build(t, k, chainA, scenario(0))
	genesis, err := NewParams(chainA, kid, k.Public()).GenesisPrev()
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range lines {
		s, err := receipt.ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		r, err := receipt.Verify(k.Public(), s)
		if err != nil {
			t.Fatal(err)
		}
		wantPrev := genesis
		if i > 0 {
			wantPrev = digest.SHA256(lines[i-1])
		}
		if r.Seq != int64(i) || r.Prev != wantPrev || r.ChainID != chainA {
			t.Fatalf("receipt %d: seq=%d chain=%s prev ok=%v", i, r.Seq, r.ChainID, r.Prev == wantPrev)
		}
	}
}

func TestAppenderRefusesTimeRegression(t *testing.T) {
	a, err := NewAppender(newKey(t), kid, chainA)
	if err != nil {
		t.Fatal(err)
	}
	c := call("crm.lookup")
	if _, _, err := a.Append(dec(5, "t1", c, receipt.Allow)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Append(dec(4, "t1", c, receipt.Allow)); !errors.Is(err, ErrTimeRegression) {
		t.Fatalf("got %v, want ErrTimeRegression", err)
	}
	if a.Next() != 1 {
		t.Fatalf("failed append advanced the chain to %d", a.Next())
	}
}

func TestVerifyValidLog(t *testing.T) {
	k := newKey(t)
	lines := build(t, k, chainA, scenario(0))
	rep, err := Verify(bytes.NewReader(join(lines)), chainA, resolver(map[string]*composite.PublicKey{kid: k.Public()}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Receipts != 6 || rep.LastSeq != 5 || rep.Head != digest.SHA256(lines[5]) {
		t.Fatalf("unexpected report %+v", rep)
	}
	if len(rep.OpenDecisions) != 1 || rep.OpenDecisions[0] != 5 {
		t.Fatalf("open decisions %v, want [5]", rep.OpenDecisions)
	}

	// No trailing newline is also accepted.
	if _, err := Verify(bytes.NewReader(bytes.TrimSuffix(join(lines), []byte("\n"))), chainA,
		resolver(map[string]*composite.PublicKey{kid: k.Public()})); err != nil {
		t.Fatalf("log without trailing newline rejected: %v", err)
	}
}

func TestVerifyDetects(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	keys := resolver(map[string]*composite.PublicKey{kid: k.Public(), "other-kid": other.Public()})
	crm := call("crm.lookup")
	mail := call("email.send")

	type tc struct {
		name   string
		log    func(lines [][]byte) [][]byte
		line   int
		reason Reason
	}
	cases := []tc{
		{"flipped signature character", func(l [][]byte) [][]byte {
			b := bytes.Clone(l[2])
			i := bytes.Index(b, []byte(`"signature":"`)) + len(`"signature":"`) + 20
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			l[2] = b
			return l
		}, 3, ReasonBadSignature},
		{"payload swapped from another line", func(l [][]byte) [][]byte {
			a, _ := receipt.ParseLine(l[2])
			b, _ := receipt.ParseLine(l[3])
			a.Payload = b.Payload
			l[2], _ = a.Line()
			return l
		}, 3, ReasonBadSignature},
		{"deleted receipt", func(l [][]byte) [][]byte {
			return append(l[:2:2], l[3:]...)
		}, 3, ReasonSeqGap},
		{"duplicated receipt", func(l [][]byte) [][]byte {
			return append(l[:3:3], l[2:]...)
		}, 4, ReasonSeqGap},
		{"swapped receipts", func(l [][]byte) [][]byte {
			l[1], l[2] = l[2], l[1]
			return l
		}, 2, ReasonSeqGap},
		{"blank line", func(l [][]byte) [][]byte {
			return append(l[:2:2], append([][]byte{{}}, l[2:]...)...)
		}, 3, ReasonMalformed},
		{"receipt from another chain", func(l [][]byte) [][]byte {
			l[2] = build(t, k, chainB, scenario(0))[2]
			return l
		}, 3, ReasonWrongChain},
		{"re-signed by an untrusted key", func(l [][]byte) [][]byte {
			l[2] = forge(t, newKey(t), kid, at(dec(2, "t1", crm, receipt.Allow), chainA, 2, l))
			return l
		}, 3, ReasonBadSignature},
		{"unknown key ID", func(l [][]byte) [][]byte {
			l[2] = forge(t, k, "nobody", at(dec(2, "t1", crm, receipt.Allow), chainA, 2, l))
			return l
		}, 3, ReasonUnknownKey},
		{"forged prev", func(l [][]byte) [][]byte {
			r := at(dec(2, "t1", crm, receipt.Allow), chainA, 2, l)
			r.Prev = digest.SHA256([]byte("elsewhere"))
			l[2] = forge(t, k, kid, r)
			return l[:3]
		}, 3, ReasonChainBreak},
		{"wrong genesis", func(l [][]byte) [][]byte {
			r := dec(0, "t1", crm, receipt.Allow)
			r.ChainID, r.Seq, r.Prev = chainA, 0, digest.SHA256([]byte("not the genesis"))
			return [][]byte{forge(t, k, kid, r)}
		}, 1, ReasonChainBreak},
		{"genesis bound to a different key", func(l [][]byte) [][]byte {
			// Validly signed by another trusted key, but carrying the genesis
			// prev of a chain started by k. The genesis binds the signing key.
			r := dec(0, "t1", crm, receipt.Allow)
			prev, err := NewParams(chainA, kid, k.Public()).GenesisPrev()
			if err != nil {
				t.Fatal(err)
			}
			r.ChainID, r.Seq, r.Prev = chainA, 0, prev
			return [][]byte{forge(t, other, "other-kid", r)}
		}, 1, ReasonChainBreak},
		{"time regression", func(l [][]byte) [][]byte {
			l[2] = forge(t, k, kid, at(dec(0, "t1", crm, receipt.Allow), chainA, 2, l))
			return l[:3]
		}, 3, ReasonTimeRegression},
		{"result for a denied call", func(l [][]byte) [][]byte {
			l = l[:6]
			return append(l, forge(t, k, kid, at(res(9, "t1", mail, 4), chainA, 6, l)))
		}, 7, ReasonDeniedCallExecuted},
		{"result for a call that required approval", func(l [][]byte) [][]byte {
			l = l[:6]
			pay := call("payments.refund")
			l = append(l, forge(t, k, kid, at(dec(9, "t1", pay, receipt.RequireApproval), chainA, 6, l)))
			return append(l, forge(t, k, kid, at(res(10, "t1", pay, 6), chainA, 7, l)))
		}, 8, ReasonMissingApproval},
		{"duplicate result", func(l [][]byte) [][]byte {
			l = l[:6]
			return append(l, forge(t, k, kid, at(res(9, "t1", crm, 0), chainA, 6, l)))
		}, 7, ReasonDuplicateResult},
		{"result referencing a result", func(l [][]byte) [][]byte {
			l = l[:6]
			return append(l, forge(t, k, kid, at(res(9, "t1", crm, 1), chainA, 6, l)))
		}, 7, ReasonBadReference},
		{"result for a different call", func(l [][]byte) [][]byte {
			l = l[:6]
			return append(l, forge(t, k, kid, at(res(9, "t1", call("tickets.delete"), 5), chainA, 6, l)))
		}, 7, ReasonBadReference},
		{"result for a different task", func(l [][]byte) [][]byte {
			l = l[:6]
			return append(l, forge(t, k, kid, at(res(9, "t2", call("tickets.update"), 5), chainA, 6, l)))
		}, 7, ReasonBadReference},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := c.log(build(t, k, chainA, scenario(0)))
			_, err := Verify(bytes.NewReader(join(lines)), chainA, keys)
			var f *Failure
			if !errors.As(err, &f) {
				t.Fatalf("got %v, want *Failure", err)
			}
			if f.Reason != c.reason || f.Line != c.line {
				t.Fatalf("got line %d %s (%s), want line %d %s", f.Line, f.Reason, f.Detail, c.line, c.reason)
			}
		})
	}

	t.Run("empty log", func(t *testing.T) {
		_, err := Verify(strings.NewReader(""), chainA, keys)
		var f *Failure
		if !errors.As(err, &f) || f.Reason != ReasonEmptyLog {
			t.Fatalf("got %v, want empty_log", err)
		}
	})
}

// These tests pin down what a hash chain alone cannot detect (threat W10).
// Signed checkpoints anchored outside Warden are what close these gaps.
func TestChainAloneDoesNotDetect(t *testing.T) {
	k := newKey(t)
	keys := resolver(map[string]*composite.PublicKey{kid: k.Public()})

	t.Run("truncation of the newest receipts", func(t *testing.T) {
		lines := build(t, k, chainA, scenario(0))
		rep, err := Verify(bytes.NewReader(join(lines[:4])), chainA, keys)
		if err != nil {
			t.Fatalf("truncated log should still verify without a checkpoint: %v", err)
		}
		if rep.LastSeq != 3 {
			t.Fatalf("LastSeq %d, want 3", rep.LastSeq)
		}
	})

	t.Run("full rewrite by the key holder", func(t *testing.T) {
		rs := scenario(0)
		rs[4].Decision.Result = receipt.Allow // the denied email now looks allowed
		if _, err := Verify(bytes.NewReader(join(build(t, k, chainA, rs))), chainA, keys); err != nil {
			t.Fatalf("rewritten log should still verify without a checkpoint: %v", err)
		}
	})
}
