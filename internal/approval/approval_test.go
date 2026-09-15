package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const chainID = "01J9Z3CHAIN"

var now = time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

func at(d time.Duration) string { return now.Add(d).Format(receipt.TimeFormat) }

func newKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fixture struct {
	bob, carol *composite.PrivateKey
	keys       KeyResolver
	decision   *receipt.Receipt
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{bob: newKey(t), carol: newKey(t)}
	f.keys = func(kid string) (*composite.PublicKey, error) {
		switch kid {
		case "bob@tenant-a":
			return f.bob.Public(), nil
		case "carol@tenant-a":
			return f.carol.Public(), nil
		}
		return nil, errors.New("unknown approver")
	}
	f.decision = &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, ChainID: chainID, Seq: 6,
		Prev: digest.SHA256([]byte("line 5")), TS: at(-time.Minute), Type: receipt.TypeDecision,
		TaskID: "t1",
		Actor:  &receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		Call: &receipt.Call{Tool: "payments/refund", Manifest: digest.SHA256([]byte("refund")),
			ArgsCommitment: digest.SHA256([]byte(`{"amount":500}`))},
		Decision: &receipt.Decision{Result: receipt.RequireApproval, PolicyRevision: digest.SHA256([]byte("p1")),
			Rule: "refunds_need_approval"},
	}
	if err := f.decision.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) statement(t *testing.T) *Statement {
	t.Helper()
	cd, err := CallDigest(f.decision.TaskID, *f.decision.Actor, *f.decision.Call)
	if err != nil {
		t.Fatal(err)
	}
	return &Statement{
		Domain: StatementDomain, ChainID: chainID, DecisionSeq: 6, CallDigest: cd,
		Outcome: receipt.Approved, Approver: "bob@tenant-a",
		TS: at(-10 * time.Second), ExpiresTS: at(30 * time.Minute),
	}
}

func sign(t *testing.T, k *composite.PrivateKey, s *Statement) *receipt.Signed {
	t.Helper()
	signed, err := Sign(k, s)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestAccept(t *testing.T) {
	f := newFixture(t)
	for _, outcome := range []receipt.ApprovalOutcome{receipt.Approved, receipt.Rejected} {
		t.Run(string(outcome), func(t *testing.T) {
			st := f.statement(t)
			st.Outcome = outcome
			signed := sign(t, f.bob, st)
			acc, err := Accept(signed, f.decision, f.keys, now, DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			a := acc.Receipt.Approval
			if a.DecisionSeq != 6 || a.Outcome != outcome || a.Approver != "bob@tenant-a" || a.ExpiresTS != st.ExpiresTS {
				t.Fatalf("unexpected approval %+v", a)
			}
			line, _ := signed.Line()
			if a.Statement != digest.SHA256(line) || acc.StatementDigest != a.Statement || string(acc.StatementLine) != string(line) {
				t.Fatal("receipt does not commit to the signed statement")
			}
			// Once the chain fields are filled in, the receipt is valid.
			r := *acc.Receipt
			r.ChainID, r.Seq, r.Prev = chainID, 7, digest.SHA256([]byte("line 6"))
			if err := r.Validate(); err != nil {
				t.Fatalf("approval receipt invalid: %v", err)
			}
			if r.TS != now.Format(receipt.TimeFormat) {
				t.Fatalf("receipt ts %s, want Warden's clock", r.TS)
			}
		})
	}
}

func TestAcceptRejects(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name  string
		build func(t *testing.T) (*receipt.Signed, *receipt.Receipt)
		want  error
	}{
		{"decision does not require approval", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			d := *f.decision
			dd := *d.Decision
			dd.Result = receipt.Allow
			d.Decision = &dd
			return sign(t, f.bob, f.statement(t)), &d
		}, ErrNotPending},
		{"approver key not trusted", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.Approver = "mallory@tenant-a"
			return sign(t, newKey(t), st), f.decision
		}, ErrStatement},
		{"signed with another approver's key", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			return sign(t, f.carol, f.statement(t)), f.decision // kid says bob, key is carol's
		}, ErrStatement},
		{"self-approval", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.Approver = "alice@tenant-a"
			alice := newKey(t)
			keys := f.keys
			f.keys = func(kid string) (*composite.PublicKey, error) {
				if kid == "alice@tenant-a" {
					return alice.Public(), nil
				}
				return keys(kid)
			}
			return sign(t, alice, st), f.decision
		}, ErrSelfApproval},
		{"different call shown to the approver", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			c := *f.decision.Call
			c.ArgsCommitment = digest.SHA256([]byte(`{"amount":50}`))
			st.CallDigest, _ = CallDigest(f.decision.TaskID, *f.decision.Actor, c)
			return sign(t, f.bob, st), f.decision
		}, ErrMismatch},
		{"different decision seq", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.DecisionSeq = 5
			return sign(t, f.bob, st), f.decision
		}, ErrMismatch},
		{"different chain", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.ChainID = "OTHER"
			return sign(t, f.bob, st), f.decision
		}, ErrMismatch},
		{"already expired", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.TS, st.ExpiresTS = at(-2*time.Hour), at(-time.Hour)
			return sign(t, f.bob, st), f.decision
		}, ErrExpired},
		{"expiry longer than allowed", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.ExpiresTS = at(3 * time.Hour)
			return sign(t, f.bob, st), f.decision
		}, ErrExpired},
		{"statement from the future", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			st := f.statement(t)
			st.TS, st.ExpiresTS = at(10*time.Minute), at(20*time.Minute)
			return sign(t, f.bob, st), f.decision
		}, ErrStatement},
		{"signature tampered", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			signed := sign(t, f.bob, f.statement(t))
			other := sign(t, f.bob, func() *Statement { s := f.statement(t); s.Outcome = receipt.Rejected; return s }())
			signed.Payload = other.Payload
			return signed, f.decision
		}, ErrStatement},
		{"a receipt passed off as a statement", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			s, err := receipt.Sign(f.bob, "bob@tenant-a", f.decision)
			if err != nil {
				t.Fatal(err)
			}
			return s, f.decision
		}, ErrStatement},
		{"a checkpoint passed off as a statement", func(t *testing.T) (*receipt.Signed, *receipt.Receipt) {
			b := checkpoint.NewBuilder(chainID)
			b.Add([]byte("x"))
			c, err := b.Checkpoint(at(0))
			if err != nil {
				t.Fatal(err)
			}
			s, err := checkpoint.Sign(f.bob, "bob@tenant-a", c)
			if err != nil {
				t.Fatal(err)
			}
			return s, f.decision
		}, ErrStatement},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			saved := f.keys
			defer func() { f.keys = saved }()
			signed, decision := c.build(t)
			if _, err := Accept(signed, decision, f.keys, now, DefaultLimits); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestStatementValidate(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(s *Statement){
		"wrong domain":          func(s *Statement) { s.Domain = "agent-warden/receipt/v1" },
		"empty chain":           func(s *Statement) { s.ChainID = "" },
		"negative seq":          func(s *Statement) { s.DecisionSeq = -1 },
		"bad call digest":       func(s *Statement) { s.CallDigest = "sha256:x" },
		"unknown outcome":       func(s *Statement) { s.Outcome = "maybe" },
		"empty approver":        func(s *Statement) { s.Approver = "" },
		"expiry before ts":      func(s *Statement) { s.ExpiresTS = s.TS },
		"ts without millis":     func(s *Statement) { s.TS = strings.Replace(s.TS, ".000Z", "Z", 1) },
		"expiry wrong spelling": func(s *Statement) { s.ExpiresTS = strings.Replace(s.ExpiresTS, "Z", "+00:00", 1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := f.statement(t)
			mutate(s)
			if err := s.Validate(); !errors.Is(err, ErrStatement) {
				t.Fatalf("got %v, want ErrStatement", err)
			}
			if _, err := Sign(f.bob, s); err == nil {
				t.Fatal("invalid statement was signed")
			}
		})
	}
}

func TestCallDigestBindsEveryField(t *testing.T) {
	f := newFixture(t)
	base, err := CallDigest(f.decision.TaskID, *f.decision.Actor, *f.decision.Call)
	if err != nil {
		t.Fatal(err)
	}
	actor, call := *f.decision.Actor, *f.decision.Call
	variants := map[string]func() (string, receipt.Actor, receipt.Call){
		"task":      func() (string, receipt.Actor, receipt.Call) { return "t2", actor, call },
		"agent":     func() (string, receipt.Actor, receipt.Call) { a := actor; a.Agent = "x"; return "t1", a, call },
		"principal": func() (string, receipt.Actor, receipt.Call) { a := actor; a.Principal = "x"; return "t1", a, call },
		"tool":      func() (string, receipt.Actor, receipt.Call) { c := call; c.Tool = "x"; return "t1", actor, c },
		"manifest": func() (string, receipt.Actor, receipt.Call) {
			c := call
			c.Manifest = digest.SHA256(nil)
			return "t1", actor, c
		},
	}
	for name, v := range variants {
		task, a, c := v()
		d, err := CallDigest(task, a, c)
		if err != nil {
			t.Fatal(err)
		}
		if d == base {
			t.Errorf("changing %s did not change the call digest", name)
		}
	}
}
