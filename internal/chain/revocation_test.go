package chain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
)

// A revoked key keeps everything it signed up to the checkpoint believed good,
// and nothing after it: you lose the tail, not the history (ADR-0016).
func TestRevokedKeyLosesTheTailNotTheHistory(t *testing.T) {
	k := newKey(t)
	lines := build(t, k, chainA, scenario(0))
	opts := func(revs ...Revoked) Options {
		return Options{
			Keys:        StaticKeys(resolver(map[string]*composite.PublicKey{kid: k.Public()})),
			Revocations: revs,
		}
	}
	revoked := Revoked{Kid: kid, EffectiveSize: 3}

	t.Run("the tail is refused", func(t *testing.T) {
		_, err := VerifyAll(bytes.NewReader(join(lines)), chainA, opts(revoked))
		var f *Failure
		if !errors.As(err, &f) {
			t.Fatalf("got %v, want *Failure", err)
		}
		if f.Reason != ReasonRevokedKey || f.Seq != 3 {
			t.Fatalf("got seq %d %s (%s), want seq 3 revoked_key", f.Seq, f.Reason, f.Detail)
		}
	})

	t.Run("the history still verifies", func(t *testing.T) {
		// A log that stops at the checkpoint believed good is untouched by the
		// revocation: those receipts were anchored before the key was lost.
		rep, err := VerifyAll(bytes.NewReader(join(lines[:3])), chainA, opts(revoked))
		if err != nil {
			t.Fatalf("the anchored history failed to verify: %v", err)
		}
		if rep.Receipts != 3 || rep.LastSeq != 2 {
			t.Fatalf("unexpected report %+v", rep)
		}
	})

	t.Run("a revocation of another key is harmless", func(t *testing.T) {
		if _, err := VerifyAll(bytes.NewReader(join(lines)), chainA,
			opts(Revoked{Kid: "someone-elses-kid", EffectiveSize: 1})); err != nil {
			t.Fatalf("an unrelated revocation broke the log: %v", err)
		}
	})

	t.Run("a revocation beyond the log is harmless", func(t *testing.T) {
		if _, err := VerifyAll(bytes.NewReader(join(lines)), chainA,
			opts(Revoked{Kid: kid, EffectiveSize: 999})); err != nil {
			t.Fatalf("a revocation past the end broke the log: %v", err)
		}
	})

	t.Run("no revocations verifies as before", func(t *testing.T) {
		if _, err := VerifyAll(bytes.NewReader(join(lines)), chainA, opts()); err != nil {
			t.Fatal(err)
		}
	})
}

// Rotation and revocation together: either side of a handover can be revoked.
func TestRevocationAcrossARotation(t *testing.T) {
	ca := testCA(t)
	k1, k2 := newKey(t), newKey(t)
	cert := keyEpoch(t, ca, kid2, k2.Public())
	lines := rotatedLog(t, k1, rot(2, kid, kid2, digest.SHA256(k2.Public().Bytes()), cert), k2, kid2)
	log := join(lines)

	cases := map[string]struct {
		revoked Revoked
		seq     int64
	}{
		// The retired key is revoked back to before it handed over.
		"the outgoing key, before the handover": {Revoked{Kid: kid, EffectiveSize: 1}, 1},
		// The incoming key is revoked from the first receipt it signed.
		"the incoming key, after the handover": {Revoked{Kid: kid2, EffectiveSize: 3}, 3},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyAll(bytes.NewReader(log), chainA, Options{
				Keys:        trusting(t, k1, ca),
				Revocations: []Revoked{c.revoked},
			})
			var f *Failure
			if !errors.As(err, &f) {
				t.Fatalf("got %v, want *Failure", err)
			}
			if f.Reason != ReasonRevokedKey || f.Seq != c.seq {
				t.Fatalf("got seq %d %s (%s), want seq %d revoked_key", f.Seq, f.Reason, f.Detail, c.seq)
			}
		})
	}

	// Revoking the outgoing key from the handover onward leaves the whole log
	// standing: it signed nothing after the rotation receipt.
	t.Run("the outgoing key, from the handover onward", func(t *testing.T) {
		if _, err := VerifyAll(bytes.NewReader(log), chainA, Options{
			Keys:        trusting(t, k1, ca),
			Revocations: []Revoked{{Kid: kid, EffectiveSize: 3}},
		}); err != nil {
			t.Fatalf("revoking the retired key broke the log it had already left: %v", err)
		}
	})
}
