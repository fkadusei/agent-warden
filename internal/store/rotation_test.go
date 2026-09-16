package store

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const kid2 = "warden-2026-10-e2"

func rotCA(t *testing.T) *identity.CA {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identity.NewCA("Warden Store Test Root", k, base.Add(-time.Hour), base.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func epochFor(t *testing.T, ca *identity.CA, id string, pub *composite.PublicKey) []byte {
	t.Helper()
	der, err := ca.IssueKeyEpoch(id, pub, base.Add(-time.Minute), base.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// rotation is a well-formed handover from one kid to another at step i.
func rotation(i int, from, to string, incoming *composite.PrivateKey, cert []byte) *receipt.Receipt {
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS:   base.Add(time.Duration(i) * time.Millisecond).Format(receipt.TimeFormat),
		Type: receipt.TypeKeyRotation,
		Rotation: &receipt.Rotation{
			From: from, To: to,
			Key:         digest.SHA256(incoming.Public().Bytes()),
			Certificate: base64.RawURLEncoding.EncodeToString(cert),
			Reason:      "scheduled rotation",
		},
	}
}

func openAs(t *testing.T, path string, k *composite.PrivateKey, id string) (*Store, error) {
	t.Helper()
	return Open(path, k, id, chainID)
}

// rotated opens a store, writes two decisions, hands over to a fresh key, and
// returns the store, the incoming key and the CA that certified it.
func rotated(t *testing.T, path string) (*Store, *composite.PrivateKey, *composite.PrivateKey, *identity.CA) {
	t.Helper()
	ctx := context.Background()
	ca := rotCA(t)
	k1, k2 := newKey(t), newKey(t)
	s := open(t, path, k1)
	for i := range 2 {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}
	r := rotation(2, kid, kid2, k2, epochFor(t, ca, kid2, k2.Public()))
	if _, err := s.Rotate(ctx, r, k2); err != nil {
		t.Fatalf("rotation refused: %v", err)
	}
	return s, k1, k2, ca
}

func trusting(t *testing.T, k *composite.PrivateKey, ca *identity.CA) *keys.Rotating {
	t.Helper()
	return keys.NewRotating(map[string]*composite.PublicKey{kid: k.Public()}, ca.Pool())
}

func TestRotateSwitchesKeys(t *testing.T) {
	ctx := context.Background()
	s, k1, _, ca := rotated(t, filepath.Join(t.TempDir(), "receipts.db"))
	defer s.Close()

	if s.Kid() != kid2 {
		t.Fatalf("still signing with %q after the handover", s.Kid())
	}
	if s.Next() != 3 {
		t.Fatalf("next seq %d, want 3", s.Next())
	}
	// This one is signed by the incoming key.
	if _, err := s.Append(ctx, dec(3)); err != nil {
		t.Fatal(err)
	}

	rep, err := s.VerifyWithKeys(ctx, trusting(t, k1, ca))
	if err != nil {
		t.Fatalf("the rotated log does not verify: %v", err)
	}
	if rep.Receipts != 4 || rep.LastSeq != 3 {
		t.Fatalf("unexpected report %+v", rep)
	}
	if len(rep.Rotations) != 1 || rep.Rotations[0].From != kid || rep.Rotations[0].To != kid2 {
		t.Fatalf("handovers recorded as %+v", rep.Rotations)
	}

	// The old trust file alone is no longer enough, and must fail rather than
	// quietly accept the receipts the new key signed.
	_, err = s.Verify(ctx, keysFor(k1))
	var f *chain.Failure
	if !errors.As(err, &f) || f.Reason != chain.ReasonUncertifiedKey {
		t.Fatalf("got %v, want uncertified_key", err)
	}
}

func TestRotatedLogReopensWithTheIncomingKey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "receipts.db")
	s, k1, k2, ca := rotated(t, path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := openAs(t, path, k1, kid); !errors.Is(err, ErrMismatch) {
		t.Fatalf("reopening with the retired key: got %v, want ErrMismatch", err)
	}

	s2, err := openAs(t, path, k2, kid2)
	if err != nil {
		t.Fatalf("reopening with the current key: %v", err)
	}
	defer s2.Close()
	if s2.Next() != 3 || s2.Kid() != kid2 {
		t.Fatalf("resumed at seq %d under %q, want 3 under %q", s2.Next(), s2.Kid(), kid2)
	}
	if _, err := s2.Append(ctx, dec(3)); err != nil {
		t.Fatal(err)
	}
	rep, err := s2.VerifyWithKeys(ctx, trusting(t, k1, ca))
	if err != nil || rep.Receipts != 4 {
		t.Fatalf("log across the restart: %+v, %v", rep, err)
	}
}

func TestRotateRefuses(t *testing.T) {
	ctx := context.Background()
	ca := rotCA(t)

	cases := map[string]func(t *testing.T, k2 *composite.PrivateKey, cert []byte) (*receipt.Receipt, *composite.PrivateKey){
		"not a rotation receipt": func(t *testing.T, k2 *composite.PrivateKey, cert []byte) (*receipt.Receipt, *composite.PrivateKey) {
			return dec(2), k2
		},
		"handing over from a key this log does not use": func(t *testing.T, k2 *composite.PrivateKey, cert []byte) (*receipt.Receipt, *composite.PrivateKey) {
			return rotation(2, "someone-elses-kid", kid2, k2, cert), k2
		},
		"the incoming key is not the one the rotation names": func(t *testing.T, k2 *composite.PrivateKey, cert []byte) (*receipt.Receipt, *composite.PrivateKey) {
			return rotation(2, kid, kid2, k2, cert), newKey(t)
		},
		"no incoming key at all": func(t *testing.T, k2 *composite.PrivateKey, cert []byte) (*receipt.Receipt, *composite.PrivateKey) {
			return rotation(2, kid, kid2, k2, cert), nil
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			k1, k2 := newKey(t), newKey(t)
			s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k1)
			defer s.Close()
			for i := range 2 {
				if _, err := s.Append(ctx, dec(i)); err != nil {
					t.Fatal(err)
				}
			}
			r, incoming := build(t, k2, epochFor(t, ca, kid2, k2.Public()))
			if _, err := s.Rotate(ctx, r, incoming); err == nil {
				t.Fatal("the rotation was accepted")
			}
			if s.Kid() != kid {
				t.Fatalf("a refused rotation changed the signing key to %q", s.Kid())
			}
			if s.Next() != 2 {
				t.Fatalf("a refused rotation advanced the chain to %d", s.Next())
			}
			// The log is untouched and still verifies under the original key.
			if rep, err := s.Verify(ctx, keysFor(k1)); err != nil || rep.Receipts != 2 {
				t.Fatalf("log after the refused rotation: %+v, %v", rep, err)
			}
		})
	}
}

// A rotation must not sneak in through Append, which would write the receipt
// without switching the key the store signs with.
func TestAppendRefusesARotation(t *testing.T) {
	ctx := context.Background()
	ca := rotCA(t)
	k1, k2 := newKey(t), newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k1)
	defer s.Close()

	r := rotation(0, kid, kid2, k2, epochFor(t, ca, kid2, k2.Public()))
	if _, err := s.Append(ctx, r); err == nil {
		t.Fatal("Append wrote a key_rotation receipt")
	}
	if s.Next() != 0 {
		t.Fatalf("the refused rotation advanced the chain to %d", s.Next())
	}
}

// The handover is atomic: if the write fails, the old key keeps signing.
func TestFailedRotateKeepsTheOutgoingKey(t *testing.T) {
	ctx := context.Background()
	ca := rotCA(t)
	k1, k2 := newKey(t), newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k1)
	defer s.Close()
	for i := range 2 {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.db.ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
		t.Fatal(err)
	}
	r := rotation(2, kid, kid2, k2, epochFor(t, ca, kid2, k2.Public()))
	if _, err := s.Rotate(ctx, r, k2); err == nil {
		t.Fatal("rotation succeeded on a read-only database")
	}
	if s.Kid() != kid || s.Next() != 2 {
		t.Fatalf("after the failed rotation: signing with %q at seq %d", s.Kid(), s.Next())
	}

	if _, err := s.db.ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
		t.Fatal(err)
	}
	// The outgoing key still signs, and the log is still whole.
	a, err := s.Append(ctx, dec(2))
	if err != nil {
		t.Fatal(err)
	}
	if a.Seq != 2 {
		t.Fatalf("seq %d after recovery, want 2", a.Seq)
	}
	if rep, err := s.Verify(ctx, keysFor(k1)); err != nil || rep.Receipts != 3 {
		t.Fatalf("log after the failed rotation: %+v, %v", rep, err)
	}

	// And the handover still works once the database is writable.
	if _, err := s.Rotate(ctx, rotation(3, kid, kid2, k2, epochFor(t, ca, kid2, k2.Public())), k2); err != nil {
		t.Fatal(err)
	}
	if s.Kid() != kid2 {
		t.Fatalf("signing with %q after a successful retry", s.Kid())
	}
	if _, err := s.VerifyWithKeys(ctx, trusting(t, k1, ca)); err != nil {
		t.Fatalf("log after the retried rotation: %v", err)
	}
}
