package identity

import (
	"bytes"
	"crypto/mldsa"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
)

// No certificate crashes the profile checks. A key-epoch certificate comes from a
// rotation receipt, and a task credential from a client connection: both are
// attacker-supplied bytes.
func FuzzVerifyCertificate(f *testing.F) {
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	rootKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{3}, mldsa.PrivateKeySize))
	if err != nil {
		f.Fatal(err)
	}
	ca, err := NewCA("Fuzz Root", rootKey, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		f.Fatal(err)
	}
	rk, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{7}, composite.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	epoch, err := ca.IssueKeyEpoch("warden-e1", rk.Public(), at.Add(-time.Minute), at.Add(time.Minute))
	if err != nil {
		f.Fatal(err)
	}
	ak, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{5}, mldsa.PrivateKeySize))
	if err != nil {
		f.Fatal(err)
	}
	task, err := ca.IssueTask(claims, ak.PublicKey(), at.Add(-time.Minute), at.Add(time.Minute))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(epoch)
	f.Add(task)
	f.Add(epoch[:len(epoch)/2])
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	roots := ca.Pool()
	f.Fuzz(func(t *testing.T, der []byte) {
		if e, err := VerifyKeyEpoch(der, roots, at); err == nil && (e.Kid == "" || e.Key == nil) {
			t.Fatalf("accepted a key-epoch certificate without a kid or key: %+v", e)
		}
		if tk, err := VerifyTask(der, roots, at); err == nil && tk == nil {
			t.Fatal("accepted a task credential and returned nothing")
		}
	})
}
