package keys

import (
	"bytes"
	"crypto/mldsa"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/identity"
)

var rotAt = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func rotCA(t *testing.T) *identity.CA {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identity.NewCA("Warden Rotation Test Root", k, rotAt.Add(-time.Hour), rotAt.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func rotKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// epoch issues a key-epoch certificate valid around rotAt.
func epoch(t *testing.T, ca *identity.CA, kid string, pub *composite.PublicKey) []byte {
	t.Helper()
	der, err := ca.IssueKeyEpoch(kid, pub, rotAt.Add(-time.Minute), rotAt.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRotatingLearnsACertifiedKey(t *testing.T) {
	ca := rotCA(t)
	e1, e2 := rotKey(t), rotKey(t)
	r := NewRotating(map[string]*composite.PublicKey{"e1": e1.Public()}, ca.Pool())

	if _, err := r.Resolve("e2"); err == nil {
		t.Fatal("e2 resolved before any rotation introduced it")
	}
	if err := r.Accept("e2", digest.SHA256(e2.Public().Bytes()), epoch(t, ca, "e2", e2.Public()), rotAt); err != nil {
		t.Fatalf("a properly certified key was refused: %v", err)
	}
	got, err := r.Resolve("e2")
	if err != nil {
		t.Fatalf("e2 does not resolve after being accepted: %v", err)
	}
	if !bytes.Equal(got.Bytes(), e2.Public().Bytes()) {
		t.Fatal("e2 resolved to a different key than the certificate carried")
	}
	// The key from the trust file is still there: the chain's history stays verifiable.
	if _, err := r.Resolve("e1"); err != nil {
		t.Fatalf("the trusted key was lost: %v", err)
	}
	if learned := r.Learned(); len(learned) != 1 || learned[0] != "e2" {
		t.Fatalf("Learned() = %v, want [e2]", learned)
	}
}

// Replaying the same rotation is not an error; changing what it says is.
func TestRotatingAcceptIsIdempotent(t *testing.T) {
	ca := rotCA(t)
	e2 := rotKey(t)
	r := NewRotating(nil, ca.Pool())
	der, d := epoch(t, ca, "e2", e2.Public()), digest.SHA256(e2.Public().Bytes())
	for i := range 2 {
		if err := r.Accept("e2", d, der, rotAt); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}

	other := rotKey(t)
	err := r.Accept("e2", digest.SHA256(other.Public().Bytes()), epoch(t, ca, "e2", other.Public()), rotAt)
	if err == nil {
		t.Fatal("a second, different key was accepted under the kid e2")
	}
	if !strings.Contains(err.Error(), "already known") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotatingRefuses(t *testing.T) {
	ca := rotCA(t)
	e2 := rotKey(t)
	good := epoch(t, ca, "e2", e2.Public())
	goodDigest := digest.SHA256(e2.Public().Bytes())

	t.Run("without roots", func(t *testing.T) {
		r := NewRotating(nil, nil)
		if err := r.Accept("e2", goodDigest, good, rotAt); err == nil {
			t.Fatal("a key was introduced with no CA to vouch for it")
		}
	})

	cases := map[string]struct {
		kid         string
		keyDigest   string
		certificate []byte
		at          time.Time
	}{
		"certificate is for another kid": {"e3", goodDigest, good, rotAt},
		"digest names a different key":   {"e2", digest.SHA256([]byte("some other key")), good, rotAt},
		"not a certificate at all":       {"e2", goodDigest, []byte("not DER"), rotAt},
		"used before the epoch began":    {"e2", goodDigest, good, rotAt.Add(-time.Hour)},
		"used after the epoch ended":     {"e2", goodDigest, good, rotAt.Add(60 * 24 * time.Hour)},
		"issued by another CA": {"e2", goodDigest,
			epoch(t, rotCA(t), "e2", e2.Public()), rotAt},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := NewRotating(nil, ca.Pool())
			if err := r.Accept(c.kid, c.keyDigest, c.certificate, c.at); err == nil {
				t.Fatal("accepted")
			}
			if _, err := r.Resolve(c.kid); err == nil {
				t.Fatal("the refused key is resolvable anyway")
			}
			if len(r.Learned()) != 0 {
				t.Fatalf("a refused key was recorded as learned: %v", r.Learned())
			}
		})
	}
}
