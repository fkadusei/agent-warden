package chain

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const kid2 = "warden-2026-10-e2"

func testCA(t *testing.T) *identity.CA {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identity.NewCA("Warden Chain Test Root", k, base.Add(-time.Hour), base.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// keyEpoch issues a key-epoch certificate covering the timestamps ts() produces.
func keyEpoch(t *testing.T, ca *identity.CA, id string, pub *composite.PublicKey) []byte {
	t.Helper()
	der, err := ca.IssueKeyEpoch(id, pub, base.Add(-time.Minute), base.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func rot(i int, from, to, keyDigest string, certificate []byte) *receipt.Receipt {
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, TS: ts(i), Type: receipt.TypeKeyRotation,
		Rotation: &receipt.Rotation{
			From: from, To: to, Key: keyDigest,
			Certificate: base64.RawURLEncoding.EncodeToString(certificate),
			Reason:      "scheduled rotation",
		},
	}
}

// rotatedLog builds a four-receipt chain: a decision and its result signed by
// out under kid, the rotation receipt r (also signed by out, as a handover must
// be), then one more decision signed by in under inKid.
func rotatedLog(t *testing.T, out *composite.PrivateKey, r *receipt.Receipt, in *composite.PrivateKey, inKid string) [][]byte {
	t.Helper()
	crm := call("crm.lookup")
	a, err := NewAppender(out, kid, chainA)
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	appendTo := func(a *Appender, rs ...*receipt.Receipt) {
		t.Helper()
		for _, x := range rs {
			_, line, err := a.Append(x)
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, line)
		}
	}
	appendTo(a, dec(0, "t1", crm, receipt.Allow), res(1, "t1", crm, 0), r)

	b, err := ResumeAppender(in, inKid, chainA, a.State())
	if err != nil {
		t.Fatal(err)
	}
	appendTo(b, dec(3, "t1", call("tickets.update"), receipt.Allow))
	return lines
}

func trusting(t *testing.T, k *composite.PrivateKey, ca *identity.CA) *keys.Rotating {
	t.Helper()
	return keys.NewRotating(map[string]*composite.PublicKey{kid: k.Public()}, ca.Pool())
}

// A chain that hands its key over mid-log verifies from the original key alone.
func TestVerifyFollowsARotation(t *testing.T) {
	ca := testCA(t)
	k1, k2 := newKey(t), newKey(t)
	cert := keyEpoch(t, ca, kid2, k2.Public())
	lines := rotatedLog(t, k1, rot(2, kid, kid2, digest.SHA256(k2.Public().Bytes()), cert), k2, kid2)

	rep, err := VerifyWithKeys(bytes.NewReader(join(lines)), chainA, trusting(t, k1, ca), nil)
	if err != nil {
		t.Fatalf("a valid rotated log failed to verify: %v", err)
	}
	if rep.Receipts != 4 || rep.LastSeq != 3 {
		t.Fatalf("got %d receipts ending at seq %d, want 4 ending at 3", rep.Receipts, rep.LastSeq)
	}
	if len(rep.Rotations) != 1 {
		t.Fatalf("Rotations = %+v, want one handover", rep.Rotations)
	}
	h := rep.Rotations[0]
	if h.Seq != 2 || h.From != kid || h.To != kid2 || h.Reason != "scheduled rotation" {
		t.Fatalf("handover recorded as %+v", h)
	}
	// The decision after the rotation is still an open decision: rotating a key
	// changes nothing about what the log says happened.
	if len(rep.OpenDecisions) != 1 || rep.OpenDecisions[0] != 3 {
		t.Fatalf("OpenDecisions = %v, want [3]", rep.OpenDecisions)
	}
}

// Verify has no roots, so it cannot judge an incoming key. It must refuse the
// log rather than trust a key nothing vouched for.
func TestVerifyWithoutRootsRefusesARotation(t *testing.T) {
	ca := testCA(t)
	k1, k2 := newKey(t), newKey(t)
	cert := keyEpoch(t, ca, kid2, k2.Public())
	lines := rotatedLog(t, k1, rot(2, kid, kid2, digest.SHA256(k2.Public().Bytes()), cert), k2, kid2)

	// Even handed both keys directly: a rotation needs the CA, not a wider trust file.
	both := resolver(map[string]*composite.PublicKey{kid: k1.Public(), kid2: k2.Public()})
	_, err := Verify(bytes.NewReader(join(lines)), chainA, both)
	var f *Failure
	if !errors.As(err, &f) || f.Reason != ReasonUncertifiedKey {
		t.Fatalf("got %v, want uncertified_key", err)
	}
	if f.Line != 3 {
		t.Fatalf("failed at line %d, want the rotation at line 3", f.Line)
	}
}

func TestVerifyDetectsBadRotations(t *testing.T) {
	ca := testCA(t)
	k1, k2 := newKey(t), newKey(t)
	goodCert := keyEpoch(t, ca, kid2, k2.Public())
	goodDigest := digest.SHA256(k2.Public().Bytes())

	cases := []struct {
		name   string
		log    func(t *testing.T) [][]byte
		line   int
		reason Reason
	}{
		{"handover attributed to a key that did not sign it", func(t *testing.T) [][]byte {
			// k1 signs, but the body claims the handover comes from kid2.
			return rotatedLog(t, k1, rot(2, kid2, kid, digest.SHA256(k1.Public().Bytes()),
				keyEpoch(t, ca, kid, k1.Public())), k1, kid)
		}, 3, ReasonBadRotation},
		{"incoming key certified by another CA", func(t *testing.T) [][]byte {
			return rotatedLog(t, k1, rot(2, kid, kid2, goodDigest,
				keyEpoch(t, testCA(t), kid2, k2.Public())), k2, kid2)
		}, 3, ReasonUncertifiedKey},
		{"certificate carries a key the rotation does not name", func(t *testing.T) [][]byte {
			other := newKey(t)
			return rotatedLog(t, k1, rot(2, kid, kid2, digest.SHA256(other.Public().Bytes()), goodCert), k2, kid2)
		}, 3, ReasonUncertifiedKey},
		{"certificate is for a different kid", func(t *testing.T) [][]byte {
			return rotatedLog(t, k1, rot(2, kid, kid2, goodDigest,
				keyEpoch(t, ca, "warden-2026-11-e3", k2.Public())), k2, kid2)
		}, 3, ReasonUncertifiedKey},
		{"the retired key signs on after handing over", func(t *testing.T) [][]byte {
			return rotatedLog(t, k1, rot(2, kid, kid2, goodDigest, goodCert), k1, kid)
		}, 4, ReasonWrongKey},
		{"the incoming key signs before the handover", func(t *testing.T) [][]byte {
			crm := call("crm.lookup")
			a, err := NewAppender(k1, kid, chainA)
			if err != nil {
				t.Fatal(err)
			}
			_, first, err := a.Append(dec(0, "t1", crm, receipt.Allow))
			if err != nil {
				t.Fatal(err)
			}
			b, err := ResumeAppender(k2, kid2, chainA, a.State())
			if err != nil {
				t.Fatal(err)
			}
			_, second, err := b.Append(res(1, "t1", crm, 0))
			if err != nil {
				t.Fatal(err)
			}
			return [][]byte{first, second}
		}, 2, ReasonWrongKey},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := c.log(t)
			k := keys.NewRotating(map[string]*composite.PublicKey{
				kid: k1.Public(), kid2: k2.Public(),
			}, ca.Pool())
			_, err := VerifyWithKeys(bytes.NewReader(join(lines)), chainA, k, nil)
			var f *Failure
			if !errors.As(err, &f) {
				t.Fatalf("got %v, want *Failure", err)
			}
			if f.Reason != c.reason || f.Line != c.line {
				t.Fatalf("got line %d %s (%s), want line %d %s", f.Line, f.Reason, f.Detail, c.line, c.reason)
			}
		})
	}
}

// A chain that never rotates verifies exactly as it did before rotation existed.
func TestUnrotatedLogIsUnaffected(t *testing.T) {
	ca := testCA(t)
	k := newKey(t)
	lines := build(t, k, chainA, scenario(0))
	log := join(lines)

	plain, err := Verify(bytes.NewReader(log), chainA, resolver(map[string]*composite.PublicKey{kid: k.Public()}))
	if err != nil {
		t.Fatal(err)
	}
	rotating, err := VerifyWithKeys(bytes.NewReader(log), chainA, trusting(t, k, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Head != rotating.Head || plain.Receipts != rotating.Receipts {
		t.Fatalf("the two verifiers disagree:\n%+v\n%+v", plain, rotating)
	}
	if len(plain.Rotations) != 0 || len(rotating.Rotations) != 0 {
		t.Fatal("a log with no rotation receipts reported a handover")
	}
}
