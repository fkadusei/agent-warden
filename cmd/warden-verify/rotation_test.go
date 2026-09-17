package main

import (
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/revocation"
)

const kid2 = "warden-2026-10-e2"

var chainBase = time.Date(2026, 9, 14, 15, 4, 5, 0, time.UTC)

func chainTS(i int) string {
	return chainBase.Add(time.Duration(i) * time.Millisecond).Format(receipt.TimeFormat)
}

func genKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func decisionR(i int) *receipt.Receipt {
	tool := []string{"crm.lookup", "payments.refund", "email.send"}[i%3]
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS: chainTS(i), Type: receipt.TypeDecision, TaskID: "t1",
		Actor: &receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		Call: &receipt.Call{Tool: tool, Manifest: digest.SHA256([]byte(tool)),
			ArgsCommitment: digest.SHA256([]byte{byte(i)})},
		Decision: &receipt.Decision{Result: receipt.Deny, PolicyRevision: digest.SHA256([]byte("p1"))},
	}
}

// rotatedFixture is an auditor's view of a rotated chain: a trust file holding
// only the key the chain began with, the root that certified what came after,
// and an anchor whose checkpoint was signed by the key current at the time —
// which is the incoming one, known only from the log.
type rotatedFixture struct {
	fixture
	root, revocations string
	ca                *identity.CA
	k1, k2            *composite.PrivateKey
	cp                *checkpoint.Checkpoint
}

func newRotatedFixture(t *testing.T) rotatedFixture {
	t.Helper()
	f := rotatedFixture{fixture: fixture{dir: t.TempDir()}}
	f.log, f.anchor, f.keys = f.path("receipts.jsonl"), f.path("anchor.jsonl"), f.path("keys.json")
	f.root, f.revocations = f.path("ca.pem"), f.path("revocations.jsonl")

	caKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	f.ca, err = identity.NewCA("Warden Verify Test Root", caKey, chainBase.Add(-time.Hour), chainBase.AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.WriteCertificate(f.root, f.ca.Cert.Raw); err != nil {
		t.Fatal(err)
	}
	f.k1, f.k2 = genKey(t), genKey(t)
	epoch, err := f.ca.IssueKeyEpoch(kid2, f.k2.Public(), chainBase.Add(-time.Minute), chainBase.AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}

	add := func(a *chain.Appender, r *receipt.Receipt) {
		t.Helper()
		_, line, err := a.Append(r)
		if err != nil {
			t.Fatal(err)
		}
		f.lines = append(f.lines, line)
	}
	a, err := chain.NewAppender(f.k1, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	add(a, decisionR(0))
	add(a, decisionR(1))
	add(a, &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, TS: chainTS(2), Type: receipt.TypeKeyRotation,
		Rotation: &receipt.Rotation{From: kid, To: kid2,
			Key:         digest.SHA256(f.k2.Public().Bytes()),
			Certificate: base64.RawURLEncoding.EncodeToString(epoch),
			Reason:      "scheduled rotation"},
	})
	b, err := chain.ResumeAppender(f.k2, kid2, chainID, a.State())
	if err != nil {
		t.Fatal(err)
	}
	add(b, decisionR(3))
	add(b, decisionR(4))
	add(b, decisionR(5))
	write(t, f.log, f.lines)

	// The checkpoint covers the first 4 receipts and is signed by the key that
	// was current when it was made: the incoming one.
	bld := checkpoint.NewBuilder(chainID)
	for _, l := range f.lines[:4] {
		bld.Add(l)
	}
	f.cp, err = bld.Checkpoint(chainTS(100))
	if err != nil {
		t.Fatal(err)
	}
	s, err := checkpoint.Sign(f.k2, kid2, f.cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := (checkpoint.FileAnchor{Path: f.anchor}).Publish(s); err != nil {
		t.Fatal(err)
	}

	// The trust file holds one key: the one the chain began with.
	set, err := json.Marshal(keys.Set{Keys: []keys.JWK{keys.PublicJWK(kid, f.k1.Public())}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.keys, set, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f rotatedFixture) publish(t *testing.T, revokedKid string, size int64, head, reason string) {
	t.Helper()
	r := &revocation.Revocation{
		V: revocation.Version, Domain: revocation.Domain, ChainID: chainID,
		Kid: revokedKid, EffectiveSize: size, EffectiveHead: head, Reason: reason,
		TS: chainTS(200),
	}
	signed, err := revocation.Sign(f.ca.Key, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := revocation.Publish(f.revocations, signed); err != nil {
		t.Fatal(err)
	}
}

// One trusted key and the root verify a whole rotated chain, including an anchor
// signed by a key the trust file has never seen.
func TestRotatedLogVerifiesFromTheRoot(t *testing.T) {
	f := newRotatedFixture(t)
	code, out, errOut := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys,
		"--anchor", f.anchor, "--root", f.root)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"VERIFIED", "6 (seq 0-5)",
		"key rotation:   warden-2026-09-e1 to warden-2026-10-e2 at seq 2 (scheduled rotation)",
		"4 receipts (1 anchored checkpoints)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// Without the root there is nothing to judge the incoming key against, so the
// log must fail rather than trust a key nothing vouched for.
func TestRotatedLogWithoutRootFailsClosed(t *testing.T) {
	f := newRotatedFixture(t)
	code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys)
	if code != exitFailed || !strings.Contains(out, string(chain.ReasonUncertifiedKey)) {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestRevocationCostsTheTail(t *testing.T) {
	f := newRotatedFixture(t)
	f.publish(t, kid2, f.cp.Size, f.cp.Head, "signing key compromised")

	args := []string{"--log", f.log, "--chain", chainID, "--keys", f.keys,
		"--anchor", f.anchor, "--root", f.root, "--revocations", f.revocations}

	code, out, _ := runCLI(args...)
	if code != exitFailed {
		t.Fatalf("exit %d, want failure\n%s", code, out)
	}
	for _, want := range []string{"FAILED", "reason:         revoked_key", "seq:            4"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// A log that stops at the checkpoint believed good still verifies, and says
	// what was revoked.
	write(t, f.log, f.lines[:4])
	code, out, _ = runCLI(args...)
	if code != exitVerified {
		t.Fatalf("the anchored history failed: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "revoked:        warden-2026-10-e2, from seq 4 onward (signing key compromised)") {
		t.Errorf("the revocation is not reported:\n%s", out)
	}
}

func TestRevocationsAreChecked(t *testing.T) {
	t.Run("naming a checkpoint that is not anchored", func(t *testing.T) {
		f := newRotatedFixture(t)
		f.publish(t, kid2, 5, f.cp.Head, "")
		code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys,
			"--anchor", f.anchor, "--root", f.root, "--revocations", f.revocations)
		if code != exitFailed || !strings.Contains(out, "not anchored") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})

	t.Run("naming another history", func(t *testing.T) {
		f := newRotatedFixture(t)
		f.publish(t, kid2, f.cp.Size, digest.SHA256([]byte("some other log")), "")
		code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys,
			"--anchor", f.anchor, "--root", f.root, "--revocations", f.revocations)
		if code != exitFailed || !strings.Contains(out, "another history") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})

	t.Run("signed by something other than the root", func(t *testing.T) {
		f := newRotatedFixture(t)
		other, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		signed, err := revocation.Sign(other, &revocation.Revocation{
			V: revocation.Version, Domain: revocation.Domain, ChainID: chainID,
			Kid: kid2, EffectiveSize: f.cp.Size, EffectiveHead: f.cp.Head, TS: chainTS(200),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := revocation.Publish(f.revocations, signed); err != nil {
			t.Fatal(err)
		}
		code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys,
			"--anchor", f.anchor, "--root", f.root, "--revocations", f.revocations)
		if code != exitFailed || !strings.Contains(out, "revocation:") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}

func TestRotationInJSON(t *testing.T) {
	f := newRotatedFixture(t)
	f.publish(t, kid, 4, f.cp.Head, "retired early")
	code, out, _ := runCLI("--json", "--log", f.log, "--chain", chainID, "--keys", f.keys,
		"--anchor", f.anchor, "--root", f.root, "--revocations", f.revocations)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var r struct {
		Verified  bool `json:"verified"`
		Rotations []struct {
			Seq    int64  `json:"seq"`
			From   string `json:"from"`
			To     string `json:"to"`
			Reason string `json:"reason"`
		} `json:"rotations"`
		Revocations []struct {
			Kid  string `json:"kid"`
			From int64  `json:"effective_size"`
		} `json:"revocations"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if !r.Verified || len(r.Rotations) != 1 {
		t.Fatalf("unexpected result %+v", r)
	}
	if r.Rotations[0].From != kid || r.Rotations[0].To != kid2 || r.Rotations[0].Seq != 2 {
		t.Fatalf("rotation reported as %+v", r.Rotations[0])
	}
	if r.Rotations[0].Reason != "scheduled rotation" {
		t.Fatalf("rotation reason %q", r.Rotations[0].Reason)
	}
	// Revoking the outgoing key from seq 4 costs nothing: it signed nothing there.
	if len(r.Revocations) != 1 || r.Revocations[0].Kid != kid || r.Revocations[0].From != 4 {
		t.Fatalf("revocations reported as %+v", r.Revocations)
	}
}

func TestRevocationFlagNeedsRootAndAnchor(t *testing.T) {
	f := newRotatedFixture(t)
	cases := map[string][]string{
		"without the root":   {"--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor, "--revocations", f.revocations},
		"without the anchor": {"--log", f.log, "--chain", chainID, "--keys", f.keys, "--root", f.root, "--revocations", f.revocations},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := runCLI(args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want %d\n%s%s", code, exitUsage, out, errOut)
			}
			if !strings.Contains(errOut, "--revocations needs") {
				t.Errorf("unhelpful message: %s", errOut)
			}
		})
	}
}
