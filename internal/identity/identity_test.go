package identity

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

var now = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

func mlkey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("Warden Test Root", mlkey(t), now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func receiptKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var claims = TaskClaims{Agent: "support-agent-7", Principal: "alice@tenant-a", Task: "01J9Z4TASK"}

func TestOIDsAreUnderWardenArc(t *testing.T) {
	for name, oid := range map[string]x509.OID{"key epoch": PolicyKeyEpoch, "task": PolicyTaskCredential} {
		if !strings.HasPrefix(oid.String(), Arc+".") {
			t.Errorf("%s policy %s is not under %s", name, oid, Arc)
		}
	}
	if PolicyKeyEpoch.Equal(PolicyTaskCredential) {
		t.Fatal("purposes share an OID")
	}
}

func TestKeyEpochRoundTrip(t *testing.T) {
	ca := newCA(t)
	k := receiptKey(t)
	der, err := ca.IssueKeyEpoch("warden-2026-09-e1", k.Public(), now.Add(-time.Minute), now.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := VerifyKeyEpoch(der, ca.Pool(), now)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Kid != "warden-2026-09-e1" || !bytes.Equal(ep.Key.Bytes(), k.Public().Bytes()) {
		t.Fatalf("certificate does not carry the composite key: kid=%s", ep.Kid)
	}

	// End to end: a receipt signed with the key verifies with the key rebuilt
	// from its certificate.
	r := &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain, ChainID: "c", Seq: 0, Prev: digest.SHA256(nil),
		TS: "2026-09-15T12:00:00.000Z", Type: receipt.TypeDecision, TaskID: claims.Task,
		Actor:    &receipt.Actor{Agent: claims.Agent, Principal: claims.Principal},
		Call:     &receipt.Call{Tool: "crm/lookup", Manifest: digest.SHA256(nil), ArgsCommitment: digest.SHA256(nil)},
		Decision: &receipt.Decision{Result: receipt.Allow, PolicyRevision: digest.SHA256(nil)},
	}
	s, err := receipt.Sign(k, ep.Kid, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.Verify(ep.Key, s); err != nil {
		t.Fatalf("receipt does not verify with the certified key: %v", err)
	}
}

func TestTaskRoundTrip(t *testing.T) {
	ca := newCA(t)
	agent := mlkey(t)
	der, err := ca.IssueTask(claims, agent.PublicKey(), now.Add(-ClockSkew), now.Add(MaxTaskLifetime))
	if err != nil {
		t.Fatal(err)
	}
	task, err := VerifyTask(der, ca.Pool(), now)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if task.TaskClaims != claims || !bytes.Equal(task.Key.Bytes(), agent.PublicKey().Bytes()) ||
		task.Fingerprint != "cert-sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected task %+v", task.TaskClaims)
	}
}

func TestIssueRefuses(t *testing.T) {
	ca := newCA(t)
	agent := mlkey(t).PublicKey()
	cases := map[string]func() error{
		"task lifetime too long": func() error {
			_, err := ca.IssueTask(claims, agent, now, now.Add(MaxTaskLifetime+ClockSkew+time.Second))
			return err
		},
		"task expiry before start": func() error {
			_, err := ca.IssueTask(claims, agent, now, now.Add(-time.Second))
			return err
		},
		"space in principal": func() error {
			c := claims
			c.Principal = "alice smith"
			_, err := ca.IssueTask(c, agent, now, now.Add(time.Minute))
			return err
		},
		"empty task": func() error {
			c := claims
			c.Task = ""
			_, err := ca.IssueTask(c, agent, now, now.Add(time.Minute))
			return err
		},
		"slash in kid": func() error {
			_, err := ca.IssueKeyEpoch("a/b", receiptKey(t).Public(), now, now.Add(time.Hour))
			return err
		},
	}
	for name, issue := range cases {
		t.Run(name, func(t *testing.T) {
			if issue() == nil {
				t.Fatal("issued")
			}
		})
	}
}

// raw issues an arbitrary certificate from ca, for building malformed credentials.
func raw(t *testing.T, ca *CA, tmpl *x509.Certificate, pub *mldsa.PublicKey) []byte {
	t.Helper()
	der, err := ca.issue(tmpl, pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func uris(t *testing.T, ss ...string) []*url.URL {
	t.Helper()
	var out []*url.URL
	for _, s := range ss {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, u)
	}
	return out
}

func TestVerifyRejects(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	k := receiptKey(t)
	agent := mlkey(t)

	epoch, err := ca.IssueKeyEpoch("e1", k.Public(), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	task, err := ca.IssueTask(claims, agent.PublicKey(), now.Add(-time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	fromOther, err := other.IssueTask(claims, agent.PublicKey(), now.Add(-time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	edURI := func() string {
		s, _ := VerifyKeyEpoch(epoch, ca.Pool(), now)
		return uriEd25519 + b64.EncodeToString(s.Key.Bytes()[mldsa65PublicKeySize:])
	}()
	taskTmpl := func(mut func(c *x509.Certificate)) []byte {
		c := &x509.Certificate{
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			Policies: []x509.OID{PolicyTaskCredential},
			URIs:     uris(t, uriAgent+claims.Agent, uriPrincipal+claims.Principal, uriTask+claims.Task),
		}
		mut(c)
		return raw(t, ca, c, agent.PublicKey())
	}

	type check func([]byte, *x509.CertPool, time.Time) error
	asTask := func(der []byte, roots *x509.CertPool, at time.Time) error {
		_, err := VerifyTask(der, roots, at)
		return err
	}
	asEpoch := func(der []byte, roots *x509.CertPool, at time.Time) error {
		_, err := VerifyKeyEpoch(der, roots, at)
		return err
	}

	cases := []struct {
		name  string
		der   []byte
		roots *x509.CertPool
		at    time.Time
		verif check
	}{
		{"expired task credential", task, ca.Pool(), now.Add(11 * time.Minute), asTask},
		{"task credential not yet valid", task, ca.Pool(), now.Add(-2 * time.Minute), asTask},
		{"issued by another root", fromOther, ca.Pool(), now, asTask},
		{"key-epoch certificate used as a task credential", epoch, ca.Pool(), now, asTask},
		{"task credential used as a key-epoch certificate", task, ca.Pool(), now, asEpoch},
		{"root used as a leaf", ca.Cert.Raw, ca.Pool(), now, asTask},
		{"not a certificate", []byte("nope"), ca.Pool(), now, asTask},
		{"task without client-auth usage", taskTmpl(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }), ca.Pool(), now, asTask},
		{"task with both policies", taskTmpl(func(c *x509.Certificate) { c.Policies = append(c.Policies, PolicyKeyEpoch) }), ca.Pool(), now, asTask},
		{"task with no policy", taskTmpl(func(c *x509.Certificate) { c.Policies = nil }), ca.Pool(), now, asTask},
		{"task missing principal", taskTmpl(func(c *x509.Certificate) { c.URIs = uris(t, uriAgent+"a", uriTask+"t") }), ca.Pool(), now, asTask},
		{"task with duplicate agent", taskTmpl(func(c *x509.Certificate) { c.URIs = append(c.URIs, uris(t, uriAgent+"b")...) }), ca.Pool(), now, asTask},
		{"task with unknown Warden URI", taskTmpl(func(c *x509.Certificate) { c.URIs = append(c.URIs, uris(t, "urn:warden:role:admin")...) }), ca.Pool(), now, asTask},
		{"task with a DNS name", taskTmpl(func(c *x509.Certificate) { c.DNSNames = []string{"agent.example"} }), ca.Pool(), now, asTask},
		{"task valid for too long", taskTmpl(func(c *x509.Certificate) { c.NotAfter = now.Add(2 * time.Hour) }), ca.Pool(), now, asTask},
		{"key epoch missing ed25519 URI", raw(t, ca, &x509.Certificate{
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			Policies: []x509.OID{PolicyKeyEpoch}, URIs: uris(t, uriKid+"e1"),
		}, agent.PublicKey()), ca.Pool(), now, asEpoch},
		{"key epoch with short ed25519 key", raw(t, ca, &x509.Certificate{
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			Policies: []x509.OID{PolicyKeyEpoch}, URIs: uris(t, uriKid+"e1", uriEd25519+"AAAA"),
		}, agent.PublicKey()), ca.Pool(), now, asEpoch},
		{"key epoch with an extended key usage", raw(t, ca, &x509.Certificate{
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			Policies:    []x509.OID{PolicyKeyEpoch}, URIs: uris(t, uriKid+"e1", edURI),
		}, agent.PublicKey()), ca.Pool(), now, asEpoch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.verif(c.der, c.roots, c.at); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCARequiresMLDSA65(t *testing.T) {
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA("weak", k, now, now.Add(time.Hour)); err == nil {
		t.Fatal("ML-DSA-44 root accepted")
	}
	// A root made directly with Go (not via NewCA) but a non-ML-DSA-65 leaf key is
	// refused at verification.
	ca := newCA(t)
	weakDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "weak"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []x509.OID{PolicyTaskCredential},
		URIs:     uris(t, uriAgent+"a", uriPrincipal+"p", uriTask+"t"),
	}, ca.Cert, k.PublicKey(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTask(weakDER, ca.Pool(), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ML-DSA-44 task key: got %v, want ErrInvalid", err)
	}
}
