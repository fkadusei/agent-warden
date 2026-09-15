// Package identity issues and verifies Warden's X.509 certificates (ADR-0010):
// the root, key-epoch certificates for receipt-signing keys, and short-lived task
// credentials that name an agent, a principal, and a task.
//
// All certificates are signed with plain ML-DSA-65. Identity is read only from
// urn:warden: SAN URIs, and each certificate's purpose is fixed by a certificate
// policy under Warden's OID arc.
package identity

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
)

// Arc is Warden's OID arc (ADR-0008, ADR-0010).
const Arc = "2.25.319797216735078154913038669087058524786"

var (
	// PolicyKeyEpoch marks a receipt-signing key-epoch certificate.
	PolicyKeyEpoch = mustOID(Arc + ".1")
	// PolicyTaskCredential marks a task credential.
	PolicyTaskCredential = mustOID(Arc + ".2")
)

const (
	// MaxTaskLifetime is the longest a task credential may be valid.
	MaxTaskLifetime = 15 * time.Minute
	// ClockSkew is tolerated on top of MaxTaskLifetime, for back-dated NotBefore.
	ClockSkew = time.Minute

	mldsa65PublicKeySize = 1952

	uriKid       = "urn:warden:kid:"
	uriEd25519   = "urn:warden:ed25519:"
	uriAgent     = "urn:warden:agent:"
	uriPrincipal = "urn:warden:principal:"
	uriTask      = "urn:warden:task:"
	uriWarden    = "urn:warden:"
)

// ErrInvalid wraps every certificate that fails verification or profile checks.
var ErrInvalid = errors.New("identity: invalid certificate")

var valuePattern = regexp.MustCompile(`^[A-Za-z0-9._~@:+-]{1,256}$`)

var b64 = base64.RawURLEncoding.Strict()

func mustOID(s string) x509.OID {
	oid, err := x509.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return oid
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func checkValue(field, v string) error {
	if !valuePattern.MatchString(v) {
		return fmt.Errorf("identity: %s %q must match %s", field, v, valuePattern)
	}
	return nil
}

func isMLDSA65(pub *mldsa.PublicKey) bool {
	return pub != nil && len(pub.Bytes()) == mldsa65PublicKeySize
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func urn(prefix, value string) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: strings.TrimPrefix(prefix, "urn:") + value}
}

// CA is a Warden root: an ML-DSA-65 key and its self-signed certificate.
type CA struct {
	Cert *x509.Certificate
	Key  *mldsa.PrivateKey
}

// NewCA creates a self-signed root valid from notBefore to notAfter.
func NewCA(name string, key *mldsa.PrivateKey, notBefore, notAfter time.Time) (*CA, error) {
	if !isMLDSA65(key.PublicKey()) {
		return nil, errors.New("identity: root key must be ML-DSA-65")
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return nil, fmt.Errorf("identity: root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("identity: root: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Pool returns a pool holding only this root, for verification.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

func (ca *CA) issue(tmpl *x509.Certificate, pub *mldsa.PublicKey) ([]byte, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = sn
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("identity: issue: %w", err)
	}
	return der, nil
}

// IssueKeyEpoch certifies a composite receipt-signing key under kid.
func (ca *CA) IssueKeyEpoch(kid string, pub *composite.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
	if err := checkValue("kid", kid); err != nil {
		return nil, err
	}
	if pub.Suite().Name != composite.MLDSA65Ed25519.Name {
		return nil, fmt.Errorf("identity: key suite %s, want %s", pub.Suite().Name, composite.MLDSA65Ed25519.Name)
	}
	raw := pub.Bytes()
	split := len(raw) - ed25519.PublicKeySize
	mpub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw[:split])
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return ca.issue(&x509.Certificate{
		Subject:   pkix.Name{CommonName: kid},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		Policies:  []x509.OID{PolicyKeyEpoch},
		URIs:      []*url.URL{urn(uriKid, kid), urn(uriEd25519, b64.EncodeToString(raw[split:]))},
	}, mpub)
}

// TaskClaims name who acts, for whom, and in which task.
type TaskClaims struct {
	Agent     string
	Principal string
	Task      string
}

func (c TaskClaims) check() error {
	for field, v := range map[string]string{"agent": c.Agent, "principal": c.Principal, "task": c.Task} {
		if err := checkValue(field, v); err != nil {
			return err
		}
	}
	return nil
}

// IssueTask issues a short-lived task credential for the agent key pub.
func (ca *CA) IssueTask(c TaskClaims, pub *mldsa.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !isMLDSA65(pub) {
		return nil, errors.New("identity: task key must be ML-DSA-65")
	}
	if !notAfter.After(notBefore) || notAfter.Sub(notBefore) > MaxTaskLifetime+ClockSkew {
		return nil, fmt.Errorf("identity: task credential lifetime %s exceeds %s", notAfter.Sub(notBefore), MaxTaskLifetime+ClockSkew)
	}
	return ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: c.Agent},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:    []x509.OID{PolicyTaskCredential},
		URIs:        []*url.URL{urn(uriAgent, c.Agent), urn(uriPrincipal, c.Principal), urn(uriTask, c.Task)},
	}, pub)
}

// verify parses der, checks the chain, time, purpose policy, key type, and
// names, and returns the certificate with its urn:warden: values by prefix.
func verify(der []byte, roots *x509.CertPool, at time.Time, policy x509.OID, usages []x509.ExtKeyUsage, prefixes ...string) (*x509.Certificate, map[string]string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, invalid("%v", err)
	}
	if cert.IsCA {
		return nil, nil, invalid("a CA certificate cannot be used as a leaf")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: usages}); err != nil {
		return nil, nil, invalid("%v", err)
	}
	if cert.SignatureAlgorithm.String() != "ML-DSA-65" {
		return nil, nil, invalid("signature algorithm %s, want ML-DSA-65", cert.SignatureAlgorithm)
	}
	if pub, ok := cert.PublicKey.(*mldsa.PublicKey); !ok || !isMLDSA65(pub) {
		return nil, nil, invalid("subject key is not ML-DSA-65")
	}
	if len(cert.Policies) != 1 || !cert.Policies[0].Equal(policy) {
		return nil, nil, invalid("policies %v, want exactly %s", cert.Policies, policy)
	}
	if len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses) > 0 {
		return nil, nil, invalid("unexpected DNS, email, or IP subject alternative names")
	}
	vals := map[string]string{}
	for _, u := range cert.URIs {
		s := u.String()
		matched := false
		for _, p := range prefixes {
			if v, ok := strings.CutPrefix(s, p); ok {
				if _, dup := vals[p]; dup {
					return nil, nil, invalid("duplicate %s URI", p)
				}
				if !valuePattern.MatchString(v) {
					return nil, nil, invalid("malformed %s URI", p)
				}
				vals[p], matched = v, true
				break
			}
		}
		if !matched {
			if strings.HasPrefix(s, uriWarden) {
				return nil, nil, invalid("unknown Warden URI %q", s)
			}
			return nil, nil, invalid("unexpected URI %q", s)
		}
	}
	for _, p := range prefixes {
		if _, ok := vals[p]; !ok {
			return nil, nil, invalid("missing %s URI", p)
		}
	}
	return cert, vals, nil
}

// KeyEpoch is a verified receipt-signing key.
type KeyEpoch struct {
	Kid       string
	Key       *composite.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
}

// VerifyKeyEpoch verifies a key-epoch certificate against roots at time at and
// rebuilds the composite receipt key it certifies.
func VerifyKeyEpoch(der []byte, roots *x509.CertPool, at time.Time) (*KeyEpoch, error) {
	cert, vals, err := verify(der, roots, at, PolicyKeyEpoch, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, uriKid, uriEd25519)
	if err != nil {
		return nil, err
	}
	if len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) > 0 {
		return nil, invalid("key-epoch certificates must not have extended key usages")
	}
	ed, err := b64.DecodeString(vals[uriEd25519])
	if err != nil || len(ed) != ed25519.PublicKeySize {
		return nil, invalid("ed25519 URI does not hold a 32-byte public key")
	}
	mpub := cert.PublicKey.(*mldsa.PublicKey)
	key, err := composite.MLDSA65Ed25519.ParsePublicKey(append(mpub.Bytes(), ed...))
	if err != nil {
		return nil, invalid("%v", err)
	}
	return &KeyEpoch{Kid: vals[uriKid], Key: key, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}, nil
}

// Task is a verified task credential.
type Task struct {
	TaskClaims
	Key         *mldsa.PublicKey
	NotAfter    time.Time
	Fingerprint string
}

// VerifyTask verifies a task credential against roots at time at.
func VerifyTask(der []byte, roots *x509.CertPool, at time.Time) (*Task, error) {
	cert, vals, err := verify(der, roots, at, PolicyTaskCredential, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, uriAgent, uriPrincipal, uriTask)
	if err != nil {
		return nil, err
	}
	if cert.NotAfter.Sub(cert.NotBefore) > MaxTaskLifetime+ClockSkew {
		return nil, invalid("lifetime %s exceeds %s", cert.NotAfter.Sub(cert.NotBefore), MaxTaskLifetime+ClockSkew)
	}
	sum := sha256.Sum256(der)
	return &Task{
		TaskClaims:  TaskClaims{Agent: vals[uriAgent], Principal: vals[uriPrincipal], Task: vals[uriTask]},
		Key:         cert.PublicKey.(*mldsa.PublicKey),
		NotAfter:    cert.NotAfter,
		Fingerprint: "cert-sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}
