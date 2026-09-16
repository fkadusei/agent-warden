package tsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

// LocalPolicy is the policy OID the local authority stamps with. It is synthetic, for
// the demo and tests; a real authority publishes its own.
var LocalPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// Authority is a small RFC 3161 timestamp authority for the demo, tests, and offline
// benchmark runs, so nothing reaches the network. Real deployments point Warden at a
// public authority instead.
//
// It signs with ECDSA P-256: timestamp tokens are CMS, which fixes what signature
// algorithms verifiers accept, and that is outside Warden's own post-quantum chain.
type Authority struct {
	root     *x509.Certificate
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	now      func() time.Time
	Requests int
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewAuthority creates a local authority: its own root and a timestamping certificate.
func NewAuthority(name string, notBefore, notAfter time.Time) (*Authority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootSerial, err := serial()
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: name + " Root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafSerial, err := serial()
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, key.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	return &Authority{root: root, cert: leaf, key: key, now: time.Now}, nil
}

// Roots is the pool a verifier needs to trust this authority.
func (a *Authority) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.root)
	return pool
}

// RootPEM is the authority's root certificate, for a `--tsa-roots` file.
func (a *Authority) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.root.Raw})
}

// Respond answers one DER timestamp request.
func (a *Authority) Respond(request []byte) ([]byte, error) {
	req, err := timestamp.ParseRequest(request)
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}
	ts := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              a.now().UTC(),
		Nonce:             req.Nonce,
		Policy:            LocalPolicy,
		Ordering:          false,
		AddTSACertificate: true,
	}
	return ts.CreateResponseWithOpts(a.cert, a.key, req.HashAlgorithm)
}

// Handler serves the authority over HTTP, as a real one is reached.
func (a *Authority) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post a timestamp query", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxResponse))
		if err != nil {
			http.Error(w, "unreadable request", http.StatusBadRequest)
			return
		}
		a.Requests++
		reply, err := a.Respond(body)
		if err != nil {
			http.Error(w, "bad timestamp request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", ReplyContentType)
		w.Write(reply)
	})
}
