// Package composite implements the ML-DSA + EdDSA composite signature
// construction from draft-ietf-jose-pq-composite-sigs-04, section 4.
//
// Warden signs receipts only with ML-DSA-65-Ed25519 (ADR-0002). A second suite,
// ML-DSA-44-Ed25519, is kept unexported so the construction can be checked
// against a second set of the draft's test vectors.
//
// A composite signature is valid only if BOTH component signatures are valid.
// There is no single-component fallback.
package composite

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
)

// Prefix is the signature-combiner prefix from the draft, prepended to every
// message representative.
const Prefix = "CompositeAlgorithmSignatures2025"

// SeedSize is the size of a composite private key seed: a 32-byte ML-DSA seed
// followed by a 32-byte Ed25519 seed.
const SeedSize = mldsa.PrivateKeySize + ed25519.SeedSize

// ErrInvalidSignature is returned for any signature that fails verification,
// including malformed or wrongly sized signatures.
var ErrInvalidSignature = errors.New("composite: invalid signature")

// Suite is one composite algorithm: an ML-DSA parameter set paired with Ed25519.
type Suite struct {
	// Name is the JOSE "alg" value.
	Name string
	// Label is the domain separator bound into the message representative and
	// passed to ML-DSA as its context string.
	Label string

	params  func() mldsa.Parameters
	pubSize int // ML-DSA public key size in bytes (FIPS 204)
	sigSize int // ML-DSA signature size in bytes (FIPS 204)
}

// MLDSA65Ed25519 is the suite Warden uses to sign receipts.
var MLDSA65Ed25519 = Suite{
	Name:    "ML-DSA-65-Ed25519",
	Label:   "COMPSIG-MLDSA65-Ed25519-SHA512",
	params:  mldsa.MLDSA65,
	pubSize: 1952,
	sigSize: 3309,
}

// mldsa44Ed25519 exists only to test the construction against a second vector.
var mldsa44Ed25519 = Suite{
	Name:    "ML-DSA-44-Ed25519",
	Label:   "COMPSIG-MLDSA44-Ed25519-SHA512",
	params:  mldsa.MLDSA44,
	pubSize: 1312,
	sigSize: 2420,
}

// PublicKeySize is the size of the serialized composite public key.
func (s Suite) PublicKeySize() int { return s.pubSize + ed25519.PublicKeySize }

// SignatureSize is the size of a serialized composite signature.
func (s Suite) SignatureSize() int { return s.sigSize + ed25519.SignatureSize }

// MessageRepresentative computes M' = Prefix || Label || 0x00 || SHA-512(msg).
// The 0x00 byte encodes an empty application context.
func (s Suite) MessageRepresentative(msg []byte) []byte {
	ph := sha512.Sum512(msg)
	m := make([]byte, 0, len(Prefix)+len(s.Label)+1+len(ph))
	m = append(m, Prefix...)
	m = append(m, s.Label...)
	m = append(m, 0x00)
	return append(m, ph[:]...)
}

// PrivateKey is a composite signing key.
type PrivateKey struct {
	suite Suite
	mldsa *mldsa.PrivateKey
	ed    ed25519.PrivateKey
	pub   *PublicKey
}

// PublicKey is a composite verification key.
type PublicKey struct {
	suite Suite
	mldsa *mldsa.PublicKey
	ed    ed25519.PublicKey
}

// GenerateKey creates a new composite key from fresh randomness.
func (s Suite) GenerateKey() (*PrivateKey, error) {
	seed := make([]byte, SeedSize)
	rand.Read(seed)
	return s.NewPrivateKey(seed)
}

// NewPrivateKey derives a composite key from a 64-byte seed
// (ML-DSA seed || Ed25519 seed).
func (s Suite) NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("composite: seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	mk, err := mldsa.NewPrivateKey(s.params(), seed[:mldsa.PrivateKeySize])
	if err != nil {
		return nil, fmt.Errorf("composite: ML-DSA key: %w", err)
	}
	ek := ed25519.NewKeyFromSeed(seed[mldsa.PrivateKeySize:])
	pub := &PublicKey{suite: s, mldsa: mk.PublicKey(), ed: ek.Public().(ed25519.PublicKey)}
	return &PrivateKey{suite: s, mldsa: mk, ed: ek, pub: pub}, nil
}

// Seed returns a copy of the 64-byte seed the key was derived from.
func (k *PrivateKey) Seed() []byte {
	return append(k.mldsa.Bytes(), k.ed.Seed()...)
}

// Public returns the matching composite public key.
func (k *PrivateKey) Public() *PublicKey { return k.pub }

// Sign produces a composite signature over msg.
func (k *PrivateKey) Sign(msg []byte) ([]byte, error) {
	m := k.suite.MessageRepresentative(msg)
	ms, err := k.mldsa.Sign(nil, m, &mldsa.Options{Context: k.suite.Label})
	if err != nil {
		return nil, fmt.Errorf("composite: ML-DSA sign: %w", err)
	}
	if len(ms) != k.suite.sigSize {
		return nil, fmt.Errorf("composite: unexpected ML-DSA signature size %d", len(ms))
	}
	return append(ms, ed25519.Sign(k.ed, m)...), nil
}

// ParsePublicKey decodes a serialized composite public key
// (ML-DSA public key || Ed25519 public key).
func (s Suite) ParsePublicKey(b []byte) (*PublicKey, error) {
	if len(b) != s.PublicKeySize() {
		return nil, fmt.Errorf("composite: %s public key must be %d bytes, got %d", s.Name, s.PublicKeySize(), len(b))
	}
	mk, err := mldsa.NewPublicKey(s.params(), b[:s.pubSize])
	if err != nil {
		return nil, fmt.Errorf("composite: ML-DSA public key: %w", err)
	}
	ed := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(ed, b[s.pubSize:])
	return &PublicKey{suite: s, mldsa: mk, ed: ed}, nil
}

// Bytes serializes the public key as ML-DSA public key || Ed25519 public key.
func (p *PublicKey) Bytes() []byte {
	return append(p.mldsa.Bytes(), p.ed...)
}

// Suite reports which composite algorithm the key belongs to.
func (p *PublicKey) Suite() Suite { return p.suite }

// Verify checks a composite signature over msg. Both components must verify.
func (p *PublicKey) Verify(msg, sig []byte) error {
	if len(sig) != p.suite.SignatureSize() {
		return ErrInvalidSignature
	}
	m := p.suite.MessageRepresentative(msg)
	mldsaOK := mldsa.Verify(p.mldsa, m, sig[:p.suite.sigSize], &mldsa.Options{Context: p.suite.Label}) == nil
	edOK := ed25519.Verify(p.ed, m, sig[p.suite.sigSize:])
	if !mldsaOK || !edOK {
		return ErrInvalidSignature
	}
	return nil
}
