// Package revocation records that a receipt-signing key is no longer to be
// trusted, from a named checkpoint onward (ADR-0016).
//
// A revocation cannot un-sign what a key signed. It names the last checkpoint
// believed good and means: receipts covered by that checkpoint keep verifying,
// and anything that key signed after it is refused. You lose the tail, not the
// history.
//
// Revocations are signed by the root CA, which is the only authority a stolen
// receipt-signing key cannot impersonate. That makes revoking a key a
// break-glass action needing the offline root, which is the right price for the
// one statement an attacker most wants to forge.
//
// The CA signs with plain ML-DSA-65, not the composite suite receipts use, so a
// revocation carries its own envelope rather than the receipt one. The shape is
// deliberately the same — canonical JSON payload, protected header, detached
// base64url signature — and the payload domain keeps the two kinds of signed
// statement from ever being confused (threat W14).
package revocation

import (
	"bufio"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	// Version is the revocation format version.
	Version = 1
	// Domain separates revocations from receipts, checkpoints, and anything else
	// Warden signs.
	Domain = "agent-warden/revocation/v1"
	// Alg is the JOSE algorithm name for a root-signed revocation.
	Alg = "ML-DSA-65"
	// context is the ML-DSA context string bound into every revocation
	// signature, so a revocation signature can never be read as a signature over
	// anything else the root produces.
	context = "agent-warden/revocation/v1"

	maxIDLen = 256
	maxLine  = 1 << 20
)

// ErrInvalid wraps every revocation validation failure.
var ErrInvalid = errors.New("revocation: invalid")

// ErrBadSignature is returned when a revocation's signature does not verify
// under the root.
var ErrBadSignature = errors.New("revocation: bad signature")

// ErrMalformed wraps envelope and encoding failures.
var ErrMalformed = errors.New("revocation: malformed")

var b64 = base64.RawURLEncoding.Strict()

// Revocation withdraws trust in one key of one chain from a checkpoint onward.
type Revocation struct {
	V       int    `json:"v"`
	Domain  string `json:"domain"`
	ChainID string `json:"chain_id"`
	// Kid is the key being revoked.
	Kid string `json:"kid"`
	// EffectiveSize is the size of the last checkpoint believed good. Receipts
	// at seq EffectiveSize and later signed by Kid are refused; everything the
	// checkpoint covers still verifies.
	EffectiveSize int64 `json:"effective_size"`
	// EffectiveHead is that checkpoint's head. It pins the revocation to one
	// history, so a revocation cannot be re-aimed at a fork of the same size.
	EffectiveHead string `json:"effective_head"`
	// Reason is why the key was withdrawn: free text for the log's readers.
	Reason string `json:"reason,omitempty"`
	TS     string `json:"ts"`
}

// header is the protected header of a revocation envelope.
type header struct {
	Alg    string `json:"alg"`
	Domain string `json:"domain"`
}

// Signed is a signed revocation, in the same flattened shape as a receipt.
type Signed struct {
	Payload   string `json:"payload"`
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// validID accepts a non-empty, bounded string without control characters.
func validID(field, s string) error {
	if s == "" || len(s) > maxIDLen {
		return invalid("%s must be 1-%d bytes", field, maxIDLen)
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return invalid("%s contains a control character", field)
		}
	}
	return nil
}

// Validate checks the revocation's fields.
func (r *Revocation) Validate() error {
	if r.V != Version {
		return invalid("v is %d, want %d", r.V, Version)
	}
	if r.Domain != Domain {
		return invalid("domain is %q", r.Domain)
	}
	if err := validID("chain_id", r.ChainID); err != nil {
		return err
	}
	if err := validID("kid", r.Kid); err != nil {
		return err
	}
	// Size 0 would revoke a key from the start of the chain, which is a claim
	// that no checkpoint can support: there is no anchored history to keep.
	if r.EffectiveSize < 1 || r.EffectiveSize > canonical.MaxSafeInteger {
		return invalid("effective_size %d out of range", r.EffectiveSize)
	}
	if !digest.Valid(r.EffectiveHead) {
		return invalid("effective_head is not a sha256 digest")
	}
	if r.Reason != "" {
		if err := validID("reason", r.Reason); err != nil {
			return err
		}
	}
	ts, err := time.Parse(receipt.TimeFormat, r.TS)
	if err != nil || ts.UTC().Format(receipt.TimeFormat) != r.TS {
		return invalid("ts %q is not in %s", r.TS, receipt.TimeFormat)
	}
	return nil
}

func (s *Signed) signingInput() []byte {
	return []byte(s.Protected + "." + s.Payload)
}

// Sign validates r and signs it with the root's ML-DSA-65 key.
func Sign(root *mldsa.PrivateKey, r *Revocation) (*Signed, error) {
	if root == nil {
		return nil, errors.New("revocation: signing needs the root key")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	payload, err := canonical.Encode(r)
	if err != nil {
		return nil, err
	}
	hdr, err := canonical.Encode(header{Alg: Alg, Domain: Domain})
	if err != nil {
		return nil, err
	}
	s := &Signed{Payload: b64.EncodeToString(payload), Protected: b64.EncodeToString(hdr)}
	sig, err := root.Sign(nil, s.signingInput(), &mldsa.Options{Context: context})
	if err != nil {
		return nil, fmt.Errorf("revocation: sign: %w", err)
	}
	s.Signature = b64.EncodeToString(sig)
	return s, nil
}

// RootKey returns the ML-DSA-65 public key of a root certificate.
func RootKey(root *x509.Certificate) (*mldsa.PublicKey, error) {
	if root == nil {
		return nil, errors.New("revocation: no root certificate")
	}
	pub, ok := root.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("revocation: root key is %T, want ML-DSA", root.PublicKey)
	}
	return pub, nil
}

// Verify checks the envelope and signature under the root, then decodes and
// validates the revocation. The payload is not parsed until the signature
// verifies.
func Verify(root *mldsa.PublicKey, s *Signed) (*Revocation, error) {
	if root == nil {
		return nil, errors.New("revocation: no root key")
	}
	raw, err := b64.DecodeString(s.Protected)
	if err != nil {
		return nil, malformed("protected header encoding: %v", err)
	}
	var h header
	if err := canonical.DecodeStrict(raw, &h); err != nil {
		return nil, malformed("protected header: %v", err)
	}
	if h.Alg != Alg {
		return nil, malformed("alg %q, want %q", h.Alg, Alg)
	}
	if h.Domain != Domain {
		return nil, malformed("header domain %q, want %q", h.Domain, Domain)
	}
	sig, err := b64.DecodeString(s.Signature)
	if err != nil {
		return nil, malformed("signature encoding: %v", err)
	}
	if err := mldsa.Verify(root, s.signingInput(), sig, &mldsa.Options{Context: context}); err != nil {
		return nil, ErrBadSignature
	}
	payload, err := b64.DecodeString(s.Payload)
	if err != nil {
		return nil, malformed("payload encoding: %v", err)
	}
	var r Revocation
	if err := canonical.DecodeStrict(payload, &r); err != nil {
		return nil, malformed("payload: %v", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Line returns the canonical one-line encoding published beside the anchor.
func (s *Signed) Line() ([]byte, error) { return canonical.Encode(s) }

// ParseLine decodes one published revocation line.
func ParseLine(line []byte) (*Signed, error) {
	var s Signed
	if err := canonical.DecodeStrict(line, &s); err != nil {
		return nil, malformed("line: %v", err)
	}
	return &s, nil
}

// Publish appends a signed revocation to path, one line each, and syncs.
//
// Revocations live beside the anchored checkpoints rather than inside the
// anchor file: every anchor line is a checkpoint, and a compromised Warden must
// not be able to quietly drop the notice that its key is compromised, which is
// a property of where the file lives, not of its format.
func Publish(path string, s *Signed) error {
	line, err := s.Line()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("revocation: publish: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("revocation: publish: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("revocation: publish: %w", err)
	}
	return f.Close()
}

// ReadVerified reads published revocations, verifies each signature under the
// root, and keeps those for chainID. A revocation for another chain is skipped,
// not an error: one file may cover several chains.
func ReadVerified(r io.Reader, chainID string, root *mldsa.PublicKey) ([]*Revocation, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	var out []*Revocation
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		s, err := ParseLine(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("revocation: line %d: %w", n, err)
		}
		rev, err := Verify(root, s)
		if err != nil {
			return nil, fmt.Errorf("revocation: line %d: %w", n, err)
		}
		if rev.ChainID != chainID {
			continue
		}
		out = append(out, rev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("revocation: %w", err)
	}
	return out, nil
}
