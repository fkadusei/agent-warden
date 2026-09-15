package receipt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
)

const (
	// Alg is the JOSE algorithm for every receipt signature (ADR-0002).
	Alg = "ML-DSA-65-Ed25519"
	// AlgRef pins the draft revision whose construction produced the signature.
	AlgRef = "draft-ietf-jose-pq-composite-sigs-04"
)

var (
	// ErrMalformed wraps envelope encoding and header failures.
	ErrMalformed = errors.New("receipt: malformed envelope")
	// ErrBadSignature is returned when the composite signature does not verify.
	ErrBadSignature = errors.New("receipt: bad signature")
)

var b64 = base64.RawURLEncoding.Strict()

// header is the JWS protected header. alg_ref is listed in crit, so a verifier
// that does not understand it must reject the receipt.
type header struct {
	Alg    string   `json:"alg"`
	AlgRef string   `json:"alg_ref"`
	Crit   []string `json:"crit"`
	Kid    string   `json:"kid"`
}

// Signed is a receipt in flattened JWS JSON serialization.
type Signed struct {
	Payload   string `json:"payload"`
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// Sign validates r and signs it with k under key ID kid.
func Sign(k *composite.PrivateKey, kid string, r *Receipt) (*Signed, error) {
	if name := k.Public().Suite().Name; name != Alg {
		return nil, fmt.Errorf("receipt: key suite %s, want %s", name, Alg)
	}
	if err := validID("kid", kid); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	payload, err := canonical.Encode(r)
	if err != nil {
		return nil, err
	}
	hdr, err := canonical.Encode(header{Alg: Alg, AlgRef: AlgRef, Crit: []string{"alg_ref"}, Kid: kid})
	if err != nil {
		return nil, err
	}
	s := &Signed{Payload: b64.EncodeToString(payload), Protected: b64.EncodeToString(hdr)}
	sig, err := k.Sign(s.signingInput())
	if err != nil {
		return nil, err
	}
	s.Signature = b64.EncodeToString(sig)
	return s, nil
}

func (s *Signed) signingInput() []byte {
	return []byte(s.Protected + "." + s.Payload)
}

// Line returns the canonical one-line encoding stored in a receipt log.
func (s *Signed) Line() ([]byte, error) {
	return canonical.Encode(s)
}

// Hash returns the digest of the canonical line. The next receipt's prev field
// holds this value (ADR-0003).
func (s *Signed) Hash() (string, error) {
	line, err := s.Line()
	if err != nil {
		return "", err
	}
	return digest.SHA256(line), nil
}

// ParseLine decodes one receipt log line. The line must be canonical and contain
// exactly the three envelope fields.
func ParseLine(line []byte) (*Signed, error) {
	var s Signed
	if err := decodeStrict(line, &s); err != nil {
		return nil, malformed("line: %v", err)
	}
	return &s, nil
}

// KeyID returns the key ID from the protected header so the caller can look up
// the verification key. The header is not authenticated until Verify succeeds.
func (s *Signed) KeyID() (string, error) {
	h, err := s.header()
	if err != nil {
		return "", err
	}
	return h.Kid, nil
}

func (s *Signed) header() (*header, error) {
	raw, err := b64.DecodeString(s.Protected)
	if err != nil {
		return nil, malformed("protected header encoding: %v", err)
	}
	var h header
	if err := decodeStrict(raw, &h); err != nil {
		return nil, malformed("protected header: %v", err)
	}
	if h.Alg != Alg {
		return nil, malformed("alg %q, want %q", h.Alg, Alg)
	}
	if h.AlgRef != AlgRef {
		return nil, malformed("alg_ref %q, want %q", h.AlgRef, AlgRef)
	}
	if !slices.Equal(h.Crit, []string{"alg_ref"}) {
		return nil, malformed("crit must be [\"alg_ref\"]")
	}
	if err := validID("kid", h.Kid); err != nil {
		return nil, malformed("kid: %v", err)
	}
	return &h, nil
}

// Verify checks the envelope and signature with pub, then decodes and validates
// the payload. The payload is not parsed until the signature verifies.
func Verify(pub *composite.PublicKey, s *Signed) (*Receipt, error) {
	if name := pub.Suite().Name; name != Alg {
		return nil, fmt.Errorf("receipt: key suite %s, want %s", name, Alg)
	}
	if _, err := s.header(); err != nil {
		return nil, err
	}
	sig, err := b64.DecodeString(s.Signature)
	if err != nil {
		return nil, malformed("signature encoding: %v", err)
	}
	if err := pub.Verify(s.signingInput(), sig); err != nil {
		return nil, ErrBadSignature
	}
	payload, err := b64.DecodeString(s.Payload)
	if err != nil {
		return nil, malformed("payload encoding: %v", err)
	}
	var r Receipt
	if err := decodeStrict(payload, &r); err != nil {
		return nil, malformed("payload: %v", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// decodeStrict decodes canonical JSON into v and requires that re-encoding v
// reproduces the input exactly. This rejects non-canonical input, unknown
// fields, missing fields, duplicate keys, and numbers JCS would change.
func decodeStrict(b []byte, v any) error {
	if err := canonical.Check(b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	again, err := canonical.Encode(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return errors.New("fields do not round-trip (missing, empty, or out-of-range values)")
	}
	return nil
}
