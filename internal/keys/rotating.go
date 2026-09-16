package keys

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/identity"
)

// Rotating resolves receipt-signing keys for a chain that rotates them (ADR-0016).
//
// It starts from the trust file and learns each later key from the log itself: a
// key_rotation receipt names the incoming key and carries its key-epoch certificate,
// which must be issued by the root CA. So an auditor's trust file holds one key for the
// life of a chain, however often it rotates, and introducing a new key needs both the
// outgoing signing key (to sign the rotation) and the CA (to certify the key).
//
// A Rotating resolver is stateful and single-walk: use one per verification pass, in
// order, and do not share it across goroutines.
type Rotating struct {
	known map[string]*composite.PublicKey
	roots *x509.CertPool
	// learned records which kids came from a rotation rather than the trust file,
	// for reporting.
	learned []string
}

// NewRotating trusts the keys in a trust file, and accepts later keys that a rotation
// introduces when their key-epoch certificate chains to roots. With no roots, only the
// trusted keys are ever accepted.
func NewRotating(trusted map[string]*composite.PublicKey, roots *x509.CertPool) *Rotating {
	known := make(map[string]*composite.PublicKey, len(trusted))
	for kid, key := range trusted {
		known[kid] = key
	}
	return &Rotating{known: known, roots: roots}
}

// Resolve is the KeyResolver a verifier calls for each receipt.
func (r *Rotating) Resolve(kid string) (*composite.PublicKey, error) {
	if k, ok := r.known[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("keys: kid %q is not trusted and no rotation introduced it", kid)
}

// Learned lists the key IDs this walk accepted from rotations, in order.
func (r *Rotating) Learned() []string { return append([]string(nil), r.learned...) }

// Accept checks a rotation's incoming key and, if it holds up, makes that key usable for
// the receipts that follow. certificate is the DER key-epoch certificate from the
// rotation body, keyDigest the digest the body claims, and at the receipt's timestamp:
// the certificate is judged at the moment it was used, as a timestamp token is.
func (r *Rotating) Accept(kid, keyDigest string, certificate []byte, at time.Time) error {
	if r.roots == nil {
		return fmt.Errorf("keys: no certificate roots were given, so kid %q cannot be introduced", kid)
	}
	epoch, err := identity.VerifyKeyEpoch(certificate, r.roots, at)
	if err != nil {
		return fmt.Errorf("keys: kid %q: %w", kid, err)
	}
	if epoch.Kid != kid {
		return fmt.Errorf("keys: the certificate is for kid %q, not %q", epoch.Kid, kid)
	}
	// The same way a chain names its first key in the genesis parameters.
	if got := digest.SHA256(epoch.Key.Bytes()); got != keyDigest {
		return fmt.Errorf("keys: kid %q: the certificate holds a different key than the rotation names", kid)
	}
	if existing, ok := r.known[kid]; ok {
		if bytes.Equal(existing.Bytes(), epoch.Key.Bytes()) {
			return nil
		}
		return fmt.Errorf("keys: kid %q is already known with a different key", kid)
	}
	r.known[kid] = epoch.Key
	r.learned = append(r.learned, kid)
	return nil
}
