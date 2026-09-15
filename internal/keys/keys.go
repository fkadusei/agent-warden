// Package keys reads and writes the trusted public keys a verifier uses, as a
// JWK Set in the "AKP" key format of draft-ietf-jose-pq-composite-sigs.
//
// This is the interim trust input for warden-verify. Once key-epoch
// certificates exist (ADR-0008), trust will come from a root certificate.
package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// KeyType is the JWK key type for composite algorithm key pairs.
const KeyType = "AKP"

// JWK is one public composite key.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Pub string `json:"pub"`
	// Priv is only declared so a private key in a trust file is reported
	// clearly instead of as an unknown field. It is never accepted.
	Priv *string `json:"priv,omitempty"`
}

// Set is a JWK Set.
type Set struct {
	Keys []JWK `json:"keys"`
}

var b64 = base64.RawURLEncoding.Strict()

// PublicJWK describes pub under kid.
func PublicJWK(kid string, pub *composite.PublicKey) JWK {
	return JWK{Kty: KeyType, Alg: pub.Suite().Name, Kid: kid, Pub: b64.EncodeToString(pub.Bytes())}
}

// Parse reads a JWK Set of trusted public keys, keyed by kid.
func Parse(data []byte) (map[string]*composite.PublicKey, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var set Set
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	if dec.More() {
		return nil, errors.New("keys: trailing data after the key set")
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("keys: no keys")
	}
	out := make(map[string]*composite.PublicKey, len(set.Keys))
	for i, k := range set.Keys {
		if k.Priv != nil {
			return nil, fmt.Errorf("keys: key %d (%q) contains private key material; a trust file must hold public keys only", i, k.Kid)
		}
		if k.Kty != KeyType {
			return nil, fmt.Errorf("keys: key %d: kty %q, want %q", i, k.Kty, KeyType)
		}
		if k.Alg != receipt.Alg {
			return nil, fmt.Errorf("keys: key %d: alg %q, want %q", i, k.Alg, receipt.Alg)
		}
		if k.Kid == "" {
			return nil, fmt.Errorf("keys: key %d: missing kid", i)
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("keys: duplicate kid %q", k.Kid)
		}
		raw, err := b64.DecodeString(k.Pub)
		if err != nil {
			return nil, fmt.Errorf("keys: key %q: pub encoding: %w", k.Kid, err)
		}
		pub, err := composite.MLDSA65Ed25519.ParsePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("keys: key %q: %w", k.Kid, err)
		}
		out[k.Kid] = pub
	}
	return out, nil
}

// Resolver returns a function that looks up trusted keys by kid.
func Resolver(trusted map[string]*composite.PublicKey) func(kid string) (*composite.PublicKey, error) {
	return func(kid string) (*composite.PublicKey, error) {
		if k, ok := trusted[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("keys: kid %q is not trusted", kid)
	}
}
