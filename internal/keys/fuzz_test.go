package keys

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
)

// No trust file crashes Parse, and every key it accepts survives a round trip.
func FuzzParse(f *testing.F) {
	k, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{7}, composite.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	good, err := json.Marshal(Set{Keys: []JWK{PublicJWK("warden-e1", k.Public())}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":[{"kty":"AKP","alg":"ML-DSA-65-Ed25519","kid":"k","pub":"AA","priv":"AA"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		trusted, err := Parse(data)
		if err != nil {
			return
		}
		var set Set
		for kid, pub := range trusted {
			set.Keys = append(set.Keys, PublicJWK(kid, pub))
		}
		again, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(again)
		if err != nil {
			t.Fatalf("accepted keys do not parse back: %v", err)
		}
		for kid, pub := range trusted {
			if !bytes.Equal(back[kid].Bytes(), pub.Bytes()) {
				t.Fatalf("key %q changed in a round trip", kid)
			}
		}
	})
}
