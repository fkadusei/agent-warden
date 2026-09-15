package composite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vector is one example from draft-ietf-jose-pq-composite-sigs-04, Appendix A.1.
type vector struct {
	MLDSASeed string `json:"mldsa_seed"`
	EdDSASeed string `json:"eddsa_seed"`
	JWK       struct {
		Kty  string `json:"kty"`
		Alg  string `json:"alg"`
		Pub  string `json:"pub"`
		Priv string `json:"priv"`
	} `json:"jwk"`
	JWS                      string `json:"jws"`
	RawToBeSigned            string `json:"raw_to_be_signed"`
	RawMessageRepresentative string `json:"raw_message_representative"`
	RawCompositeSignature    string `json:"raw_composite_signature"`
	RawCompositePublicKey    string `json:"raw_composite_public_key"`
}

func loadVector(t *testing.T, s Suite) vector {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "composite", s.Name+".jose.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.JWK.Alg != s.Name {
		t.Fatalf("vector alg %q, want %q", v.JWK.Alg, s.Name)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func unb64u(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url: %v", err)
	}
	return b
}

func TestDraftVectors(t *testing.T) {
	for _, s := range []Suite{MLDSA65Ed25519, mldsa44Ed25519} {
		t.Run(s.Name, func(t *testing.T) {
			v := loadVector(t, s)
			seed := append(unhex(t, v.MLDSASeed), unhex(t, v.EdDSASeed)...)
			tbs := unhex(t, v.RawToBeSigned)
			wantSig := unhex(t, v.RawCompositeSignature)
			wantPub := unhex(t, v.RawCompositePublicKey)

			k, err := s.NewPrivateKey(seed)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("public key from seeds", func(t *testing.T) {
				if got := k.Public().Bytes(); !bytes.Equal(got, wantPub) {
					t.Fatal("derived public key does not match raw_composite_public_key")
				}
				if !bytes.Equal(unb64u(t, v.JWK.Pub), wantPub) {
					t.Fatal("jwk.pub does not match raw_composite_public_key")
				}
			})

			t.Run("private key is the concatenated seeds", func(t *testing.T) {
				if !bytes.Equal(unb64u(t, v.JWK.Priv), seed) {
					t.Fatal("jwk.priv is not mldsa_seed || eddsa_seed")
				}
				if !bytes.Equal(k.Seed(), seed) {
					t.Fatal("Seed() does not round-trip")
				}
			})

			t.Run("message representative", func(t *testing.T) {
				if got := s.MessageRepresentative(tbs); !bytes.Equal(got, unhex(t, v.RawMessageRepresentative)) {
					t.Fatal("M' does not match raw_message_representative")
				}
			})

			t.Run("vector signature verifies", func(t *testing.T) {
				pub, err := s.ParsePublicKey(wantPub)
				if err != nil {
					t.Fatal(err)
				}
				if err := pub.Verify(tbs, wantSig); err != nil {
					t.Fatalf("vector signature rejected: %v", err)
				}
			})

			t.Run("JWS is consistent with raw values", func(t *testing.T) {
				parts := strings.Split(v.JWS, ".")
				if len(parts) != 3 {
					t.Fatalf("JWS has %d parts", len(parts))
				}
				if got := parts[0] + "." + parts[1]; got != string(tbs) {
					t.Fatal("JWS signing input does not match raw_to_be_signed")
				}
				if !bytes.Equal(unb64u(t, parts[2]), wantSig) {
					t.Fatal("JWS signature does not match raw_composite_signature")
				}
			})

			t.Run("fresh signature verifies", func(t *testing.T) {
				sig, err := k.Sign(tbs)
				if err != nil {
					t.Fatal(err)
				}
				if len(sig) != s.SignatureSize() {
					t.Fatalf("signature size %d, want %d", len(sig), s.SignatureSize())
				}
				if err := k.Public().Verify(tbs, sig); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestRejectsTamperingAndDowngrade(t *testing.T) {
	s := MLDSA65Ed25519
	k, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"seq":1,"type":"decision"}`)
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public()

	flip := func(i int) []byte {
		b := bytes.Clone(sig)
		b[i] ^= 0x01
		return b
	}

	// A signature made with the right keys but without the composite binding:
	// ML-DSA with an empty context and Ed25519 over the raw message.
	unbound := func() []byte {
		ms, err := k.mldsa.Sign(nil, msg, &mldsa.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return append(ms, ed25519.Sign(k.ed, msg)...)
	}

	cases := []struct {
		name string
		msg  []byte
		sig  []byte
	}{
		{"ML-DSA component altered", msg, flip(0)},
		{"Ed25519 component altered", msg, flip(len(sig) - 1)},
		{"Ed25519 component stripped", msg, sig[:s.sigSize]},
		{"ML-DSA component stripped", msg, sig[s.sigSize:]},
		{"Ed25519 component zeroed", msg, append(bytes.Clone(sig[:s.sigSize]), make([]byte, ed25519.SignatureSize)...)},
		{"extra trailing byte", msg, append(bytes.Clone(sig), 0)},
		{"different message", []byte(`{"seq":2,"type":"decision"}`), sig},
		{"components without composite binding", msg, unbound()},
		{"empty signature", msg, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := pub.Verify(c.msg, c.sig); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("got %v, want ErrInvalidSignature", err)
			}
		})
	}

	t.Run("other key rejected", func(t *testing.T) {
		other, err := s.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := other.Public().Verify(msg, sig); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("got %v, want ErrInvalidSignature", err)
		}
	})
}

func TestKeyEncoding(t *testing.T) {
	s := MLDSA65Ed25519
	k, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := k.Public().Bytes()
	if len(b) != s.PublicKeySize() {
		t.Fatalf("public key size %d, want %d", len(b), s.PublicKeySize())
	}
	pub, err := s.ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub.Bytes(), b) {
		t.Fatal("public key does not round-trip")
	}
	if _, err := s.ParsePublicKey(b[:len(b)-1]); err == nil {
		t.Fatal("short public key accepted")
	}
	if _, err := s.NewPrivateKey(make([]byte, SeedSize-1)); err == nil {
		t.Fatal("short seed accepted")
	}
	k2, err := s.NewPrivateKey(k.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k2.Public().Bytes(), b) {
		t.Fatal("key does not round-trip through its seed")
	}
}
