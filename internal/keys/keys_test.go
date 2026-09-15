package keys

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
)

func newKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func setJSON(t *testing.T, ks ...JWK) []byte {
	t.Helper()
	b, err := json.Marshal(Set{Keys: ks})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	got, err := Parse(setJSON(t, PublicJWK("e1", k1.Public()), PublicJWK("e2", k2.Public())))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got["e1"].Bytes(), k1.Public().Bytes()) || !bytes.Equal(got["e2"].Bytes(), k2.Public().Bytes()) {
		t.Fatal("keys did not round-trip")
	}
	resolve := Resolver(got)
	if _, err := resolve("e1"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("nope"); err == nil {
		t.Fatal("untrusted kid resolved")
	}
}

func TestParseRejects(t *testing.T) {
	k := newKey(t)
	good := PublicJWK("e1", k.Public())
	priv := "c2VjcmV0"
	cases := map[string][]byte{
		"private key material": setJSON(t, func() JWK { j := good; j.Priv = &priv; return j }()),
		"wrong kty":            setJSON(t, func() JWK { j := good; j.Kty = "OKP"; return j }()),
		"wrong alg":            setJSON(t, func() JWK { j := good; j.Alg = "ML-DSA-65"; return j }()),
		"missing kid":          setJSON(t, func() JWK { j := good; j.Kid = ""; return j }()),
		"duplicate kid":        setJSON(t, good, good),
		"short pub":            setJSON(t, func() JWK { j := good; j.Pub = j.Pub[:40]; return j }()),
		"padded pub":           setJSON(t, func() JWK { j := good; j.Pub += "="; return j }()),
		"no keys":              []byte(`{"keys":[]}`),
		"unknown field":        []byte(strings.Replace(string(setJSON(t, good)), `"kty"`, `"use":"sig","kty"`, 1)),
		"trailing data":        append(setJSON(t, good), []byte(` {}`)...),
		"not JSON":             []byte(`nope`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
