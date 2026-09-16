package tsa

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func authority(t *testing.T, name string) *Authority {
	t.Helper()
	now := time.Now()
	a, err := NewAuthority(name, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func stamp(t *testing.T, a *Authority, message []byte) []byte {
	t.Helper()
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	token, err := (&Client{URL: srv.URL}).Stamp(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestStampAndVerify(t *testing.T) {
	a := authority(t, "Warden Local TSA")
	message := []byte(`{"checkpoint":"line as anchored"}`)
	before := time.Now().Add(-time.Minute)

	token := stamp(t, a, message)
	when, err := Verify(token, message, a.Roots())
	if err != nil {
		t.Fatal(err)
	}
	if when.Before(before) || when.After(time.Now().Add(time.Minute)) {
		t.Fatalf("timestamp %s is not around now", when)
	}
	if a.Requests != 1 {
		t.Fatalf("authority saw %d requests", a.Requests)
	}
}

func TestVerifyRejects(t *testing.T) {
	a := authority(t, "Warden Local TSA")
	other := authority(t, "Someone Else")
	message := []byte("checkpoint line")
	token := stamp(t, a, message)

	cases := map[string]struct {
		token   []byte
		message []byte
		roots   *x509.CertPool
	}{
		"different data":      {token, []byte("checkpoint line!"), a.Roots()},
		"untrusted authority": {token, message, other.Roots()},
		"no roots":            {token, message, nil},
		"empty roots":         {token, message, x509.NewCertPool()},
		"not a token":         {[]byte("nonsense"), message, a.Roots()},
		"truncated token":     {token[:len(token)/2], message, a.Roots()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(tc.token, tc.message, tc.roots); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify() = %v, want ErrInvalid", err)
			}
		})
	}
}

// A token stays valid after the authority's certificate expires: it is evidence about
// a moment, and the chain is checked at that moment, not at verification time.
func TestVerifyUsesTheStampedTime(t *testing.T) {
	now := time.Now()
	a, err := NewAuthority("Short-lived TSA", now.Add(-time.Hour), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("checkpoint stamped just before the certificate expired")
	token := stamp(t, a, message)

	time.Sleep(3 * time.Second) // the authority's certificate expires
	if _, err := a.cert.Verify(x509.VerifyOptions{Roots: a.Roots(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err == nil {
		t.Fatal("the certificate should have expired by now")
	}
	when, err := Verify(token, message, a.Roots())
	if err != nil {
		t.Fatalf("a token stamped while the certificate was valid must still verify: %v", err)
	}
	if time.Since(when) > time.Minute {
		t.Fatalf("stamped time %s is not recent", when)
	}
}

func TestTokenFile(t *testing.T) {
	a := authority(t, "Warden Local TSA")
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.jsonl")
	first, second := []byte("checkpoint one"), []byte("checkpoint two")
	for _, m := range [][]byte{first, second} {
		if err := AppendToken(path, m, stamp(t, a, m)); err != nil {
			t.Fatal(err)
		}
	}
	// A second authority also stamps the first checkpoint.
	if err := AppendToken(path, first, stamp(t, authority(t, "Second TSA"), first)); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := ReadTokens(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens[Digest(first)]) != 2 || len(tokens[Digest(second)]) != 1 {
		t.Fatalf("tokens: %d for the first, %d for the second", len(tokens[Digest(first)]), len(tokens[Digest(second)]))
	}
	if _, err := Verify(tokens[Digest(second)][0], second, a.Roots()); err != nil {
		t.Fatal(err)
	}
	// One of the two tokens for the first checkpoint is from the trusted authority.
	trusted := 0
	for _, token := range tokens[Digest(first)] {
		if _, err := Verify(token, first, a.Roots()); err == nil {
			trusted++
		}
	}
	if trusted != 1 {
		t.Fatalf("%d of 2 tokens verified against the first authority", trusted)
	}
}

func TestReadTokensRejects(t *testing.T) {
	for name, data := range map[string]string{
		"not json":      "{",
		"unknown field": `{"v":1,"message":"sha256:aa","token":"AA==","extra":true}`,
		"wrong version": `{"v":2,"message":"sha256:aa","token":"AA=="}`,
		"not base64":    `{"v":1,"message":"sha256:aa","token":"not base64!"}`,
		"empty token":   `{"v":1,"message":"sha256:aa","token":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadTokens(strings.NewReader(data)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	tokens, err := ReadTokens(strings.NewReader("\n\n"))
	if err != nil || len(tokens) != 0 {
		t.Fatalf("empty file: %v %v", tokens, err)
	}
}

func TestLoadRoots(t *testing.T) {
	a := authority(t, "Warden Local TSA")
	dir := t.TempDir()
	path := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(path, a.RootPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadRoots(path)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("checkpoint")
	if _, err := Verify(stamp(t, a, message), message, pool); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoots(path); err == nil {
		t.Fatal("accepted a file with no certificates")
	}
}
