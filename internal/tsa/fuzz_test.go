package tsa

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

// No token file crashes ReadTokens.
func FuzzReadTokens(f *testing.F) {
	f.Add([]byte(`{"v":1,"message":"sha256:00","token":"AA=="}`))
	f.Add([]byte("\n\n"))
	f.Add([]byte(`{"v":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ReadTokens(bytes.NewReader(data))
	})
}

// No token crashes Verify, which parses CMS with the two unreleased digitorus
// modules; a panic there would take warden-verify down with it.
func FuzzVerifyToken(f *testing.F) {
	now := time.Now()
	a, err := NewAuthority("Fuzz TSA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		f.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	f.Cleanup(srv.Close)
	msg := []byte("an anchored checkpoint line")
	token, err := (&Client{URL: srv.URL}).Stamp(context.Background(), msg)
	if err != nil {
		f.Fatal(err)
	}
	roots := a.Roots()
	f.Add(token)
	f.Add(token[:len(token)/2])
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, tok []byte) {
		Verify(tok, msg, roots)
	})
}
