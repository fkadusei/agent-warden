package revocation

import (
	"bytes"
	"crypto/mldsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/identity"
)

const (
	chainA = "01J9Z3CHAINA"
	chainB = "01J9Z3CHAINB"
	kid    = "warden-2026-09-e1"
)

var now = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func rootKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rev(chainID string, size int64) *Revocation {
	return &Revocation{
		V: Version, Domain: Domain, ChainID: chainID, Kid: kid,
		EffectiveSize: size,
		EffectiveHead: digest.SHA256([]byte("head")),
		Reason:        "signing key compromised",
		TS:            now.Format("2006-01-02T15:04:05.000Z"),
	}
}

func signed(t *testing.T, root *mldsa.PrivateKey, r *Revocation) *Signed {
	t.Helper()
	s, err := Sign(root, r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	root := rootKey(t)
	s := signed(t, root, rev(chainA, 12))

	got, err := Verify(root.PublicKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kid != kid || got.EffectiveSize != 12 || got.ChainID != chainA {
		t.Fatalf("round trip changed the revocation: %+v", got)
	}
	if got.Reason != "signing key compromised" {
		t.Fatalf("reason lost: %q", got.Reason)
	}

	// It survives the line encoding it is published in.
	line, err := s.Line()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root.PublicKey(), parsed); err != nil {
		t.Fatalf("a published revocation does not verify: %v", err)
	}
}

// signRaw builds a validly signed envelope around arbitrary header and payload
// bytes, to prove Verify rejects bad content even when the signature is good.
func signRaw(t *testing.T, root *mldsa.PrivateKey, hdr, payload string) *Signed {
	t.Helper()
	s := &Signed{Payload: b64.EncodeToString([]byte(payload)), Protected: b64.EncodeToString([]byte(hdr))}
	sig, err := root.Sign(nil, s.signingInput(), &mldsa.Options{Context: context})
	if err != nil {
		t.Fatal(err)
	}
	s.Signature = b64.EncodeToString(sig)
	return s
}

func TestVerifyRejects(t *testing.T) {
	root := rootKey(t)
	good := signed(t, root, rev(chainA, 12))
	payload, _ := b64.DecodeString(good.Payload)
	p := string(payload)

	goodHeader := `{"alg":"ML-DSA-65","domain":"agent-warden/revocation/v1"}`

	t.Run("signed by another root", func(t *testing.T) {
		if _, err := Verify(rootKey(t).PublicKey(), good); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})
	t.Run("payload swapped after signing", func(t *testing.T) {
		s := *good
		s.Payload = signed(t, root, rev(chainA, 99)).Payload
		if _, err := Verify(root.PublicKey(), &s); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})
	t.Run("padded base64", func(t *testing.T) {
		s := *good
		s.Payload += "="
		if _, err := Verify(root.PublicKey(), &s); err == nil {
			t.Fatal("padded base64 accepted")
		}
	})
	t.Run("no root key", func(t *testing.T) {
		if _, err := Verify(nil, good); err == nil {
			t.Fatal("verified with no root")
		}
	})

	// A signature over a different context must not verify here, or a signature
	// the root made for another purpose could be replayed as a revocation.
	t.Run("signed with the wrong context", func(t *testing.T) {
		s := &Signed{Payload: good.Payload, Protected: good.Protected}
		sig, err := root.Sign(nil, s.signingInput(), &mldsa.Options{Context: "some-other-purpose"})
		if err != nil {
			t.Fatal(err)
		}
		s.Signature = b64.EncodeToString(sig)
		if _, err := Verify(root.PublicKey(), s); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})

	headers := map[string]string{
		"wrong alg":            `{"alg":"ML-DSA-65-Ed25519","domain":"agent-warden/revocation/v1"}`,
		"wrong domain":         `{"alg":"ML-DSA-65","domain":"agent-warden/checkpoint/v1"}`,
		"non-canonical header": `{"alg":"ML-DSA-65", "domain":"agent-warden/revocation/v1"}`,
		"unknown header field": `{"alg":"ML-DSA-65","domain":"agent-warden/revocation/v1","x5u":"https://evil.example"}`,
	}
	for name, hdr := range headers {
		t.Run("validly signed, "+name, func(t *testing.T) {
			if _, err := Verify(root.PublicKey(), signRaw(t, root, hdr, p)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}

	payloads := map[string]string{
		"non-canonical payload": strings.Replace(p, `"v":1`, `"v": 1`, 1),
		"unknown field":         strings.Replace(p, `"v":1`, `"note":"hi","v":1`, 1),
		"duplicate key":         strings.Replace(p, `"v":1`, `"v":1,"v":2`, 1),
	}
	for name, bad := range payloads {
		t.Run("validly signed, "+name, func(t *testing.T) {
			if bad == p {
				t.Fatal("test mutation did not apply")
			}
			if _, err := Verify(root.PublicKey(), signRaw(t, root, goodHeader, bad)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}

	t.Run("validly signed, invalid revocation", func(t *testing.T) {
		bad := strings.Replace(p, `"effective_size":12`, `"effective_size":0`, 1)
		if bad == p {
			t.Fatal("test mutation did not apply")
		}
		if _, err := Verify(root.PublicKey(), signRaw(t, root, goodHeader, bad)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(r *Revocation){
		"wrong version":          func(r *Revocation) { r.V = 2 },
		"wrong domain":           func(r *Revocation) { r.Domain = "agent-warden/receipt/v1" },
		"empty chain_id":         func(r *Revocation) { r.ChainID = "" },
		"empty kid":              func(r *Revocation) { r.Kid = "" },
		"control char in kid":    func(r *Revocation) { r.Kid = "e1\n" },
		"effective_size zero":    func(r *Revocation) { r.EffectiveSize = 0 },
		"negative size":          func(r *Revocation) { r.EffectiveSize = -1 },
		"size above MaxSafe":     func(r *Revocation) { r.EffectiveSize = canonical.MaxSafeInteger + 1 },
		"head not a digest":      func(r *Revocation) { r.EffectiveHead = "abc" },
		"head uppercase hex":     func(r *Revocation) { r.EffectiveHead = "sha256:" + strings.Repeat("AB", 32) },
		"control char in reason": func(r *Revocation) { r.Reason = "lost\nkey" },
		"ts without millis":      func(r *Revocation) { r.TS = "2026-09-16T12:00:00Z" },
		"ts with offset":         func(r *Revocation) { r.TS = "2026-09-16T12:00:00.000+01:00" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := rev(chainA, 12)
			mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}

	t.Run("reason is optional", func(t *testing.T) {
		r := rev(chainA, 12)
		r.Reason = ""
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("signing refuses an invalid revocation", func(t *testing.T) {
		r := rev(chainA, 0)
		if _, err := Sign(rootKey(t), r); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
}

func TestPublishAndReadVerified(t *testing.T) {
	root := rootKey(t)
	path := filepath.Join(t.TempDir(), "revocations.jsonl")

	for _, r := range []*Revocation{rev(chainA, 10), rev(chainB, 20), rev(chainA, 30)} {
		if err := Publish(path, signed(t, root, r)); err != nil {
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadVerified(bytes.NewReader(data), chainA, root.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// The other chain's revocation is skipped, not an error: one file may cover
	// several chains.
	if len(got) != 2 || got[0].EffectiveSize != 10 || got[1].EffectiveSize != 30 {
		t.Fatalf("read %d revocations: %+v", len(got), got)
	}

	t.Run("a line signed by another root is refused", func(t *testing.T) {
		forged := signed(t, rootKey(t), rev(chainA, 40))
		line, err := forged.Line()
		if err != nil {
			t.Fatal(err)
		}
		all := append(append([]byte{}, data...), append(line, '\n')...)
		if _, err := ReadVerified(bytes.NewReader(all), chainA, root.PublicKey()); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})
}

func TestRootKeyFromCertificate(t *testing.T) {
	k := rootKey(t)
	ca, err := identity.NewCA("Warden Revocation Test Root", k, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := RootKey(ca.Cert)
	if err != nil {
		t.Fatal(err)
	}
	// The key taken from the certificate verifies what the root key signed.
	if _, err := Verify(pub, signed(t, k, rev(chainA, 5))); err != nil {
		t.Fatalf("the certificate's key does not verify the root's signature: %v", err)
	}
	if _, err := RootKey(nil); err == nil {
		t.Fatal("RootKey(nil) succeeded")
	}
}
