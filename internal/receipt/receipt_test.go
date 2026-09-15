package receipt

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
)

var (
	d1 = digest.SHA256([]byte("one"))
	d2 = digest.SHA256([]byte("two"))
	d3 = digest.SHA256([]byte("three"))
)

func decision(seq int64) *Receipt {
	return &Receipt{
		V:       Version,
		Domain:  Domain,
		ChainID: "01J9Z3CHAIN",
		Seq:     seq,
		Prev:    d1,
		TS:      "2026-09-14T15:04:05.123Z",
		Type:    TypeDecision,
		TaskID:  "01J9Z4TASK",
		Actor:   &Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		Call:    &Call{Tool: "payments.refund", Manifest: d2, ArgsCommitment: d3},
		Decision: &Decision{
			Result:         RequireApproval,
			PolicyRevision: d1,
			Rule:           "refund_over_limit",
			Taint:          []string{"web:example.org"},
		},
	}
}

func result(seq, decisionSeq int64) *Receipt {
	r := decision(seq)
	r.Type = TypeResult
	r.Decision = nil
	r.Result = &Result{DecisionSeq: decisionSeq, Status: StatusOK, ResultCommitment: d2}
	return r
}

func newKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k := newKey(t)
	for _, r := range []*Receipt{decision(7), result(8, 7)} {
		t.Run(string(r.Type), func(t *testing.T) {
			s, err := Sign(k, "warden-2026-09-e1", r)
			if err != nil {
				t.Fatal(err)
			}
			line, err := s.Line()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseLine(line)
			if err != nil {
				t.Fatal(err)
			}
			kid, err := parsed.KeyID()
			if err != nil || kid != "warden-2026-09-e1" {
				t.Fatalf("KeyID = %q, %v", kid, err)
			}
			got, err := Verify(k.Public(), parsed)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, r) {
				t.Fatalf("round trip changed the receipt:\n got %+v\nwant %+v", got, r)
			}
			h1, _ := s.Hash()
			h2, _ := parsed.Hash()
			if h1 != h2 || !digest.Valid(h1) {
				t.Fatalf("hash not stable: %s vs %s", h1, h2)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(r *Receipt){
		"wrong version":             func(r *Receipt) { r.V = 2 },
		"wrong domain":              func(r *Receipt) { r.Domain = "other" },
		"empty chain_id":            func(r *Receipt) { r.ChainID = "" },
		"negative seq":              func(r *Receipt) { r.Seq = -1 },
		"seq above MaxSeq":          func(r *Receipt) { r.Seq = MaxSeq + 1 },
		"prev uppercase hex":        func(r *Receipt) { r.Prev = strings.ToUpper(r.Prev) },
		"prev wrong prefix":         func(r *Receipt) { r.Prev = "sha1:" + r.Prev[len(digest.Prefix):] },
		"ts without milliseconds":   func(r *Receipt) { r.TS = "2026-09-14T15:04:05Z" },
		"ts with offset":            func(r *Receipt) { r.TS = "2026-09-14T15:04:05.123+01:00" },
		"missing actor":             func(r *Receipt) { r.Actor = nil },
		"control char in principal": func(r *Receipt) { r.Actor.Principal = "alice\n" },
		"missing call":              func(r *Receipt) { r.Call = nil },
		"bad manifest digest":       func(r *Receipt) { r.Call.Manifest = "abc" },
		"missing decision":          func(r *Receipt) { r.Decision = nil },
		"unknown decision result":   func(r *Receipt) { r.Decision.Result = "maybe" },
		"decision with result":      func(r *Receipt) { r.Result = &Result{Status: StatusError} },
		"empty taint entry":         func(r *Receipt) { r.Decision.Taint = []string{""} },
		"unknown type":              func(r *Receipt) { r.Type = "note" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := decision(7)
			mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}

	resultCases := map[string]func(r *Receipt){
		"decision_seq not before seq": func(r *Receipt) { r.Result.DecisionSeq = r.Seq },
		"ok without commitment":       func(r *Receipt) { r.Result.ResultCommitment = "" },
		"unknown status":              func(r *Receipt) { r.Result.Status = "partial" },
		"result with decision":        func(r *Receipt) { r.Decision = decision(0).Decision },
	}
	for name, mutate := range resultCases {
		t.Run(name, func(t *testing.T) {
			r := result(8, 7)
			mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}

	t.Run("unspecified types are refused, not accepted", func(t *testing.T) {
		for _, typ := range []Type{TypeApproval, TypeKeyRotation, TypeCheckpoint} {
			r := decision(7)
			r.Type = typ
			if err := r.Validate(); !errors.Is(err, ErrUnsupportedType) {
				t.Errorf("%s: got %v, want ErrUnsupportedType", typ, err)
			}
		}
	})
}

func TestSignRefusesInvalidReceipt(t *testing.T) {
	r := decision(7)
	r.Call = nil
	if _, err := Sign(newKey(t), "k1", r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

// signRaw builds a validly signed envelope around arbitrary header and payload
// bytes, to prove that Verify rejects bad content even when the signature is good.
func signRaw(t *testing.T, k *composite.PrivateKey, hdr, payload string) *Signed {
	t.Helper()
	s := &Signed{Payload: b64.EncodeToString([]byte(payload)), Protected: b64.EncodeToString([]byte(hdr))}
	sig, err := k.Sign(s.signingInput())
	if err != nil {
		t.Fatal(err)
	}
	s.Signature = b64.EncodeToString(sig)
	return s
}

const goodHeader = `{"alg":"ML-DSA-65-Ed25519","alg_ref":"draft-ietf-jose-pq-composite-sigs-04","crit":["alg_ref"],"kid":"k1"}`

func TestVerifyRejects(t *testing.T) {
	k := newKey(t)
	good, err := Sign(k, "k1", decision(7))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := b64.DecodeString(good.Payload)
	p := string(payload)

	other, err := Sign(k, "k1", decision(8))
	if err != nil {
		t.Fatal(err)
	}

	expectErr := func(t *testing.T, s *Signed, want error) {
		t.Helper()
		if _, err := Verify(k.Public(), s); !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	}

	t.Run("payload swapped from another receipt", func(t *testing.T) {
		s := *good
		s.Payload = other.Payload
		expectErr(t, &s, ErrBadSignature)
	})
	t.Run("signature from another receipt", func(t *testing.T) {
		s := *good
		s.Signature = other.Signature
		expectErr(t, &s, ErrBadSignature)
	})
	t.Run("signed by a different key", func(t *testing.T) {
		s, err := Sign(newKey(t), "k1", decision(7))
		if err != nil {
			t.Fatal(err)
		}
		expectErr(t, s, ErrBadSignature)
	})
	t.Run("kid changed after signing", func(t *testing.T) {
		s := *good
		s.Protected = b64.EncodeToString([]byte(strings.Replace(goodHeader, `"k1"`, `"k2"`, 1)))
		expectErr(t, &s, ErrBadSignature)
	})

	headerCases := map[string]string{
		"wrong alg":            strings.Replace(goodHeader, "ML-DSA-65-Ed25519", "ML-DSA-65", 1),
		"wrong alg_ref":        strings.Replace(goodHeader, "-04", "-05", 1),
		"crit missing":         `{"alg":"ML-DSA-65-Ed25519","alg_ref":"draft-ietf-jose-pq-composite-sigs-04","kid":"k1"}`,
		"crit wrong":           strings.Replace(goodHeader, `["alg_ref"]`, `["kid"]`, 1),
		"extra header field":   `{"alg":"ML-DSA-65-Ed25519","alg_ref":"draft-ietf-jose-pq-composite-sigs-04","crit":["alg_ref"],"kid":"k1","x5u":"https://evil.example"}`,
		"empty kid":            strings.Replace(goodHeader, `"k1"`, `""`, 1),
		"non-canonical header": strings.Replace(goodHeader, `,"kid"`, `, "kid"`, 1),
	}
	for name, hdr := range headerCases {
		t.Run("validly signed, "+name, func(t *testing.T) {
			expectErr(t, signRaw(t, k, hdr, p), ErrMalformed)
		})
	}

	payloadCases := map[string]string{
		"non-canonical payload": strings.Replace(p, `"seq":7`, `"seq": 7`, 1),
		"unknown field":         strings.Replace(p, `"seq":7`, `"note":"hi","seq":7`, 1),
		"missing prev":          strings.Replace(p, `"prev":"`+d1+`",`, "", 1),
		"empty taint array":     strings.Replace(p, `,"taint":["web:example.org"]`, `,"taint":[]`, 1),
		"seq above 2^53":        strings.Replace(p, `"seq":7`, `"seq":9007199254740993`, 1),
		"duplicate key":         strings.Replace(p, `"seq":7`, `"seq":7,"seq":8`, 1),
	}
	for name, bad := range payloadCases {
		t.Run("validly signed, "+name, func(t *testing.T) {
			if bad == p {
				t.Fatal("test mutation did not apply")
			}
			expectErr(t, signRaw(t, k, goodHeader, bad), ErrMalformed)
		})
	}

	t.Run("validly signed, invalid receipt", func(t *testing.T) {
		bad := strings.Replace(p, `"result":"require_approval"`, `"result":"maybe"`, 1)
		expectErr(t, signRaw(t, k, goodHeader, bad), ErrInvalid)
	})

	t.Run("padded base64", func(t *testing.T) {
		s := *good
		s.Payload += "="
		expectErr(t, &s, ErrBadSignature)
	})
}

func TestParseLineRejects(t *testing.T) {
	k := newKey(t)
	s, err := Sign(k, "k1", decision(7))
	if err != nil {
		t.Fatal(err)
	}
	line, _ := s.Line()
	l := string(line)
	cases := map[string]string{
		"whitespace":    strings.Replace(l, `{"payload"`, `{ "payload"`, 1),
		"unknown field": strings.Replace(l, `{"payload"`, `{"header":{},"payload"`, 1),
		"missing field": `{"payload":"` + s.Payload + `","protected":"` + s.Protected + `"}`,
		"trailing data": l + "\n",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLine([]byte(bad)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
}
