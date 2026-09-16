package receipt

import (
	"errors"
	"strings"
	"testing"
)

// rotation returns a valid key-rotation receipt at seq.
func rotation(seq int64) *Receipt {
	return &Receipt{
		V: Version, Domain: Domain, ChainID: "c1", Seq: seq,
		Prev: "sha256:" + strings.Repeat("ab", 32),
		TS:   "2026-09-16T15:04:05.123Z",
		Type: TypeKeyRotation,
		Rotation: &Rotation{
			From:        "warden-e1",
			To:          "warden-e2",
			Key:         "sha256:" + strings.Repeat("cd", 32),
			Certificate: "TUlJQ2VydGlmaWNhdGVEZXI",
			Reason:      "scheduled rotation",
		},
	}
}

// A key rotation receipt is now a specified type, not an unsupported one.
func TestRotationValidates(t *testing.T) {
	if err := rotation(7).Validate(); err != nil {
		t.Fatalf("a well-formed rotation was rejected: %v", err)
	}
	r := rotation(7)
	r.Rotation.Reason = ""
	if err := r.Validate(); err != nil {
		t.Fatalf("reason is optional: %v", err)
	}
	if errors.Is(rotation(7).Validate(), ErrUnsupportedType) {
		t.Fatal("key_rotation is still reported as unsupported")
	}
}

func TestRotationRejects(t *testing.T) {
	cases := map[string]func(r *Receipt){
		"missing rotation body":   func(r *Receipt) { r.Rotation = nil },
		"empty from":              func(r *Receipt) { r.Rotation.From = "" },
		"empty to":                func(r *Receipt) { r.Rotation.To = "" },
		"rotating to itself":      func(r *Receipt) { r.Rotation.To = r.Rotation.From },
		"key not a digest":        func(r *Receipt) { r.Rotation.Key = "abc" },
		"key uppercase hex":       func(r *Receipt) { r.Rotation.Key = "sha256:" + strings.Repeat("CD", 32) },
		"no certificate":          func(r *Receipt) { r.Rotation.Certificate = "" },
		"certificate not base64":  func(r *Receipt) { r.Rotation.Certificate = "not base64!" },
		"certificate padded":      func(r *Receipt) { r.Rotation.Certificate = "TUlJQ2VydGlmaWNhdGVEZXI=" },
		"certificate far too big": func(r *Receipt) { r.Rotation.Certificate = strings.Repeat("A", maxCertificate+1) },
		"control char in reason":  func(r *Receipt) { r.Rotation.Reason = "lost\nkey" },
		// A rotation is about the chain, not about a call.
		"carries a task":     func(r *Receipt) { r.TaskID = "t1" },
		"carries an actor":   func(r *Receipt) { r.Actor = &Actor{Agent: "a", Principal: "p"} },
		"carries a call":     func(r *Receipt) { r.Call = &Call{Tool: "crm/lookup"} },
		"carries a decision": func(r *Receipt) { r.Decision = &Decision{Result: Allow} },
		"carries a result":   func(r *Receipt) { r.Result = &Result{Status: StatusOK} },
		"carries an approval": func(r *Receipt) {
			r.Approval = &Approval{Outcome: Approved, Approver: "bob@tenant-a"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := rotation(7)
			mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

// A call receipt must not carry a rotation section: one receipt, one job.
func TestOtherTypesRejectARotationBody(t *testing.T) {
	r := decision(7)
	r.Rotation = &Rotation{From: "warden-e1", To: "warden-e2"}
	if err := r.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a decision carrying a rotation section: got %v, want ErrInvalid", err)
	}
}

func TestRotationSignVerifyRoundTrip(t *testing.T) {
	key := newKey(t)
	signed, err := Sign(key, "warden-e1", rotation(7))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(key.Public(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeKeyRotation || got.Rotation == nil {
		t.Fatalf("round trip lost the rotation: %+v", got)
	}
	if got.Rotation.To != "warden-e2" || got.Rotation.Certificate != rotation(7).Rotation.Certificate {
		t.Fatalf("rotation body changed: %+v", got.Rotation)
	}
	// The outgoing key signs the handover.
	kid, err := signed.KeyID()
	if err != nil || kid != "warden-e1" {
		t.Fatalf("kid %q (%v), want the outgoing key", kid, err)
	}
}
