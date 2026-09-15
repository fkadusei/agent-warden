package commit

import (
	"bytes"
	"errors"
	"testing"
)

func TestCommitAndOpen(t *testing.T) {
	args := map[string]any{"customer": "c-100", "amount": 500}
	c, salt, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(c, salt, args); err != nil {
		t.Fatalf("opening failed: %v", err)
	}

	// Key order does not matter: the value is canonicalized first.
	reordered := map[string]any{"amount": 500, "customer": "c-100"}
	if err := Verify(c, salt, reordered); err != nil {
		t.Fatalf("reordered value rejected: %v", err)
	}
}

func TestRejectsWrongOpening(t *testing.T) {
	args := map[string]any{"amount": 500}
	c, salt, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	otherSalt := bytes.Clone(salt)
	otherSalt[0] ^= 1

	if err := Verify(c, salt, map[string]any{"amount": 501}); !errors.Is(err, ErrMismatch) {
		t.Errorf("different value: got %v, want ErrMismatch", err)
	}
	if err := Verify(c, otherSalt, args); !errors.Is(err, ErrMismatch) {
		t.Errorf("different salt: got %v, want ErrMismatch", err)
	}
	if err := Verify(c, salt[:SaltSize-1], args); err == nil {
		t.Error("short salt accepted")
	}
	if err := Verify("sha256:XYZ", salt, args); err == nil {
		t.Error("malformed commitment accepted")
	}
}

func TestSaltHidesEqualValues(t *testing.T) {
	c1, _, err := New("same")
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := New("same")
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Fatal("two commitments to the same value are equal; salts are not fresh")
	}
}
