// Package canonical produces and checks RFC 8785 (JCS) canonical JSON.
//
// It wraps github.com/gowebpki/jcs and adds what that library leaves to the
// caller: rejecting invalid UTF-8, and a strict Check that accepts input only if
// it is already byte-for-byte canonical.
//
// JCS serializes numbers as IEEE 754 doubles, so integers above 2^53-1 lose
// precision. Callers must keep integers within MaxSafeInteger; Check rejects
// input whose numbers change when canonicalized.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// MaxSafeInteger is the largest integer JCS can represent exactly (2^53 - 1).
const MaxSafeInteger = 1<<53 - 1

// ErrNotCanonical is returned by Check for valid JSON that is not in canonical form.
var ErrNotCanonical = errors.New("canonical: JSON is not in RFC 8785 canonical form")

// Transform canonicalizes JSON text.
func Transform(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("canonical: invalid UTF-8")
	}
	out, err := jcs.Transform(b)
	if err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	return out, nil
}

// Encode marshals v to JSON and canonicalizes it.
func Encode(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	return Transform(b)
}

// Check returns nil only if b is valid JSON already in canonical form.
func Check(b []byte) error {
	out, err := Transform(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(out, b) {
		return ErrNotCanonical
	}
	return nil
}
