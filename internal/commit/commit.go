// Package commit creates and checks salted commitments to tool arguments and
// results (ADR-0005).
//
// A commitment is SHA-256(salt || JCS(value)) with a fresh 32-byte salt. Receipts
// carry only the commitment; the value and salt are stored separately and
// disclosed selectively. The salt stops anyone from confirming a guessed
// low-entropy value (an amount, a short ID) from the receipt alone.
package commit

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/digest"
)

// SaltSize is the size of a commitment salt in bytes.
const SaltSize = 32

// ErrMismatch is returned when a disclosed value and salt do not match a commitment.
var ErrMismatch = errors.New("commit: value does not match commitment")

// New commits to value with a fresh random salt.
func New(value any) (commitment string, salt []byte, err error) {
	salt = make([]byte, SaltSize)
	rand.Read(salt)
	commitment, err = Compute(salt, value)
	if err != nil {
		return "", nil, err
	}
	return commitment, salt, nil
}

// Compute returns the commitment to value under salt.
func Compute(salt []byte, value any) (string, error) {
	if len(salt) != SaltSize {
		return "", fmt.Errorf("commit: salt must be %d bytes, got %d", SaltSize, len(salt))
	}
	c, err := canonical.Encode(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(append(append(make([]byte, 0, len(salt)+len(c)), salt...), c...)), nil
}

// Verify checks that value and salt open commitment.
func Verify(commitment string, salt []byte, value any) error {
	if !digest.Valid(commitment) {
		return fmt.Errorf("commit: malformed commitment")
	}
	got, err := Compute(salt, value)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(commitment)) != 1 {
		return ErrMismatch
	}
	return nil
}
