// Package digest formats and validates the "sha256:<hex>" digests used
// throughout receipts.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Prefix identifies the hash algorithm in a digest string.
const Prefix = "sha256:"

// SHA256 returns the digest string for b.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return Prefix + hex.EncodeToString(sum[:])
}

// Valid reports whether s is a well-formed digest: the prefix followed by
// exactly 64 lowercase hexadecimal characters. Only one spelling of a digest is
// accepted, so equal digests are always equal strings.
func Valid(s string) bool {
	h, ok := strings.CutPrefix(s, Prefix)
	if !ok || len(h) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
