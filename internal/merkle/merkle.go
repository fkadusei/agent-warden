// Package merkle implements the Merkle tree hash, inclusion proofs, and
// inclusion proof verification from RFC 9162 (Certificate Transparency 2.0),
// section 2.1. The hashing is the same as RFC 6962.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/fkadusei/agent-warden/internal/digest"
)

// Hash is a SHA-256 tree node or leaf hash.
type Hash = [sha256.Size]byte

// ErrInvalidProof is returned when an inclusion proof does not verify.
var ErrInvalidProof = errors.New("merkle: invalid inclusion proof")

// LeafHash is SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return Hash(h.Sum(nil))
}

// nodeHash is SHA-256(0x01 || left || right).
func nodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	return Hash(h.Sum(nil))
}

// EmptyRoot is the root of a tree with no leaves, SHA-256("").
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// Root computes the Merkle tree hash over leaf hashes.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	return mth(leaves)
}

func mth(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return nodeHash(mth(leaves[:k]), mth(leaves[k:]))
}

// split returns the largest power of two strictly less than n, for n > 1.
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// InclusionProof returns the audit path for leaf index m in the tree over
// leaves, ordered from the leaf level upward.
func InclusionProof(leaves []Hash, m int) ([]Hash, error) {
	if m < 0 || m >= len(leaves) {
		return nil, errors.New("merkle: leaf index out of range")
	}
	return path(m, leaves), nil
}

func path(m int, leaves []Hash) []Hash {
	if len(leaves) == 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(path(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), mth(leaves[:k]))
}

// VerifyInclusion checks that leaf is at index in a tree of size with the given
// root, following RFC 9162 section 2.1.3.2.
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	if index >= size {
		return ErrInvalidProof
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrInvalidProof
	}
	return nil
}

// Digest formats a hash in the receipt digest spelling, "sha256:<hex>".
func Digest(h Hash) string { return digest.Prefix + hex.EncodeToString(h[:]) }
