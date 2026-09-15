package merkle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type vectors struct {
	LeafInputs []string `json:"leaf_inputs"`
	LeafHashes []string `json:"leaf_hashes"`
	RootHashes []string `json:"root_hashes"`
	EmptyRoot  string   `json:"empty_root"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "merkle", "transparency-dev.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.LeafInputs) != 8 || len(v.LeafHashes) != 8 || len(v.RootHashes) != 8 {
		t.Fatalf("unexpected vector counts %d/%d/%d", len(v.LeafInputs), len(v.LeafHashes), len(v.RootHashes))
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTransparencyDevVectors(t *testing.T) {
	v := load(t)
	var leaves []Hash
	for i, in := range v.LeafInputs {
		lh := LeafHash(unhex(t, in))
		if hex.EncodeToString(lh[:]) != v.LeafHashes[i] {
			t.Fatalf("leaf %d hash mismatch", i)
		}
		leaves = append(leaves, lh)
	}
	for n := 1; n <= 8; n++ {
		r := Root(leaves[:n])
		if hex.EncodeToString(r[:]) != v.RootHashes[n-1] {
			t.Fatalf("root of size %d mismatch", n)
		}
	}
	e := Root(nil)
	if hex.EncodeToString(e[:]) != v.EmptyRoot {
		t.Fatal("empty root mismatch")
	}
	// Every leaf of the vector tree proves inclusion against the published root.
	root := Hash(unhex(t, v.RootHashes[7]))
	for m := range leaves {
		p, err := InclusionProof(leaves, m)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(leaves[m], uint64(m), 8, p, root); err != nil {
			t.Fatalf("leaf %d: %v", m, err)
		}
	}
}

func leavesOf(n int) []Hash {
	l := make([]Hash, n)
	for i := range l {
		l[i] = LeafHash([]byte{byte(i), byte(i >> 8)})
	}
	return l
}

func TestInclusionProofsAllSizes(t *testing.T) {
	for n := 1; n <= 40; n++ {
		leaves := leavesOf(n)
		root := Root(leaves)
		for m := 0; m < n; m++ {
			p, err := InclusionProof(leaves, m)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(leaves[m], uint64(m), uint64(n), p, root); err != nil {
				t.Fatalf("n=%d m=%d: valid proof rejected", n, m)
			}
			reject := func(what string, leaf Hash, index, size uint64, proof []Hash, r Hash) {
				t.Helper()
				if err := VerifyInclusion(leaf, index, size, proof, r); !errors.Is(err, ErrInvalidProof) {
					t.Fatalf("n=%d m=%d: %s accepted", n, m, what)
				}
			}
			other := LeafHash([]byte("not in the tree"))
			reject("wrong leaf", other, uint64(m), uint64(n), p, root)
			reject("index out of range", leaves[m], uint64(n), uint64(n), p, root)
			reject("wrong root", leaves[m], uint64(m), uint64(n), p, other)
			reject("extra proof element", leaves[m], uint64(m), uint64(n), append(append([]Hash{}, p...), other), root)
			if n > 1 {
				reject("wrong index", leaves[m], uint64((m+1)%n), uint64(n), p, root)
				reject("truncated proof", leaves[m], uint64(m), uint64(n), p[:len(p)-1], root)
				bad := append([]Hash{}, p...)
				bad[0][0] ^= 1
				reject("altered proof element", leaves[m], uint64(m), uint64(n), bad, root)
				// No "larger size" case: for leaves on the left edge, a proof and
				// root can verify for more than one tree size under RFC 9162's
				// algorithm. The size is bound by signing it together with the root,
				// as checkpoints do.
			}
		}
	}
}

func TestInclusionProofIndexRange(t *testing.T) {
	leaves := leavesOf(3)
	for _, m := range []int{-1, 3} {
		if _, err := InclusionProof(leaves, m); err == nil {
			t.Fatalf("index %d accepted", m)
		}
	}
}
