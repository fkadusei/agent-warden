package revocation

import (
	"bytes"
	"crypto/mldsa"
	"testing"
)

func fuzzRoot(tb testing.TB) *mldsa.PrivateKey {
	tb.Helper()
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{9}, mldsa.PrivateKeySize))
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func fuzzRevocationLine(tb testing.TB, root *mldsa.PrivateKey) []byte {
	tb.Helper()
	s, err := Sign(root, rev(chainA, 12))
	if err != nil {
		tb.Fatal(err)
	}
	line, err := s.Line()
	if err != nil {
		tb.Fatal(err)
	}
	return line
}

// No line crashes the parser or the verifier; a line that parses re-encodes to
// exactly its bytes, and one that verifies is a valid revocation.
func FuzzRevocationLine(f *testing.F) {
	root := fuzzRoot(f)
	good := fuzzRevocationLine(f, root)
	f.Add(good)
	f.Add(append(bytes.Clone(good), '\n'))
	f.Add([]byte(`{"payload":"","protected":"","signature":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		s, err := ParseLine(line)
		if err == nil {
			if again, err := s.Line(); err != nil || !bytes.Equal(again, line) {
				t.Fatalf("parsed %q, which re-encodes as %q (%v)", line, again, err)
			}
			if r, err := Verify(root.PublicKey(), s); err == nil {
				if err := r.Validate(); err != nil {
					t.Fatalf("a verified revocation is invalid: %v", err)
				}
			}
		}
		ReadVerified(bytes.NewReader(line), chainA, root.PublicKey())
	})
}

// Changing any one byte of a signed revocation makes it fail to verify.
func FuzzTamperedRevocation(f *testing.F) {
	root := fuzzRoot(f)
	good := fuzzRevocationLine(f, root)
	f.Add(uint(0), byte('x'))
	f.Add(uint(len(good)/2), byte('A'))
	f.Add(uint(len(good)-3), byte('0'))
	f.Fuzz(func(t *testing.T, pos uint, b byte) {
		i := int(pos % uint(len(good)))
		if good[i] == b {
			return
		}
		bad := bytes.Clone(good)
		bad[i] = b
		s, err := ParseLine(bad)
		if err != nil {
			return
		}
		if _, err := Verify(root.PublicKey(), s); err == nil {
			t.Fatalf("byte %d changed from %q to %q, and the revocation still verifies", i, good[i], b)
		}
	})
}
