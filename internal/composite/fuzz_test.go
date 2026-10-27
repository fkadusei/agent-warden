package composite

import (
	"bytes"
	"testing"
)

// No signature verifies over a message that was never signed.
//
// ML-DSA signing is randomized, so two valid signatures over the same message
// differ; this target cannot tell a malleated signature from a second honest one,
// and checks only that nothing verifies over any other message.
func FuzzVerify(f *testing.F) {
	k, err := MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{7}, SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	msg := []byte("agent-warden fuzz: the only message ever signed")
	sig, err := k.Sign(msg)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(msg, sig)
	f.Add(msg, sig[:len(sig)-1])
	f.Add([]byte("another message"), sig)
	f.Add([]byte{}, []byte{})
	pub := k.Public()
	f.Fuzz(func(t *testing.T, m, s []byte) {
		if pub.Verify(m, s) == nil && !bytes.Equal(m, msg) {
			t.Fatalf("a signature verified over a message that was never signed: %q", m)
		}
	})
}
