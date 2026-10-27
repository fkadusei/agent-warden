package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
)

// sealedSigner keeps its key to itself, as a hardware module would: callers get
// signatures and the public key, never the private key. It counts what it signs,
// and can be made to fail as an unreachable module would.
type sealedSigner struct {
	key   *composite.PrivateKey
	signs int
	fail  error
}

func (s *sealedSigner) Public() *composite.PublicKey { return s.key.Public() }

func (s *sealedSigner) Sign(msg []byte) ([]byte, error) {
	if s.fail != nil {
		return nil, s.fail
	}
	s.signs++
	return s.key.Sign(msg)
}

// A signer that is not a key file runs a whole chain: receipts, a rotation to a
// second such signer, and a checkpoint. Everything verifies, and every signature
// went through the signers.
func TestASignerThatIsNotAKeyFile(t *testing.T) {
	ctx := context.Background()
	ca := rotCA(t)
	first, second := &sealedSigner{key: newKey(t)}, &sealedSigner{key: newKey(t)}

	s, err := Open(filepath.Join(t.TempDir(), "receipts.db"), first, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range 3 {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}
	r := rotation(3, kid, kid2, second.key, epochFor(t, ca, kid2, second.key.Public()))
	if _, err := s.Rotate(ctx, r, second); err != nil {
		t.Fatal(err)
	}
	for i := 4; i < 6; i++ {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}

	// Three decisions and the handover by the first; the rest by the second.
	if first.signs != 4 || second.signs != 2 {
		t.Fatalf("first signed %d, second %d; want 4 and 2", first.signs, second.signs)
	}
	rep, err := s.VerifyWithKeys(ctx, trusting(t, first.key, ca))
	if err != nil {
		t.Fatalf("a log signed through the interface does not verify: %v", err)
	}
	if rep.Receipts != 6 || len(rep.Rotations) != 1 {
		t.Fatalf("report %+v", rep)
	}

	var buf bytes.Buffer
	if err := s.Export(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	b := checkpoint.NewBuilder(chainID)
	for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
		b.Add(line)
	}
	cp, err := b.Checkpoint(dec(6).TS)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := checkpoint.Sign(second, kid2, cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpoint.Verify(second.key.Public(), signed); err != nil {
		t.Fatalf("a checkpoint signed through the interface does not verify: %v", err)
	}
}

// A signer that cannot sign, as an unreachable hardware module cannot, stops the
// call: nothing is written, the chain does not advance, and it resumes cleanly.
func TestAnUnavailableSignerFailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := rotCA(t)
	sig := &sealedSigner{key: newKey(t)}
	s, err := Open(filepath.Join(t.TempDir(), "receipts.db"), sig, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range 2 {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}

	unreachable := errors.New("signing module unreachable")
	sig.fail = unreachable
	if _, err := s.Append(ctx, dec(2)); !errors.Is(err, unreachable) {
		t.Fatalf("append with an unavailable signer: got %v, want the signer's error", err)
	}
	next := &sealedSigner{key: newKey(t)}
	r := rotation(2, kid, kid2, next.key, epochFor(t, ca, kid2, next.key.Public()))
	if _, err := s.Rotate(ctx, r, next); !errors.Is(err, unreachable) {
		t.Fatalf("rotation with an unavailable signer: got %v, want the signer's error", err)
	}
	if s.Next() != 2 || s.Kid() != kid {
		t.Fatalf("a failed signature moved the chain: next %d, kid %q", s.Next(), s.Kid())
	}

	sig.fail = nil
	if a, err := s.Append(ctx, dec(2)); err != nil || a.Seq != 2 {
		t.Fatalf("after the signer came back: %+v, %v", a, err)
	}
	if rep, err := s.Verify(ctx, keysFor(sig.key)); err != nil || rep.Receipts != 3 {
		t.Fatalf("log after the outage: %+v, %v", rep, err)
	}
}

// A write that fails after a rotation resumes under the incoming signer, not the
// one that handed over: recovery must not bring a retired key back.
func TestAFailedWriteAfterARotationKeepsTheIncomingSigner(t *testing.T) {
	ctx := context.Background()
	ca := rotCA(t)
	first, second := &sealedSigner{key: newKey(t)}, &sealedSigner{key: newKey(t)}
	s, err := Open(filepath.Join(t.TempDir(), "receipts.db"), first, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Append(ctx, dec(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(ctx, rotation(1, kid, kid2, second.key, epochFor(t, ca, kid2, second.key.Public())), second); err != nil {
		t.Fatal(err)
	}

	if _, err := s.db.ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, dec(2)); err == nil {
		t.Fatal("append succeeded on a read-only database")
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, dec(2)); err != nil {
		t.Fatal(err)
	}

	if first.signs != 2 {
		t.Fatalf("the retired signer signed %d times, want 2 (a decision and its handover)", first.signs)
	}
	if _, err := s.VerifyWithKeys(ctx, trusting(t, first.key, ca)); err != nil {
		t.Fatalf("log after recovering from a failed write: %v", err)
	}
}
