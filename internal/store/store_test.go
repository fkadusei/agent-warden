package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	chainID = "01J9Z3CHAIN"
	kid     = "warden-2026-09-e1"
)

var base = time.Date(2026, 9, 14, 15, 4, 5, 0, time.UTC)

func newKey(t *testing.T) *composite.PrivateKey {
	t.Helper()
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func dec(i int) *receipt.Receipt {
	tool := fmt.Sprintf("tool-%d", i)
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS:     base.Add(time.Duration(i) * time.Millisecond).Format(receipt.TimeFormat),
		Type:   receipt.TypeDecision,
		TaskID: "t1",
		Actor:  &receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		Call: &receipt.Call{Tool: tool, Manifest: digest.SHA256([]byte(tool)),
			ArgsCommitment: digest.SHA256([]byte{byte(i)})},
		Decision: &receipt.Decision{Result: receipt.Deny, PolicyRevision: digest.SHA256([]byte("p1"))},
	}
}

func keysFor(k *composite.PrivateKey) chain.KeyResolver {
	return func(id string) (*composite.PublicKey, error) {
		if id == kid {
			return k.Public(), nil
		}
		return nil, errors.New("unknown")
	}
}

func open(t *testing.T, path string, k *composite.PrivateKey) *Store {
	t.Helper()
	s, err := Open(path, k, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAppendExportVerify(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k)
	defer s.Close()

	for i := 0; i < 5; i++ {
		a, err := s.Append(ctx, dec(i))
		if err != nil {
			t.Fatal(err)
		}
		if a.Seq != int64(i) || a.Hash != digest.SHA256(a.Line) {
			t.Fatalf("append %d returned %+v", i, a)
		}
	}
	rep, err := s.Verify(ctx, keysFor(k))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Receipts != 5 || rep.LastSeq != 4 {
		t.Fatalf("unexpected report %+v", rep)
	}

	var buf bytes.Buffer
	if err := s.Export(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Verify(bytes.NewReader(buf.Bytes()), chainID, keysFor(k)); err != nil {
		t.Fatalf("exported log does not verify: %v", err)
	}
}

func TestReopenResumesChain(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	path := filepath.Join(t.TempDir(), "receipts.db")

	s := open(t, path, k)
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = open(t, path, k)
	defer s.Close()
	if s.Next() != 3 {
		t.Fatalf("reopened at seq %d, want 3", s.Next())
	}
	for i := 3; i < 5; i++ {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if rep, err := s.Verify(ctx, keysFor(k)); err != nil || rep.Receipts != 5 {
		t.Fatalf("resumed log: %+v, %v", rep, err)
	}

	t.Run("time regression across restart is refused", func(t *testing.T) {
		if _, err := s.Append(ctx, dec(0)); !errors.Is(err, chain.ErrTimeRegression) {
			t.Fatalf("got %v, want ErrTimeRegression", err)
		}
	})
}

func TestReopenRejectsMismatch(t *testing.T) {
	k := newKey(t)
	path := filepath.Join(t.TempDir(), "receipts.db")
	s := open(t, path, k)
	if _, err := s.Append(context.Background(), dec(0)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := Open(path, k, kid, "OTHER-CHAIN"); !errors.Is(err, ErrMismatch) {
		t.Errorf("other chain: got %v, want ErrMismatch", err)
	}
	if _, err := Open(path, k, "other-kid", chainID); !errors.Is(err, ErrMismatch) {
		t.Errorf("other kid: got %v, want ErrMismatch", err)
	}
}

// ADR-0004: a failed write must not advance the chain, and the log stays valid.
func TestFailedWriteDoesNotAdvance(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k)
	defer s.Close()

	for i := 0; i < 2; i++ {
		if _, err := s.Append(ctx, dec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, dec(2)); err == nil {
		t.Fatal("append succeeded on a read-only database")
	}
	if s.Next() != 2 {
		t.Fatalf("failed write advanced the chain to %d", s.Next())
	}

	if _, err := s.db.ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
		t.Fatal(err)
	}
	a, err := s.Append(ctx, dec(2))
	if err != nil {
		t.Fatal(err)
	}
	if a.Seq != 2 {
		t.Fatalf("seq %d after recovery, want 2", a.Seq)
	}
	if rep, err := s.Verify(ctx, keysFor(k)); err != nil || rep.Receipts != 3 {
		t.Fatalf("log after failed write: %+v, %v", rep, err)
	}
}

func TestInvalidReceiptIsNotWritten(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k)
	defer s.Close()

	bad := dec(0)
	bad.Call = nil
	if _, err := s.Append(ctx, bad); !errors.Is(err, receipt.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
	if s.Next() != 0 {
		t.Fatalf("invalid receipt advanced the chain to %d", s.Next())
	}
}

func TestConcurrentAppends(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k)
	defer s.Close()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := dec(i)
			r.TS = base.Format(receipt.TimeFormat) // equal timestamps are allowed
			if _, err := s.Append(ctx, r); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if rep, err := s.Verify(ctx, keysFor(k)); err != nil || rep.Receipts != n {
		t.Fatalf("concurrent log: %+v, %v", rep, err)
	}
}

func TestTamperedRowIsDetected(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	s := open(t, filepath.Join(t.TempDir(), "receipts.db"), k)
	defer s.Close()
	var lines [][]byte
	for i := 0; i < 3; i++ {
		a, err := s.Append(ctx, dec(i))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, a.Line)
	}
	// Someone with database access swaps row 1's line for row 2's.
	if _, err := s.db.ExecContext(ctx, "UPDATE receipts SET line = ? WHERE seq = 1", lines[2]); err != nil {
		t.Fatal(err)
	}
	_, err := s.Verify(ctx, keysFor(k))
	var f *chain.Failure
	if !errors.As(err, &f) || f.Line != 2 || f.Reason != chain.ReasonSeqGap {
		t.Fatalf("got %v, want seq_gap at line 2", err)
	}
}
