package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

func TestStatements(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	path := filepath.Join(t.TempDir(), "receipts.db")
	s := open(t, path, k)

	signed, err := receipt.SignPayload(k, "bob@tenant-a", []byte(`{"domain":"test-statement"}`))
	if err != nil {
		t.Fatal(err)
	}
	line, err := signed.Line()
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.SaveStatement(ctx, line)
	if err != nil {
		t.Fatal(err)
	}
	if d != digest.SHA256(line) {
		t.Fatalf("digest %s, want digest of the line", d)
	}
	if again, err := s.SaveStatement(ctx, line); err != nil || again != d {
		t.Fatalf("saving twice: %s, %v", again, err)
	}

	// Survives a restart.
	s.Close()
	s = open(t, path, k)
	defer s.Close()
	got, err := s.Statement(ctx, d)
	if err != nil || string(got) != string(line) {
		t.Fatalf("stored statement: %q, %v", got, err)
	}

	if _, err := s.Statement(ctx, digest.SHA256([]byte("missing"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing statement: got %v, want ErrNotFound", err)
	}
	if _, err := s.SaveStatement(ctx, []byte(`{"not":"an envelope"}`)); err == nil {
		t.Fatal("malformed statement stored")
	}

	t.Run("tampered row is refused", func(t *testing.T) {
		if _, err := s.db.ExecContext(ctx, "UPDATE statements SET line = ? WHERE digest = ?", []byte(`{}`), d); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Statement(ctx, d); err == nil {
			t.Fatal("tampered statement returned")
		}
	})
}
