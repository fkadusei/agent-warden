// Package store is Warden's durable, write-ahead receipt log (ADR-0004).
//
// A receipt counts only once its row is committed to SQLite with
// synchronous=FULL. Append returns an error, and leaves the chain exactly where
// it was, if the write fails; the gateway must then refuse the tool call.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	_ "modernc.org/sqlite"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS receipts (
	seq  INTEGER PRIMARY KEY,
	line BLOB NOT NULL,
	hash TEXT NOT NULL,
	ts   TEXT NOT NULL
) STRICT;
`

// ErrMismatch is returned when an existing store belongs to a different chain
// or was written under a different key ID.
var ErrMismatch = errors.New("store: existing log does not match")

// Store is a durable receipt log for one chain. It is safe for concurrent use;
// appends are serialized.
type Store struct {
	db      *sql.DB
	key     *composite.PrivateKey
	kid     string
	chainID string

	mu  sync.Mutex
	app *chain.Appender
}

// Open opens or creates the log at path for chainID, signing with key under kid.
// Reopening an existing log resumes its chain.
func Open(path string, key *composite.PrivateKey, kid, chainID string) (*Store, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("store: unsupported path %q", path)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, key: key, kid: kid, chainID: chainID}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	var sync string
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync); err != nil || sync != "2" {
		return fmt.Errorf("store: synchronous is %q, want FULL (2): %v", sync, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer tx.Rollback()
	for k, want := range map[string]string{"chain_id": s.chainID, "kid": s.kid} {
		var got string
		switch err := tx.QueryRowContext(ctx, "SELECT v FROM meta WHERE k = ?", k).Scan(&got); {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx, "INSERT INTO meta (k, v) VALUES (?, ?)", k, want); err != nil {
				return fmt.Errorf("store: %w", err)
			}
		case err != nil:
			return fmt.Errorf("store: %w", err)
		case got != want:
			return fmt.Errorf("%w: %s is %q, want %q (key rotation is not supported yet)", ErrMismatch, k, got, want)
		}
	}

	var count int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM receipts").Scan(&count); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if count == 0 {
		s.app, err = chain.NewAppender(s.key, s.kid, s.chainID)
	} else {
		var st chain.State
		var last int64
		if err := tx.QueryRowContext(ctx, "SELECT seq, hash, ts FROM receipts ORDER BY seq DESC LIMIT 1").
			Scan(&last, &st.Prev, &st.LastTS); err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if last != count-1 {
			return fmt.Errorf("store: log has %d rows but last seq %d; rows are missing", count, last)
		}
		st.Next = count
		s.app, err = chain.ResumeAppender(s.key, s.kid, s.chainID, st)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Appended describes a receipt that was durably written.
type Appended struct {
	Seq    int64
	Hash   string
	Line   []byte
	Signed *receipt.Signed
}

// Append signs r as the next receipt in the chain and durably writes it. On any
// error nothing is written and the chain does not advance.
func (s *Store) Append(ctx context.Context, r *receipt.Receipt) (*Appended, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	before := s.app.State()
	signed, line, err := s.app.Append(r)
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) (*Appended, error) {
		if a, err := chain.ResumeAppender(s.key, s.kid, s.chainID, before); err == nil {
			s.app = a
		}
		return nil, fmt.Errorf("store: receipt not written: %w", cause)
	}

	hash := digest.SHA256(line)
	// The Appender signs a copy of r with only chain_id, seq, and prev filled
	// in, so r.TS is the signed timestamp.
	if _, err := s.db.ExecContext(ctx,
		"INSERT INTO receipts (seq, line, hash, ts) VALUES (?, ?, ?, ?)",
		before.Next, line, hash, r.TS); err != nil {
		return rollback(err)
	}
	return &Appended{Seq: before.Next, Hash: hash, Line: line, Signed: signed}, nil
}

// Next is the sequence number the next receipt will get.
func (s *Store) Next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.app.Next()
}

// Export writes the log, one line per receipt, in order.
func (s *Store) Export(ctx context.Context, w io.Writer) error {
	rows, err := s.db.QueryContext(ctx, "SELECT line FROM receipts ORDER BY seq")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var line []byte
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Verify re-reads the stored log and verifies it with chain.Verify.
func (s *Store) Verify(ctx context.Context, keys chain.KeyResolver) (*chain.Report, error) {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.Export(ctx, pw)) }()
	defer pr.Close()
	return chain.Verify(pr, s.chainID, keys)
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
