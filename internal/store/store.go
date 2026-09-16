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
CREATE TABLE IF NOT EXISTS statements (
	digest TEXT PRIMARY KEY,
	line   BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS openings (
	commitment TEXT PRIMARY KEY,
	salt       BLOB NOT NULL,
	value      BLOB NOT NULL
) STRICT;
`

// ErrNotFound is returned when a stored item does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrMismatch is returned when an existing store belongs to a different chain,
// or signs with a different key than the one it was opened with.
var ErrMismatch = errors.New("store: existing log does not match")

// Store is a durable receipt log for one chain. It is safe for concurrent use;
// appends are serialized.
type Store struct {
	db      *sql.DB
	chainID string

	// key and kid are the signing key now in use. Rotate advances them, so they
	// are guarded like the appender they sign through (ADR-0016).
	mu  sync.Mutex
	key *composite.PrivateKey
	kid string
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

	// meta holds three facts about the log. chain_id and kid are fixed for its
	// life: kid is the genesis key, hashed into the first receipt's prev, so it
	// names the chain as surely as chain_id does. current_kid is the key signing
	// now, which Rotate advances (ADR-0016). A log written before rotation
	// existed has no current_kid row, and its only key is the genesis key.
	get := func(k string) (string, bool, error) {
		var v string
		switch err := tx.QueryRowContext(ctx, "SELECT v FROM meta WHERE k = ?", k).Scan(&v); {
		case errors.Is(err, sql.ErrNoRows):
			return "", false, nil
		case err != nil:
			return "", false, fmt.Errorf("store: %w", err)
		}
		return v, true, nil
	}
	set := func(k, v string) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO meta (k, v) VALUES (?, ?)", k, v); err != nil {
			return fmt.Errorf("store: %w", err)
		}
		return nil
	}

	switch got, ok, err := get("chain_id"); {
	case err != nil:
		return err
	case !ok:
		if err := set("chain_id", s.chainID); err != nil {
			return err
		}
	case got != s.chainID:
		return fmt.Errorf("%w: chain_id is %q, want %q", ErrMismatch, got, s.chainID)
	}

	genesis, ok, err := get("kid")
	if err != nil {
		return err
	}
	if !ok {
		genesis = s.kid
		if err := set("kid", genesis); err != nil {
			return err
		}
	}
	current, ok, err := get("current_kid")
	if err != nil {
		return err
	}
	if !ok {
		current = genesis
		if err := set("current_kid", current); err != nil {
			return err
		}
	}
	if current != s.kid {
		return fmt.Errorf("%w: this log signs with %q, not %q", ErrMismatch, current, s.kid)
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
	// A handover changes which key signs, which must happen in the same
	// transaction as the receipt that announces it. Only Rotate does that.
	if r.Type == receipt.TypeKeyRotation {
		return nil, fmt.Errorf("store: use Rotate to append a %s receipt", receipt.TypeKeyRotation)
	}

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

// Rotate appends r, a key_rotation receipt, as the last receipt the outgoing key
// signs, and switches the log to next (ADR-0016). The receipt row and the record
// of which key signs now commit together, so a crash cannot leave the database
// claiming one key while the log has already handed over to another.
//
// On any error nothing is written, the chain does not advance, and the outgoing
// key keeps signing.
func (s *Store) Rotate(ctx context.Context, r *receipt.Receipt, next *composite.PrivateKey) (*Appended, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.Type != receipt.TypeKeyRotation || r.Rotation == nil {
		return nil, fmt.Errorf("store: Rotate needs a %s receipt", receipt.TypeKeyRotation)
	}
	if next == nil {
		return nil, errors.New("store: rotation needs the incoming private key")
	}
	if r.Rotation.From != s.kid {
		return nil, fmt.Errorf("%w: rotation hands over from %q but this log signs with %q",
			ErrMismatch, r.Rotation.From, s.kid)
	}
	// Refuse to hand over to a key we do not hold: every later receipt would be
	// signed by a key the log does not name, and none of them would verify.
	if got := digest.SHA256(next.Public().Bytes()); got != r.Rotation.Key {
		return nil, fmt.Errorf("%w: the incoming key hashes to %s but the rotation names %s",
			ErrMismatch, got, r.Rotation.Key)
	}

	// The outgoing key signs its own handover.
	before := s.app.State()
	signed, line, err := s.app.Append(r)
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) (*Appended, error) {
		if a, err := chain.ResumeAppender(s.key, s.kid, s.chainID, before); err == nil {
			s.app = a
		}
		return nil, fmt.Errorf("store: rotation not written: %w", cause)
	}

	hash := digest.SHA256(line)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rollback(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO receipts (seq, line, hash, ts) VALUES (?, ?, ?, ?)",
		before.Next, line, hash, r.TS); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE meta SET v = ? WHERE k = 'current_kid'", r.Rotation.To); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return rollback(err)
	}

	// Committed. From here the incoming key signs.
	app, err := chain.ResumeAppender(next, r.Rotation.To, s.chainID, s.app.State())
	if err != nil {
		return nil, fmt.Errorf("store: rotation is written but the log did not switch key: %w", err)
	}
	s.key, s.kid, s.app = next, r.Rotation.To, app
	return &Appended{Seq: before.Next, Hash: hash, Line: line, Signed: signed}, nil
}

// Next is the sequence number the next receipt will get.
func (s *Store) Next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.app.Next()
}

// Kid is the key ID signing this log now. Rotate advances it.
func (s *Store) Kid() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kid
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

// exported streams the log for a verifier to read.
func (s *Store) exported(ctx context.Context) *io.PipeReader {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.Export(ctx, pw)) }()
	return pr
}

// Verify re-reads the stored log and verifies it with chain.Verify. A log that
// has rotated its key needs VerifyWithKeys instead: chain.Verify has nothing to
// judge an incoming key against and fails closed.
func (s *Store) Verify(ctx context.Context, keys chain.KeyResolver) (*chain.Report, error) {
	pr := s.exported(ctx)
	defer pr.Close()
	return chain.Verify(pr, s.chainID, keys)
}

// VerifyWithKeys re-reads the stored log and verifies it, following any key
// rotations it records (ADR-0016).
func (s *Store) VerifyWithKeys(ctx context.Context, keys chain.Keys) (*chain.Report, error) {
	pr := s.exported(ctx)
	defer pr.Close()
	return chain.VerifyWithKeys(pr, s.chainID, keys, nil)
}

// SaveStatement durably stores an approver's signed statement, keyed by the
// digest of its line, so an approval receipt can later be proven against it
// without trusting Warden (ADR-0009). Saving the same statement twice is a no-op.
func (s *Store) SaveStatement(ctx context.Context, line []byte) (string, error) {
	signed, err := receipt.ParseLine(line)
	if err != nil {
		return "", fmt.Errorf("store: statement: %w", err)
	}
	canonicalLine, err := signed.Line()
	if err != nil {
		return "", err
	}
	d := digest.SHA256(canonicalLine)
	if _, err := s.db.ExecContext(ctx,
		"INSERT INTO statements (digest, line) VALUES (?, ?) ON CONFLICT(digest) DO NOTHING", d, canonicalLine); err != nil {
		return "", fmt.Errorf("store: statement: %w", err)
	}
	return d, nil
}

// Statement returns the stored statement line with digest d.
func (s *Store) Statement(ctx context.Context, d string) ([]byte, error) {
	var line []byte
	switch err := s.db.QueryRowContext(ctx, "SELECT line FROM statements WHERE digest = ?", d).Scan(&line); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("store: statement: %w", err)
	}
	if digest.SHA256(line) != d {
		return nil, fmt.Errorf("store: statement %s does not match its digest", d)
	}
	return line, nil
}

// SaveOpening stores the salt and canonical value behind a commitment
// (ADR-0005), so one call's arguments or result can be disclosed later without
// disclosing any other. The caller must have computed commitment from salt and
// value; Opening checks it again on the way out.
func (s *Store) SaveOpening(ctx context.Context, commitment string, salt, value []byte) error {
	if !digest.Valid(commitment) {
		return fmt.Errorf("store: opening: malformed commitment")
	}
	if _, err := s.db.ExecContext(ctx,
		"INSERT INTO openings (commitment, salt, value) VALUES (?, ?, ?) ON CONFLICT(commitment) DO NOTHING",
		commitment, salt, value); err != nil {
		return fmt.Errorf("store: opening: %w", err)
	}
	return nil
}

// Opening returns the salt and value stored for commitment.
func (s *Store) Opening(ctx context.Context, commitment string) (salt, value []byte, err error) {
	switch err := s.db.QueryRowContext(ctx, "SELECT salt, value FROM openings WHERE commitment = ?", commitment).Scan(&salt, &value); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil, ErrNotFound
	case err != nil:
		return nil, nil, fmt.Errorf("store: opening: %w", err)
	}
	return salt, value, nil
}

// ChainID is the chain this store holds.
func (s *Store) ChainID() string { return s.chainID }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
