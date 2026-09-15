package checkpoint

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// Anchor publishes signed checkpoints outside Warden's control.
type Anchor interface {
	Publish(s *receipt.Signed) error
}

// FileAnchor appends signed checkpoints to a file, one line each, and syncs
// every write.
//
// It only ever appends; it cannot make the file write-once. That guarantee must
// come from where the file lives: an append-only filesystem flag, WORM object
// storage, or an account Warden's operator does not control.
type FileAnchor struct {
	Path string
}

// Publish appends s to the anchor file.
func (a FileAnchor) Publish(s *receipt.Signed) error {
	line, err := s.Line()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("checkpoint: anchor: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("checkpoint: anchor: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("checkpoint: anchor: %w", err)
	}
	return f.Close()
}

// ErrAnchorOrder is returned when anchored checkpoints do not grow in size and
// time, which means the anchor itself was reordered or tampered with.
var ErrAnchorOrder = errors.New("checkpoint: anchored checkpoints out of order")

// ReadVerified reads anchored checkpoints, verifies each signature, and checks
// that every checkpoint belongs to chainID and that sizes strictly increase and
// timestamps never decrease. keys resolves a key ID to a trusted key.
func ReadVerified(r io.Reader, chainID string, keys func(kid string) (*composite.PublicKey, error)) ([]*Checkpoint, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []*Checkpoint
	for n := 1; sc.Scan(); n++ {
		s, err := receipt.ParseLine(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("checkpoint: anchor line %d: %w", n, err)
		}
		kid, err := s.KeyID()
		if err != nil {
			return nil, fmt.Errorf("checkpoint: anchor line %d: %w", n, err)
		}
		pub, err := keys(kid)
		if err != nil || pub == nil {
			return nil, fmt.Errorf("checkpoint: anchor line %d: unknown key %q", n, kid)
		}
		c, err := Verify(pub, s)
		if err != nil {
			return nil, fmt.Errorf("checkpoint: anchor line %d: %w", n, err)
		}
		if c.ChainID != chainID {
			return nil, fmt.Errorf("checkpoint: anchor line %d: chain_id %q, want %q", n, c.ChainID, chainID)
		}
		if len(out) > 0 {
			last := out[len(out)-1]
			if c.Size <= last.Size || c.TS < last.TS {
				return nil, fmt.Errorf("%w: line %d", ErrAnchorOrder, n)
			}
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("checkpoint: anchor: %w", err)
	}
	return out, nil
}
