package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// ErrConflict is returned when a checkpoint's name already holds different
// bytes: a second checkpoint of the same size, which is a fork.
var ErrConflict = errors.New("s3: anchored object holds a different checkpoint")

var (
	safeChainID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	safePrefix  = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

// ValidName reports whether chainID and prefix can name objects safely: no
// empty or dot-only segments, nothing that needs escaping.
func ValidName(prefix, chainID string) error {
	if !safeChainID.MatchString(chainID) || chainID == "." || chainID == ".." {
		return fmt.Errorf("s3: chain ID %q needs to be letters, digits, '.', '_' or '-' to name objects", chainID)
	}
	if prefix != "" {
		if !safePrefix.MatchString(prefix) {
			return fmt.Errorf("s3: prefix %q needs segments of letters, digits, '.', '_' or '-' separated by '/'", prefix)
		}
		for _, seg := range strings.Split(prefix, "/") {
			if seg == "." || seg == ".." {
				return fmt.Errorf("s3: prefix %q has a dot segment", prefix)
			}
		}
	}
	return nil
}

// ChainPrefix is where a chain's checkpoints live: "<prefix>/<chain_id>/".
func ChainPrefix(prefix, chainID string) string {
	if prefix == "" {
		return chainID + "/"
	}
	return prefix + "/" + chainID + "/"
}

// ObjectName names the checkpoint covering size receipts. Sizes are padded to
// 20 digits so names sort in log order.
func ObjectName(prefix, chainID string, size int64) string {
	return fmt.Sprintf("%s%020d.json", ChainPrefix(prefix, chainID), size)
}

// Anchor publishes checkpoints to an object store with Object Lock in
// compliance mode (ADR-0017). Each object holds exactly the signed checkpoint
// line that the file anchor writes.
type Anchor struct {
	Client    *Client
	Prefix    string
	ChainID   string
	Retention time.Duration
}

var _ checkpoint.Anchor = (*Anchor)(nil)

// Publish stores s under the name for c's size, locked until now plus the
// retention. A retry after a lost response is safe: the write is conditional,
// and a name that already holds exactly these bytes counts as published.
func (a *Anchor) Publish(ctx context.Context, c *checkpoint.Checkpoint, s *receipt.Signed) error {
	if c == nil || s == nil {
		return errors.New("s3: nothing to anchor")
	}
	if c.ChainID != a.ChainID {
		return fmt.Errorf("s3: checkpoint for chain %q, anchor is for %q", c.ChainID, a.ChainID)
	}
	if a.Retention <= 0 {
		return errors.New("s3: anchor retention must be positive")
	}
	line, err := s.Line()
	if err != nil {
		return err
	}
	name := ObjectName(a.Prefix, a.ChainID, c.Size)
	_, err = a.Client.PutLocked(ctx, name, line, a.Client.now().Add(a.Retention))
	if !errors.Is(err, ErrExists) {
		return err
	}
	got, gerr := a.Client.Get(ctx, name, "")
	if gerr != nil {
		return fmt.Errorf("s3: %s exists and could not be read back: %w", name, gerr)
	}
	if !bytes.Equal(got.Body, line) {
		return fmt.Errorf("%w: %s", ErrConflict, name)
	}
	return nil
}
