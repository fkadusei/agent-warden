// Package checkpoint creates, signs, anchors, and verifies checkpoints
// (ADR-0003, design §4.4).
//
// A checkpoint commits to the first Size receipts of a chain: their Merkle root
// and the digest of the last covered line. Sent somewhere Warden's operator
// cannot rewrite, it lets a verifier detect truncation, rewrites, and forks of
// everything it covers, even by someone holding the signing key.
//
// Checkpoints are separate signed statements, not receipts in the chain. They
// use the same envelope and key as receipts, and their payload domain keeps the
// two from being confused (threat W14).
package checkpoint

import (
	"errors"
	"fmt"
	"time"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/merkle"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	// Version is the checkpoint format version.
	Version = 1
	// Domain separates checkpoints from receipts and other signed objects.
	Domain = "agent-warden/checkpoint/v1"
)

// ErrInvalid wraps every checkpoint validation failure.
var ErrInvalid = errors.New("checkpoint: invalid")

// Checkpoint commits to receipts 0 through Size-1 of a chain.
type Checkpoint struct {
	V       int    `json:"v"`
	Domain  string `json:"domain"`
	ChainID string `json:"chain_id"`
	// Size is the number of receipts covered.
	Size int64 `json:"size"`
	// Root is the RFC 9162 Merkle tree hash over the covered log lines.
	Root string `json:"root"`
	// Head is the digest of line Size-1: the prev the next receipt carries.
	Head string `json:"head"`
	TS   string `json:"ts"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Validate checks the checkpoint's fields.
func (c *Checkpoint) Validate() error {
	if c.V != Version {
		return invalid("v is %d, want %d", c.V, Version)
	}
	if c.Domain != Domain {
		return invalid("domain is %q", c.Domain)
	}
	if c.ChainID == "" || len(c.ChainID) > 256 {
		return invalid("chain_id must be 1-256 bytes")
	}
	for _, r := range c.ChainID {
		if r < 0x20 || r == 0x7f {
			return invalid("chain_id contains a control character")
		}
	}
	if c.Size < 1 || c.Size > canonical.MaxSafeInteger {
		return invalid("size %d out of range", c.Size)
	}
	if !digest.Valid(c.Root) {
		return invalid("root is not a sha256 digest")
	}
	if !digest.Valid(c.Head) {
		return invalid("head is not a sha256 digest")
	}
	ts, err := time.Parse(receipt.TimeFormat, c.TS)
	if err != nil || ts.UTC().Format(receipt.TimeFormat) != c.TS {
		return invalid("ts %q is not in %s", c.TS, receipt.TimeFormat)
	}
	return nil
}

// Sign validates c and signs it with k under key ID kid.
func Sign(k *composite.PrivateKey, kid string, c *Checkpoint) (*receipt.Signed, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	payload, err := canonical.Encode(c)
	if err != nil {
		return nil, err
	}
	return receipt.SignPayload(k, kid, payload)
}

// Verify checks the signature with pub, then decodes and validates the
// checkpoint. The payload is not parsed until the signature verifies.
func Verify(pub *composite.PublicKey, s *receipt.Signed) (*Checkpoint, error) {
	payload, err := receipt.VerifyPayload(pub, s)
	if err != nil {
		return nil, err
	}
	var c Checkpoint
	if err := canonical.DecodeStrict(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", receipt.ErrMalformed, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Builder accumulates log lines in order and produces checkpoints over them.
type Builder struct {
	chainID string
	leaves  []merkle.Hash
	head    string
}

// NewBuilder starts an empty builder for a chain.
func NewBuilder(chainID string) *Builder { return &Builder{chainID: chainID} }

// Add records the next log line.
func (b *Builder) Add(line []byte) {
	b.leaves = append(b.leaves, merkle.LeafHash(line))
	b.head = digest.SHA256(line)
}

// Size is the number of lines added.
func (b *Builder) Size() int64 { return int64(len(b.leaves)) }

// Checkpoint returns a checkpoint over every line added so far.
func (b *Builder) Checkpoint(ts string) (*Checkpoint, error) {
	if len(b.leaves) == 0 {
		return nil, errors.New("checkpoint: no receipts to cover")
	}
	c := &Checkpoint{
		V:       Version,
		Domain:  Domain,
		ChainID: b.chainID,
		Size:    int64(len(b.leaves)),
		Root:    merkle.Digest(merkle.Root(b.leaves)),
		Head:    b.head,
		TS:      ts,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Policy decides when a checkpoint is due: after Every new receipts or after
// Interval has passed since the last checkpoint, whichever comes first, as long
// as there is at least one new receipt.
type Policy struct {
	Every    int64
	Interval time.Duration
}

// DefaultPolicy is the design default: 100 receipts or 60 seconds.
var DefaultPolicy = Policy{Every: 100, Interval: 60 * time.Second}

// Due reports whether a checkpoint should be made now.
func (p Policy) Due(lastSize, size int64, lastAt, now time.Time) bool {
	if size <= lastSize {
		return false
	}
	return size-lastSize >= p.Every || now.Sub(lastAt) >= p.Interval
}
