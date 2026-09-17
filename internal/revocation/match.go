package revocation

import (
	"fmt"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
)

// Effective is a revocation matched to the anchored checkpoint it names: the key
// signs nothing trustworthy from sequence number Size onward.
type Effective struct {
	Kid  string
	Size int64
	// Reason is carried through for reporting.
	Reason string
}

// Match pairs each revocation with the anchored checkpoint it names.
//
// A revocation is only meaningful against a checkpoint someone else can check,
// so one that names a checkpoint which is not anchored is refused rather than
// ignored: it asserts a boundary no anchor supports. One whose head differs from
// the anchored checkpoint of that size names a different history — a fork — and
// is refused too, which is what stops a revocation being re-aimed at a log it
// was never written about.
func Match(revs []*Revocation, cps []*checkpoint.Checkpoint) ([]Effective, error) {
	out := make([]Effective, 0, len(revs))
	for _, r := range revs {
		var cp *checkpoint.Checkpoint
		for _, c := range cps {
			if c.Size == r.EffectiveSize {
				cp = c
				break
			}
		}
		switch {
		case cp == nil:
			return nil, fmt.Errorf("%w: the revocation of %q is effective from a checkpoint of size %d, which is not anchored",
				ErrInvalid, r.Kid, r.EffectiveSize)
		case cp.Head != r.EffectiveHead:
			return nil, fmt.Errorf("%w: the revocation of %q names a checkpoint of size %d whose head is not the anchored one: it was written about another history",
				ErrInvalid, r.Kid, r.EffectiveSize)
		}
		out = append(out, Effective{Kid: r.Kid, Size: r.EffectiveSize, Reason: r.Reason})
	}
	return out, nil
}
