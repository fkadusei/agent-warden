package chain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// cpOver builds, signs, and re-verifies a checkpoint over lines, the way a
// verifier would receive it from an anchor.
func cpOver(t *testing.T, k *composite.PrivateKey, chainID string, lines [][]byte, i int) *checkpoint.Checkpoint {
	t.Helper()
	b := checkpoint.NewBuilder(chainID)
	for _, l := range lines {
		b.Add(l)
	}
	c, err := b.Checkpoint(ts(100 + i))
	if err != nil {
		t.Fatal(err)
	}
	s, err := checkpoint.Sign(k, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := checkpoint.Verify(k.Public(), s)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestVerifyWithCheckpoints(t *testing.T) {
	k := newKey(t)
	keys := resolver(map[string]*composite.PublicKey{kid: k.Public()})
	lines := build(t, k, chainA, scenario(0)) // 6 receipts

	expectFailure := func(t *testing.T, log [][]byte, cps []*checkpoint.Checkpoint, line int) {
		t.Helper()
		_, err := VerifyWithCheckpoints(bytes.NewReader(join(log)), chainA, keys, cps)
		var f *Failure
		if !errors.As(err, &f) {
			t.Fatalf("got %v, want *Failure", err)
		}
		if f.Reason != ReasonCheckpointMismatch || f.Line != line {
			t.Fatalf("got line %d %s (%s), want line %d checkpoint_mismatch", f.Line, f.Reason, f.Detail, line)
		}
	}

	t.Run("log matches checkpoint", func(t *testing.T) {
		cp := cpOver(t, k, chainA, lines[:4], 0)
		rep, err := VerifyWithCheckpoints(bytes.NewReader(join(lines)), chainA, keys, []*checkpoint.Checkpoint{cp})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Checkpointed != 4 || rep.Unanchored != 2 {
			t.Fatalf("checkpointed %d unanchored %d, want 4 and 2", rep.Checkpointed, rep.Unanchored)
		}
	})

	t.Run("multiple consistent checkpoints, any order", func(t *testing.T) {
		cps := []*checkpoint.Checkpoint{cpOver(t, k, chainA, lines[:5], 1), cpOver(t, k, chainA, lines[:2], 0)}
		rep, err := VerifyWithCheckpoints(bytes.NewReader(join(lines)), chainA, keys, cps)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Checkpointed != 5 || rep.Unanchored != 1 {
			t.Fatalf("checkpointed %d unanchored %d, want 5 and 1", rep.Checkpointed, rep.Unanchored)
		}
	})

	t.Run("detects truncation before the checkpoint", func(t *testing.T) {
		cp := cpOver(t, k, chainA, lines[:4], 0)
		expectFailure(t, lines[:3], []*checkpoint.Checkpoint{cp}, 4)
	})

	t.Run("detects a full rewrite by the key holder", func(t *testing.T) {
		cp := cpOver(t, k, chainA, lines[:4], 0)
		rs := scenario(0)
		rs[0].Decision.Rule = "rewritten-later"
		expectFailure(t, build(t, k, chainA, rs), []*checkpoint.Checkpoint{cp}, 4)
	})

	t.Run("detects a fork shown by the anchor", func(t *testing.T) {
		rs := scenario(0)
		rs[1].Result.Status = receipt.StatusError // a different history of the same length
		forked := build(t, k, chainA, rs)
		cps := []*checkpoint.Checkpoint{cpOver(t, k, chainA, forked[:2], 0), cpOver(t, k, chainA, lines[:5], 1)}
		expectFailure(t, lines, cps, 2)
	})

	t.Run("rejects a checkpoint for another chain", func(t *testing.T) {
		other := build(t, k, chainB, scenario(0))
		expectFailure(t, lines, []*checkpoint.Checkpoint{cpOver(t, k, chainB, other[:4], 0)}, 0)
	})

	// The exposure window: receipts after the last checkpoint are not protected.
	t.Run("does not detect changes after the last checkpoint", func(t *testing.T) {
		cp := cpOver(t, k, chainA, lines[:4], 0)
		if _, err := VerifyWithCheckpoints(bytes.NewReader(join(lines[:5])), chainA, keys, []*checkpoint.Checkpoint{cp}); err != nil {
			t.Fatalf("truncation after the checkpoint should verify: %v", err)
		}
		// Keep the checkpointed prefix byte for byte and re-sign only what follows:
		// the denied email at seq 4 now looks allowed. (Re-signing the whole log
		// would change the prefix too, because ML-DSA signatures are randomized.)
		rs := scenario(0)
		rs[4].Decision.Result = receipt.Allow
		rewritten := append([][]byte{}, lines[:4]...)
		rewritten = append(rewritten, forge(t, k, kid, at(rs[4], chainA, 4, rewritten)))
		rewritten = append(rewritten, forge(t, k, kid, at(rs[5], chainA, 5, rewritten)))
		rep, err := VerifyWithCheckpoints(bytes.NewReader(join(rewritten)), chainA, keys, []*checkpoint.Checkpoint{cp})
		if err != nil {
			t.Fatalf("rewrite after the checkpoint should verify: %v", err)
		}
		if rep.Unanchored != 2 {
			t.Fatalf("unanchored %d, want 2", rep.Unanchored)
		}
	})

	t.Run("plain Verify reports everything unanchored", func(t *testing.T) {
		rep, err := Verify(bytes.NewReader(join(lines)), chainA, keys)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Checkpointed != 0 || rep.Unanchored != 6 {
			t.Fatalf("checkpointed %d unanchored %d, want 0 and 6", rep.Checkpointed, rep.Unanchored)
		}
	})
}
