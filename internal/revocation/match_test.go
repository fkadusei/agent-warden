package revocation

import (
	"errors"
	"strings"
	"testing"

	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/digest"
)

func cp(size int64, head string) *checkpoint.Checkpoint {
	return &checkpoint.Checkpoint{
		V: checkpoint.Version, Domain: checkpoint.Domain, ChainID: chainA,
		Size: size, Root: digest.SHA256([]byte("root")), Head: head,
		TS: now.Format("2006-01-02T15:04:05.000Z"),
	}
}

func TestMatch(t *testing.T) {
	head4, head8 := digest.SHA256([]byte("line 3")), digest.SHA256([]byte("line 7"))
	anchored := []*checkpoint.Checkpoint{cp(4, head4), cp(8, head8)}

	at := func(size int64, head string) *Revocation {
		r := rev(chainA, size)
		r.EffectiveHead = head
		return r
	}

	t.Run("matched to the checkpoint it names", func(t *testing.T) {
		got, err := Match([]*Revocation{at(8, head8)}, anchored)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Kid != kid || got[0].Size != 8 {
			t.Fatalf("got %+v", got)
		}
		if got[0].Reason != "signing key compromised" {
			t.Fatalf("reason not carried through: %q", got[0].Reason)
		}
	})

	t.Run("several at once", func(t *testing.T) {
		got, err := Match([]*Revocation{at(4, head4), at(8, head8)}, anchored)
		if err != nil || len(got) != 2 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})

	t.Run("none", func(t *testing.T) {
		got, err := Match(nil, anchored)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})

	// A revocation has to name a checkpoint someone else can check. One that
	// names a size nothing anchors asserts a boundary no anchor supports.
	t.Run("naming a checkpoint that is not anchored", func(t *testing.T) {
		_, err := Match([]*Revocation{at(6, head4)}, anchored)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not anchored") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("no anchored checkpoints at all", func(t *testing.T) {
		if _, err := Match([]*Revocation{at(4, head4)}, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v", err)
		}
	})

	// Same size, different history: the revocation was written about a fork.
	t.Run("naming a checkpoint of that size in another history", func(t *testing.T) {
		_, err := Match([]*Revocation{at(4, head8)}, anchored)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "another history") {
			t.Fatalf("got %v", err)
		}
	})
}
