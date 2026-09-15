package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/receipt"
)

func TestListPending(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if got, err := f.gw.ListPending(); err != nil || len(got) != 0 {
		t.Fatalf("empty gateway: %v, %v", got, err)
	}

	var seqs []int64
	for _, amount := range []int{500, 700} {
		resp, err := f.gw.Call(ctx, f.aliceCred, "payments", "refund", json.RawMessage(`{"amount":`+itoa(amount)+`}`))
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, resp.DecisionSeq)
	}
	// An allowed call is never listed.
	if _, err := f.gw.Call(ctx, f.aliceCred, "crm", "lookup", nil); err != nil {
		t.Fatal(err)
	}

	list, err := f.gw.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Decision.Seq != seqs[0] || list[1].Decision.Seq != seqs[1] {
		t.Fatalf("listed %d calls", len(list))
	}
	if string(list[1].Args) != `{"amount":700}` || list[0].Approval != nil {
		t.Fatalf("unexpected entry %+v", list[1])
	}

	if _, err := f.gw.Approve(ctx, f.statement(t, f.bob, "bob@tenant-a", seqs[0], receipt.Approved, 30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	list, _ = f.gw.ListPending()
	if list[0].Approval == nil || list[0].Approval.Approver != "bob@tenant-a" {
		t.Fatalf("approval not shown: %+v", list[0])
	}

	if _, err := f.gw.Resume(ctx, f.aliceCred, seqs[0]); err != nil {
		t.Fatal(err)
	}
	list, _ = f.gw.ListPending()
	if len(list) != 1 || list[0].Decision.Seq != seqs[1] {
		t.Fatalf("executed call still listed: %d entries", len(list))
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
