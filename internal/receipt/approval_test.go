package receipt

import (
	"errors"
	"reflect"
	"testing"

	"github.com/fkadusei/agent-warden/internal/digest"
)

func approval(seq, decisionSeq int64) *Receipt {
	r := decision(seq)
	r.Type = TypeApproval
	r.Decision = nil
	r.Approval = &Approval{
		DecisionSeq: decisionSeq,
		Outcome:     Approved,
		Approver:    "bob@tenant-a",
		Statement:   d3,
		ExpiresTS:   "2026-09-14T15:34:05.123Z",
	}
	return r
}

func TestApprovalReceiptRoundTrip(t *testing.T) {
	k := newKey(t)
	r := approval(9, 7)
	s, err := Sign(k, "k1", r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(k.Public(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Fatalf("round trip changed the approval:\n got %+v\nwant %+v", got.Approval, r.Approval)
	}
}

func TestApprovalValidateRejects(t *testing.T) {
	cases := map[string]func(r *Receipt){
		"missing approval section":    func(r *Receipt) { r.Approval = nil },
		"decision_seq not before seq": func(r *Receipt) { r.Approval.DecisionSeq = r.Seq },
		"negative decision_seq":       func(r *Receipt) { r.Approval.DecisionSeq = -1 },
		"unknown outcome":             func(r *Receipt) { r.Approval.Outcome = "maybe" },
		"empty approver":              func(r *Receipt) { r.Approval.Approver = "" },
		"bad statement digest":        func(r *Receipt) { r.Approval.Statement = "sha256:no" },
		"expiry without milliseconds": func(r *Receipt) { r.Approval.ExpiresTS = "2026-09-14T15:34:05Z" },
		"expiry equal to ts":          func(r *Receipt) { r.Approval.ExpiresTS = r.TS },
		"expiry before ts":            func(r *Receipt) { r.Approval.ExpiresTS = "2026-09-14T15:00:00.000Z" },
		"also has a decision":         func(r *Receipt) { r.Decision = decision(0).Decision },
		"also has a result":           func(r *Receipt) { r.Result = &Result{DecisionSeq: 7, Status: StatusError} },
		"missing call":                func(r *Receipt) { r.Call = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := approval(9, 7)
			mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}

	t.Run("decision and result receipts may not carry an approval", func(t *testing.T) {
		a := approval(9, 7).Approval
		for _, r := range []*Receipt{decision(7), result(8, 7)} {
			r.Approval = a
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s with approval: got %v, want ErrInvalid", r.Type, err)
			}
		}
	})

	t.Run("rejected outcome is valid", func(t *testing.T) {
		r := approval(9, 7)
		r.Approval.Outcome = Rejected
		r.Approval.Statement = digest.SHA256([]byte("statement"))
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}
