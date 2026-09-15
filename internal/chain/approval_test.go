package chain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

func appr(i int, task string, c *receipt.Call, decisionSeq int64, outcome receipt.ApprovalOutcome, approver string, expiresAt int) *receipt.Receipt {
	r := dec(i, task, c, receipt.Allow)
	r.Type, r.Decision = receipt.TypeApproval, nil
	r.Approval = &receipt.Approval{
		DecisionSeq: decisionSeq,
		Outcome:     outcome,
		Approver:    approver,
		Statement:   digest.SHA256([]byte("statement")),
		ExpiresTS:   ts(expiresAt),
	}
	return r
}

// approvalFlow extends the scenario with a refund that needs approval:
//
//	6 decision require_approval payments.refund
//	7 approval approved by bob, expires at ts(100)
//	8 result for 6
func approvalFlow() []*receipt.Receipt {
	refund := call("payments.refund.large")
	return append(scenario(0),
		dec(6, "t1", refund, receipt.RequireApproval),
		appr(7, "t1", refund, 6, receipt.Approved, "bob@tenant-a", 100),
		res(8, "t1", refund, 6),
	)
}

func TestApprovedCallVerifies(t *testing.T) {
	k := newKey(t)
	lines := build(t, k, chainA, approvalFlow())
	rep, err := Verify(bytes.NewReader(join(lines)), chainA, resolver(map[string]*composite.PublicKey{kid: k.Public()}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Receipts != 9 {
		t.Fatalf("receipts %d, want 9", rep.Receipts)
	}
}

func TestApprovalRules(t *testing.T) {
	k := newKey(t)
	keys := resolver(map[string]*composite.PublicKey{kid: k.Public()})
	refund := call("payments.refund.large")

	cases := []struct {
		name   string
		mutate func(rs []*receipt.Receipt) []*receipt.Receipt
		line   int
		reason Reason
	}{
		{"result without approval", func(rs []*receipt.Receipt) []*receipt.Receipt {
			return append(rs[:7:7], res(8, "t1", refund, 6))
		}, 8, ReasonMissingApproval},
		{"result after a rejection", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7].Approval.Outcome = receipt.Rejected
			return rs
		}, 9, ReasonRejectedCallExecuted},
		{"result after the approval expired", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7].Approval.ExpiresTS = ts(8)
			rs[8] = res(9, "t1", refund, 6) // one millisecond after the expiry
			return rs
		}, 9, ReasonApprovalExpired},
		{"self-approval", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7].Approval.Approver = "alice@tenant-a"
			return rs
		}, 8, ReasonSelfApproval},
		{"duplicate approval", func(rs []*receipt.Receipt) []*receipt.Receipt {
			second := appr(8, "t1", refund, 6, receipt.Approved, "carol@tenant-a", 100)
			return append(rs[:8:8], second, res(9, "t1", refund, 6))
		}, 9, ReasonDuplicateApproval},
		{"approval for an allow decision", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7] = appr(7, "t1", call("tickets.update"), 5, receipt.Approved, "bob@tenant-a", 100)
			return rs[:8]
		}, 8, ReasonBadReference},
		{"approval for a different call", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7] = appr(7, "t1", call("payments.refund.other"), 6, receipt.Approved, "bob@tenant-a", 100)
			return rs[:8]
		}, 8, ReasonBadReference},
		{"approval for a different task", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7] = appr(7, "t2", refund, 6, receipt.Approved, "bob@tenant-a", 100)
			return rs[:8]
		}, 8, ReasonBadReference},
		{"approval referencing a result", func(rs []*receipt.Receipt) []*receipt.Receipt {
			rs[7] = appr(7, "t1", call("crm.lookup"), 1, receipt.Approved, "bob@tenant-a", 100)
			return rs[:8]
		}, 8, ReasonBadReference},
		{"approval after the result", func(rs []*receipt.Receipt) []*receipt.Receipt {
			// Approving a small refund that already ran: decision 2 was allow, so
			// this is also not a require_approval decision.
			return append(rs[:7:7], appr(7, "t1", call("payments.refund"), 2, receipt.Approved, "bob@tenant-a", 100))
		}, 8, ReasonBadReference},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := build(t, k, chainA, c.mutate(approvalFlow()))
			_, err := Verify(bytes.NewReader(join(lines)), chainA, keys)
			var f *Failure
			if !errors.As(err, &f) {
				t.Fatalf("got %v, want *Failure", err)
			}
			if f.Reason != c.reason || f.Line != c.line {
				t.Fatalf("got line %d %s (%s), want line %d %s", f.Line, f.Reason, f.Detail, c.line, c.reason)
			}
		})
	}

	t.Run("rejected decision with no result verifies", func(t *testing.T) {
		rs := approvalFlow()[:8]
		rs[7].Approval.Outcome = receipt.Rejected
		if _, err := Verify(bytes.NewReader(join(build(t, k, chainA, rs))), chainA, keys); err != nil {
			t.Fatalf("a rejection that was honored should verify: %v", err)
		}
	})
}
