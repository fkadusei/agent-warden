package approval

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// No approver statement crashes the verifier, and one that verifies is valid.
// Statements arrive over the network from approvers.
func FuzzStatement(f *testing.F) {
	bob, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{8}, composite.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	keys := func(kid string) (*composite.PublicKey, error) {
		if kid == "bob@tenant-a" {
			return bob.Public(), nil
		}
		return nil, errors.New("unknown approver")
	}
	cd, err := CallDigest("t1", receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		receipt.Call{Tool: "payments/refund", Manifest: digest.SHA256([]byte("refund")), ArgsCommitment: digest.SHA256([]byte("args"))})
	if err != nil {
		f.Fatal(err)
	}
	s, err := Sign(bob, &Statement{
		Domain: StatementDomain, ChainID: chainID, DecisionSeq: 6, CallDigest: cd,
		Outcome: receipt.Approved, Approver: "bob@tenant-a",
		TS: now.Format(receipt.TimeFormat), ExpiresTS: now.Add(30 * time.Minute).Format(receipt.TimeFormat),
	})
	if err != nil {
		f.Fatal(err)
	}
	line, err := s.Line()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(line)
	f.Add([]byte(`{"payload":"","protected":"","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		signed, err := receipt.ParseLine(data)
		if err != nil {
			return
		}
		st, err := Verify(signed, keys)
		if err == nil {
			if err := st.Validate(); err != nil {
				t.Fatalf("a verified statement is invalid: %v", err)
			}
		}
	})
}
