package gate

// Helpers for the key rotation and revocation gates (ADR-0016). They act on the
// live deployment the scenario is running against, so what the gates check is
// the chain Warden actually wrote, not a reconstruction of one.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// signingKey is the key the log signs with now: the key introduced by the last
// rotation, or the one the chain began with.
func (e *Env) signingKey() *composite.PrivateKey {
	if e.current != nil {
		return e.current
	}
	return e.receiptKey
}

func (e *Env) signingKid() string {
	if e.currentKid != "" {
		return e.currentKid
	}
	return kid
}

// rotate hands the live chain over to a fresh key under newKid, certified by
// this deployment's root, as `warden rotate-key` does.
func (e *Env) rotate(newKid string) error {
	incoming, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		return err
	}
	now := time.Now()
	epoch, err := e.ca.IssueKeyEpoch(newKid, incoming.Public(), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		return err
	}
	outgoing := e.signingKey()
	if _, err := e.store.Rotate(e.ctx, rotationReceipt(e.signingKid(), newKid, incoming, epoch), incoming); err != nil {
		return err
	}
	e.retired, e.current, e.currentKid = outgoing, incoming, newKid
	return nil
}

// rotationReceipt is the handover; the appender fills in the chain fields.
func rotationReceipt(from, to string, incoming *composite.PrivateKey, epochDER []byte) *receipt.Receipt {
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS:   time.Now().UTC().Format(receipt.TimeFormat),
		Type: receipt.TypeKeyRotation,
		Rotation: &receipt.Rotation{
			From: from, To: to,
			Key:         digest.SHA256(incoming.Public().Bytes()),
			Certificate: base64.RawURLEncoding.EncodeToString(epochDER),
			Reason:      "gate scenario",
		},
	}
}

// decisionFor is a plausible decision receipt, for forging onto a log.
func decisionFor(tool string) *receipt.Receipt {
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS: time.Now().UTC().Format(receipt.TimeFormat), Type: receipt.TypeDecision, TaskID: "t1",
		Actor: &receipt.Actor{Agent: "support-agent-7", Principal: "alice@tenant-a"},
		Call: &receipt.Call{Tool: tool, Manifest: digest.SHA256([]byte(tool)),
			ArgsCommitment: digest.SHA256([]byte("args"))},
		Decision: &receipt.Decision{Result: receipt.Allow, PolicyRevision: digest.SHA256([]byte("policy"))},
	}
}

func (e *Env) export() ([]byte, error) {
	var buf bytes.Buffer
	if err := e.store.Export(e.ctx, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *Env) logLines() ([][]byte, error) {
	data, err := e.export()
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("the log is empty")
	}
	return bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")), nil
}

func joinLines(lines [][]byte) []byte {
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// exportPrefix returns the log's first n receipts.
func (e *Env) exportPrefix(n int64) ([]byte, error) {
	lines, err := e.logLines()
	if err != nil {
		return nil, err
	}
	if int64(len(lines)) < n {
		return nil, fmt.Errorf("the log holds %d receipts, want at least %d", len(lines), n)
	}
	return joinLines(lines[:n]), nil
}

// appendForged signs r with key under keyID and puts it at the end of the log,
// carrying the sequence number and link the next receipt would. The store would
// refuse to write this; someone holding the key and the file would not.
func (e *Env) appendForged(key *composite.PrivateKey, keyID string, r *receipt.Receipt) ([]byte, error) {
	lines, err := e.logLines()
	if err != nil {
		return nil, err
	}
	r.ChainID, r.Seq, r.Prev = chainID, int64(len(lines)), digest.SHA256(lines[len(lines)-1])
	r.TS = time.Now().UTC().Format(receipt.TimeFormat)
	s, err := receipt.Sign(key, keyID, r)
	if err != nil {
		return nil, err
	}
	line, err := s.Line()
	if err != nil {
		return nil, err
	}
	return joinLines(append(lines, line)), nil
}

// genesisKeys is an auditor's position: the one key the chain began with, and
// the root that certifies whatever it rotated to.
func (e *Env) genesisKeys() chain.Keys {
	return keys.NewRotating(map[string]*composite.PublicKey{kid: e.receiptKey.Public()}, e.pool)
}

func (e *Env) verifyFromGenesis(revoked []chain.Revoked) (*chain.Report, error) {
	data, err := e.export()
	if err != nil {
		return nil, err
	}
	return chain.VerifyAll(bytes.NewReader(data), chainID, chain.Options{Keys: e.genesisKeys(), Revocations: revoked})
}

// mustFail checks that a log fails verification for the stated reason.
func (e *Env) mustFail(log []byte, want chain.Reason) error {
	_, err := chain.VerifyAll(bytes.NewReader(log), chainID, chain.Options{Keys: e.genesisKeys()})
	var f *chain.Failure
	if !errors.As(err, &f) {
		return breach("the log verified (err=%v), want %s", err, want)
	}
	if f.Reason != want {
		return breach("failed with %s (%s), want %s", f.Reason, f.Detail, want)
	}
	return nil
}

// checkpointNow commits to the log as it stands: the most an anchor could have
// been told about so far.
func (e *Env) checkpointNow() (*checkpoint.Checkpoint, error) {
	lines, err := e.logLines()
	if err != nil {
		return nil, err
	}
	b := checkpoint.NewBuilder(chainID)
	for _, l := range lines {
		b.Add(l)
	}
	return b.Checkpoint(time.Now().UTC().Format(receipt.TimeFormat))
}
