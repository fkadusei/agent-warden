// Package chain links receipts into a hash chain and verifies receipt logs
// (ADR-0003, design §4.4).
//
// Every receipt carries a sequence number and the digest of the previous log
// line, so any edit, insertion, deletion, or reordering is detected. A chain
// alone cannot detect truncation of the newest receipts or a full rewrite by
// someone holding the signing key; anchored checkpoints address that.
package chain

import (
	"errors"
	"fmt"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// GenesisDomain separates genesis parameters from every other hashed object.
const GenesisDomain = "agent-warden/genesis/v1"

// Params are the chain parameters hashed into the first receipt's prev field.
// They bind the chain to its ID, its signature algorithm, and the key that
// signs its first receipt.
type Params struct {
	Domain  string `json:"domain"`
	ChainID string `json:"chain_id"`
	Alg     string `json:"alg"`
	AlgRef  string `json:"alg_ref"`
	Kid     string `json:"kid"`
	Key     string `json:"key"`
}

// NewParams builds the parameters for a chain whose first receipt is signed by
// pub under kid.
func NewParams(chainID, kid string, pub *composite.PublicKey) Params {
	return Params{
		Domain:  GenesisDomain,
		ChainID: chainID,
		Alg:     receipt.Alg,
		AlgRef:  receipt.AlgRef,
		Kid:     kid,
		Key:     digest.SHA256(pub.Bytes()),
	}
}

// GenesisPrev is the prev value of the receipt at seq 0.
func (p Params) GenesisPrev() (string, error) {
	b, err := canonical.Encode(p)
	if err != nil {
		return "", err
	}
	return digest.SHA256(b), nil
}

// Appender assigns chain fields to receipts and signs them in order. It is not
// safe for concurrent use.
type Appender struct {
	key     *composite.PrivateKey
	kid     string
	chainID string
	next    int64
	prev    string
	lastTS  string
}

// NewAppender starts a new chain signed by key under kid.
func NewAppender(key *composite.PrivateKey, kid, chainID string) (*Appender, error) {
	prev, err := NewParams(chainID, kid, key.Public()).GenesisPrev()
	if err != nil {
		return nil, err
	}
	return &Appender{key: key, kid: kid, chainID: chainID, prev: prev}, nil
}

// State is the part of an Appender that must survive a restart.
type State struct {
	// Next is the sequence number of the next receipt.
	Next int64
	// Prev is the digest of the last written line, or the genesis prev when Next is 0.
	Prev string
	// LastTS is the timestamp of the last written receipt, empty when Next is 0.
	LastTS string
}

// State returns a snapshot of the appender's position in the chain.
func (a *Appender) State() State {
	return State{Next: a.next, Prev: a.prev, LastTS: a.lastTS}
}

// ResumeAppender continues an existing chain from st, for example after a
// restart or to roll back an append whose line was never durably written.
func ResumeAppender(key *composite.PrivateKey, kid, chainID string, st State) (*Appender, error) {
	a, err := NewAppender(key, kid, chainID)
	if err != nil {
		return nil, err
	}
	if st.Next == 0 {
		if st.Prev != a.prev || st.LastTS != "" {
			return nil, errors.New("chain: resume at seq 0 must use the genesis prev for this key")
		}
		return a, nil
	}
	if st.Next < 0 || st.Next > receipt.MaxSeq+1 {
		return nil, fmt.Errorf("chain: resume seq %d out of range", st.Next)
	}
	if !digest.Valid(st.Prev) {
		return nil, errors.New("chain: resume prev is not a sha256 digest")
	}
	if st.LastTS == "" {
		return nil, errors.New("chain: resume after seq 0 needs the last timestamp")
	}
	a.next, a.prev, a.lastTS = st.Next, st.Prev, st.LastTS
	return a, nil
}

// Next is the sequence number the next receipt will get.
func (a *Appender) Next() int64 { return a.next }

// Head is the prev value the next receipt will get.
func (a *Appender) Head() string { return a.prev }

// ErrTimeRegression is returned when a receipt's timestamp is earlier than the
// previous receipt's.
var ErrTimeRegression = errors.New("chain: timestamp earlier than previous receipt")

// Append fills in chain_id, seq, and prev on a copy of r, signs it, and returns
// the signed receipt and its log line. The chain advances only on success, so
// the caller must durably write the line before appending the next receipt.
func (a *Appender) Append(r *receipt.Receipt) (*receipt.Signed, []byte, error) {
	if a.next > receipt.MaxSeq {
		return nil, nil, fmt.Errorf("chain: sequence exhausted")
	}
	// TimeFormat has a fixed width, so string order is time order.
	if r.TS < a.lastTS {
		return nil, nil, ErrTimeRegression
	}
	c := *r
	c.ChainID, c.Seq, c.Prev = a.chainID, a.next, a.prev
	s, err := receipt.Sign(a.key, a.kid, &c)
	if err != nil {
		return nil, nil, err
	}
	line, err := s.Line()
	if err != nil {
		return nil, nil, err
	}
	a.prev = digest.SHA256(line)
	a.lastTS = c.TS
	a.next++
	return s, line, nil
}
