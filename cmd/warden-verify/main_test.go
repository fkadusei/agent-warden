package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

const (
	chainID = "01J9Z3CHAIN"
	kid     = "warden-2026-09-e1"
)

type fixture struct {
	dir    string
	log    string
	anchor string
	keys   string
	lines  [][]byte
}

func (f fixture) path(name string) string { return filepath.Join(f.dir, name) }

func write(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newFixture writes a 6-receipt log, an anchor with one checkpoint over the
// first 4 receipts, and a trust file.
func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{dir: t.TempDir()}
	f.log, f.anchor, f.keys = f.path("receipts.jsonl"), f.path("anchor.jsonl"), f.path("keys.json")

	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := chain.NewAppender(k, kid, chainID)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 14, 15, 4, 5, 0, time.UTC)
	for i := 0; i < 6; i++ {
		tool := []string{"crm.lookup", "payments.refund", "email.send"}[i%3]
		r := &receipt.Receipt{
			V: receipt.Version, Domain: receipt.Domain,
			TS:     base.Add(time.Duration(i) * time.Millisecond).Format(receipt.TimeFormat),
			Type:   receipt.TypeDecision,
			TaskID: "t1",
			Actor:  &receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
			Call: &receipt.Call{Tool: tool, Manifest: digest.SHA256([]byte(tool)),
				ArgsCommitment: digest.SHA256([]byte{byte(i)})},
			Decision: &receipt.Decision{Result: receipt.Deny, PolicyRevision: digest.SHA256([]byte("p1"))},
		}
		_, line, err := a.Append(r)
		if err != nil {
			t.Fatal(err)
		}
		f.lines = append(f.lines, line)
	}
	write(t, f.log, f.lines)

	b := checkpoint.NewBuilder(chainID)
	for _, l := range f.lines[:4] {
		b.Add(l)
	}
	c, err := b.Checkpoint(base.Add(time.Second).Format(receipt.TimeFormat))
	if err != nil {
		t.Fatal(err)
	}
	s, err := checkpoint.Sign(k, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := (checkpoint.FileAnchor{Path: f.anchor}).Publish(s); err != nil {
		t.Fatal(err)
	}

	set, err := json.Marshal(keys.Set{Keys: []keys.JWK{keys.PublicJWK(kid, k.Public())}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.keys, set, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVerifiedWithAnchor(t *testing.T) {
	f := newFixture(t)
	code, out, errOut := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"VERIFIED", "6 (seq 0-5)", "4 receipts (1 anchored checkpoints)", "2 receipts after the last checkpoint"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if errOut != "" {
		t.Errorf("unexpected stderr: %s", errOut)
	}
}

func TestVerifiedWithoutAnchorWarns(t *testing.T) {
	f := newFixture(t)
	code, out, errOut := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys)
	if code != exitVerified || !strings.Contains(out, "checkpointed:   none") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(errOut, "WARNING: no anchored checkpoints") {
		t.Fatalf("missing warning, stderr: %q", errOut)
	}
}

func TestJSONOutput(t *testing.T) {
	f := newFixture(t)
	code, out, _ := runCLI("--json", "--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor)
	if code != exitVerified {
		t.Fatalf("exit %d: %s", code, out)
	}
	var r struct {
		Verified     bool  `json:"verified"`
		Receipts     int   `json:"receipts"`
		LastSeq      int64 `json:"last_seq"`
		Checkpointed int64 `json:"checkpointed"`
		Unanchored   int64 `json:"unanchored"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if !r.Verified || r.Receipts != 6 || r.LastSeq != 5 || r.Checkpointed != 4 || r.Unanchored != 2 {
		t.Fatalf("unexpected result %+v", r)
	}

	write(t, f.log, f.lines[:3])
	code, out, _ = runCLI("--json", "--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor)
	var failed struct {
		Verified bool   `json:"verified"`
		Stage    string `json:"stage"`
		Failure  struct {
			Line   int    `json:"line"`
			Reason string `json:"reason"`
		} `json:"failure"`
	}
	if err := json.Unmarshal([]byte(out), &failed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if code != exitFailed || failed.Verified || failed.Stage != "log" || failed.Failure.Reason != string(chain.ReasonCheckpointMismatch) {
		t.Fatalf("exit %d, unexpected failure %+v", code, failed)
	}
}

func TestFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f fixture) []string
		want   []string
	}{
		{"tampered receipt", func(t *testing.T, f fixture) []string {
			l := append([][]byte{}, f.lines...)
			b := bytes.Clone(l[2])
			i := bytes.Index(b, []byte(`"signature":"`)) + len(`"signature":"`) + 20
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			l[2] = b
			write(t, f.log, l)
			return []string{"--anchor", f.anchor}
		}, []string{"FAILED", "line:           3", "reason:         bad_signature"}},
		{"receipts removed below the checkpoint", func(t *testing.T, f fixture) []string {
			write(t, f.log, f.lines[:2])
			return []string{"--anchor", f.anchor}
		}, []string{"FAILED", "reason:         checkpoint_mismatch", "receipts were removed"}},
		{"deleted receipt", func(t *testing.T, f fixture) []string {
			write(t, f.log, append(append([][]byte{}, f.lines[:1]...), f.lines[2:]...))
			return nil
		}, []string{"FAILED", "line:           2", "reason:         seq_gap"}},
		{"tampered anchor", func(t *testing.T, f fixture) []string {
			data, err := os.ReadFile(f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			i := bytes.Index(data, []byte(`"signature":"`)) + len(`"signature":"`) + 20
			if data[i] == 'A' {
				data[i] = 'B'
			} else {
				data[i] = 'A'
			}
			if err := os.WriteFile(f.anchor, data, 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{"--anchor", f.anchor}
		}, []string{"FAILED", "anchor:", "bad signature"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			extra := c.mutate(t, f)
			code, out, errOut := runCLI(append([]string{"--log", f.log, "--chain", chainID, "--keys", f.keys}, extra...)...)
			if code != exitFailed {
				t.Fatalf("exit %d, want %d\n%s%s", code, exitFailed, out, errOut)
			}
			for _, want := range c.want {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
		})
	}

	t.Run("wrong chain", func(t *testing.T) {
		f := newFixture(t)
		code, out, _ := runCLI("--log", f.log, "--chain", "OTHER", "--keys", f.keys)
		if code != exitFailed || !strings.Contains(out, "wrong_chain") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("untrusted key", func(t *testing.T) {
		f := newFixture(t)
		other, err := composite.MLDSA65Ed25519.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		set, _ := json.Marshal(keys.Set{Keys: []keys.JWK{keys.PublicJWK(kid, other.Public())}})
		if err := os.WriteFile(f.keys, set, 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys)
		if code != exitFailed || !strings.Contains(out, "bad_signature") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}

func TestUsageErrors(t *testing.T) {
	f := newFixture(t)
	privateKeys := f.path("with-private.json")
	if err := os.WriteFile(privateKeys, []byte(`{"keys":[{"kty":"AKP","alg":"ML-DSA-65-Ed25519","kid":"k","pub":"AA","priv":"AA"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no arguments":         {},
		"missing chain":        {"--log", f.log, "--keys", f.keys},
		"missing keys":         {"--log", f.log, "--chain", chainID},
		"extra argument":       {"--log", f.log, "--chain", chainID, "--keys", f.keys, "stray"},
		"unknown flag":         {"--nope"},
		"missing log file":     {"--log", f.path("missing.jsonl"), "--chain", chainID, "--keys", f.keys},
		"missing anchor file":  {"--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.path("missing")},
		"private key in trust": {"--log", f.log, "--chain", chainID, "--keys", privateKeys},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := runCLI(args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want %d\n%s%s", code, exitUsage, out, errOut)
			}
			if out != "" {
				t.Errorf("usage errors should not print a result, got: %s", out)
			}
		})
	}
	_, _, errOut := runCLI("--log", f.log, "--chain", chainID, "--keys", privateKeys)
	if !strings.Contains(errOut, "private key material") {
		t.Errorf("private key rejection not explained: %s", errOut)
	}
}
