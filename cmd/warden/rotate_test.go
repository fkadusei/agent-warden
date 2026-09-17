package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/digest"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/revocation"
	"github.com/fkadusei/agent-warden/internal/store"
)

func initChain(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "w")
	cfgPath = filepath.Join(dir, "warden.json")
	runOK(t, "", "init", "--dir", dir, "--kid", "warden-e1")
	return dir, cfgPath
}

func loadCfg(t *testing.T, cfgPath string) *config.Config {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func decisionAt(seq int64) *receipt.Receipt {
	tool := fmt.Sprintf("crm.lookup-%d", seq)
	return &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS:     time.Now().UTC().Format(receipt.TimeFormat),
		Type:   receipt.TypeDecision,
		TaskID: "t1",
		Actor:  &receipt.Actor{Agent: "cert-sha256:ab12", Principal: "alice@tenant-a"},
		Call: &receipt.Call{Tool: tool, Manifest: digest.SHA256([]byte(tool)),
			ArgsCommitment: digest.SHA256([]byte(tool))},
		Decision: &receipt.Decision{Result: receipt.Deny, PolicyRevision: digest.SHA256([]byte("p1"))},
	}
}

// withStore opens the log with whatever key the configuration currently names.
func withStore(t *testing.T, cfg *config.Config, fn func(*store.Store)) {
	t.Helper()
	key, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.Path(cfg.Store), key, cfg.Kid, cfg.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fn(st)
}

func appendDecisions(t *testing.T, cfg *config.Config, n int) {
	t.Helper()
	withStore(t, cfg, func(st *store.Store) {
		for range n {
			if _, err := st.Append(context.Background(), decisionAt(st.Next())); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// anchorCheckpoint signs a checkpoint over the whole log and anchors it.
func anchorCheckpoint(t *testing.T, cfg *config.Config) *checkpoint.Checkpoint {
	t.Helper()
	key, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		t.Fatal(err)
	}
	var cp *checkpoint.Checkpoint
	withStore(t, cfg, func(st *store.Store) {
		var buf bytes.Buffer
		if err := st.Export(context.Background(), &buf); err != nil {
			t.Fatal(err)
		}
		b := checkpoint.NewBuilder(cfg.ChainID)
		for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
			b.Add(line)
		}
		cp, err = b.Checkpoint(time.Now().UTC().Format(receipt.TimeFormat))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := checkpoint.Sign(key, cfg.Kid, cp)
		if err != nil {
			t.Fatal(err)
		}
		if err := (checkpoint.FileAnchor{Path: cfg.Path(cfg.Anchor)}).Publish(signed); err != nil {
			t.Fatal(err)
		}
	})
	return cp
}

func caCert(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	der, err := keyfile.ReadCertificate(filepath.Join(dir, "pki", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func trustFor(t *testing.T, cfg *config.Config) map[string]*composite.PublicKey {
	t.Helper()
	trusted, err := trustedKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

// exportLog runs the export command and returns the log.
func exportLog(t *testing.T, dir, cfgPath string, name string) []byte {
	t.Helper()
	path := filepath.Join(dir, name)
	runOK(t, "", "export", "--config", cfgPath, "--out", path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRotateKey(t *testing.T) {
	dir, cfgPath := initChain(t)
	appendDecisions(t, loadCfg(t, cfgPath), 2)

	out := runOK(t, "", "rotate-key", "--config", cfgPath, "--kid", "warden-e2")
	if !strings.Contains(out, "Rotated warden-e1 to warden-e2") {
		t.Fatalf("rotate-key said:\n%s", out)
	}

	cfg := loadCfg(t, cfgPath)
	if cfg.Kid != "warden-e2" {
		t.Fatalf("config still names %q", cfg.Kid)
	}
	if cfg.ReceiptKey != filepath.Join("pki", "receipt-warden-e2.key") {
		t.Fatalf("config receipt_key is %q", cfg.ReceiptKey)
	}
	info, err := os.Stat(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the incoming private key has mode %v, want 0600", perm)
	}
	if _, err := os.Stat(cfg.Path(cfg.ReceiptCert)); err != nil {
		t.Fatalf("no epoch certificate for the incoming key: %v", err)
	}

	// The trust file keeps the retired key and gains the new one: older
	// checkpoints are still signed by the key that was current then.
	trusted := trustFor(t, cfg)
	if len(trusted) != 2 || trusted["warden-e1"] == nil || trusted["warden-e2"] == nil {
		t.Fatalf("trust file holds %d keys: %v", len(trusted), trusted)
	}

	// The log now signs with the incoming key.
	appendDecisions(t, cfg, 1)

	// And the whole thing verifies from the original key alone, following the
	// handover to a key it had never seen.
	pool := x509.NewCertPool()
	pool.AddCert(caCert(t, dir))
	rotating := keys.NewRotating(map[string]*composite.PublicKey{"warden-e1": trusted["warden-e1"]}, pool)
	rep, err := chain.VerifyWithKeys(bytes.NewReader(exportLog(t, dir, cfgPath, "export.jsonl")), cfg.ChainID, rotating, nil)
	if err != nil {
		t.Fatalf("the rotated log does not verify: %v", err)
	}
	if rep.Receipts != 4 || rep.LastSeq != 3 {
		t.Fatalf("unexpected report %+v", rep)
	}
	if len(rep.Rotations) != 1 || rep.Rotations[0].From != "warden-e1" || rep.Rotations[0].To != "warden-e2" {
		t.Fatalf("handovers: %+v", rep.Rotations)
	}
	if learned := rotating.Learned(); len(learned) != 1 || learned[0] != "warden-e2" {
		t.Fatalf("learned %v, want [warden-e2]", learned)
	}
}

// Serve reads the anchor at startup. After a rotation it holds checkpoints
// signed by the retired key, which must still resolve.
func TestRotatedAnchorStillReadsBack(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	appendDecisions(t, cfg, 2)
	anchorCheckpoint(t, cfg)
	runOK(t, "", "rotate-key", "--config", cfgPath, "--kid", "warden-e2")

	after := loadCfg(t, cfgPath)
	key, err := keyfile.ReadComposite(after.Path(after.ReceiptKey))
	if err != nil {
		t.Fatal(err)
	}
	withStore(t, after, func(st *store.Store) {
		if _, err := newCheckpointer(st, key, after, &bytes.Buffer{}); err != nil {
			t.Fatalf("a checkpoint signed by the retired key no longer reads back: %v", err)
		}
	})
}

func TestRotateKeyRefuses(t *testing.T) {
	_, cfgPath := initChain(t)
	appendDecisions(t, loadCfg(t, cfgPath), 1)

	cases := map[string][]string{
		"the key already in use": {"rotate-key", "--config", cfgPath, "--kid", "warden-e1"},
		"no key ID at all":       {"rotate-key", "--config", cfgPath},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(context.Background(), args, strings.NewReader(""), &out, &errOut); code == 0 {
				t.Fatalf("accepted:\n%s", out.String())
			}
			if loadCfg(t, cfgPath).Kid != "warden-e1" {
				t.Fatal("a refused rotation changed the configured key")
			}
		})
	}

	t.Run("rotating back to a retired key ID", func(t *testing.T) {
		runOK(t, "", "rotate-key", "--config", cfgPath, "--kid", "warden-e2")
		before := loadCfg(t, cfgPath)
		var length int64
		withStore(t, before, func(st *store.Store) { length = st.Next() })

		var out, errOut bytes.Buffer
		if code := run(context.Background(),
			[]string{"rotate-key", "--config", cfgPath, "--kid", "warden-e1"},
			strings.NewReader(""), &out, &errOut); code == 0 {
			t.Fatalf("reused a retired key ID:\n%s", out.String())
		}
		// Exiting non-zero is not enough. It has to refuse before handing the
		// log over, or the chain has rotated to a key ID that already names a
		// different key and no verifier can resolve it.
		after := loadCfg(t, cfgPath)
		if after.Kid != before.Kid {
			t.Fatalf("the log rotated to %q anyway", after.Kid)
		}
		var now int64
		withStore(t, after, func(st *store.Store) { now = st.Next() })
		if now != length {
			t.Fatalf("a refused rotation still wrote %d receipt(s)", now-length)
		}
	})
}

func TestRevokeKey(t *testing.T) {
	dir, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	appendDecisions(t, cfg, 3)
	cp := anchorCheckpoint(t, cfg)
	if cp.Size != 3 {
		t.Fatalf("checkpoint covers %d receipts, want 3", cp.Size)
	}
	// One more receipt after the checkpoint: this is the tail a revocation costs.
	appendDecisions(t, cfg, 1)

	t.Run("nothing is published without confirmation", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run(context.Background(),
			[]string{"revoke-key", "--config", cfgPath, "--kid", "warden-e1"},
			strings.NewReader("n\n"), &out, &errOut); code == 0 {
			t.Fatal("revoke-key published without confirmation")
		}
		if _, err := os.Stat(cfg.Path(cfg.Revocations)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a revocation was published anyway")
		}
	})

	t.Run("an unknown key is refused", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run(context.Background(),
			[]string{"revoke-key", "--config", cfgPath, "--kid", "warden-e9", "--yes"},
			strings.NewReader(""), &out, &errOut); code == 0 {
			t.Fatal("revoked a key the chain never used")
		}
	})

	out := runOK(t, "y\n", "revoke-key", "--config", cfgPath, "--kid", "warden-e1", "--reason", "key compromised")
	if !strings.Contains(out, "Published to") {
		t.Fatalf("revoke-key said:\n%s", out)
	}

	// The published record verifies under the root and says what was asked.
	data, err := os.ReadFile(cfg.Path(cfg.Revocations))
	if err != nil {
		t.Fatal(err)
	}
	root, err := revocation.RootKey(caCert(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	revs, err := revocation.ReadVerified(bytes.NewReader(data), cfg.ChainID, root)
	if err != nil {
		t.Fatalf("the published revocation does not verify under the root: %v", err)
	}
	if len(revs) != 1 {
		t.Fatalf("read %d revocations", len(revs))
	}
	if revs[0].Kid != "warden-e1" || revs[0].EffectiveSize != cp.Size || revs[0].EffectiveHead != cp.Head {
		t.Fatalf("revocation says %+v, want kid warden-e1 from size %d head %s", revs[0], cp.Size, cp.Head)
	}
	if revs[0].Reason != "key compromised" {
		t.Fatalf("reason %q", revs[0].Reason)
	}

	// And it bites where it should: the tail is refused, the anchored history stands.
	logData := exportLog(t, dir, cfgPath, "export.jsonl")
	trusted := trustFor(t, cfg)
	opts := chain.Options{
		Keys:        chain.StaticKeys(keys.Resolver(trusted)),
		Revocations: []chain.Revoked{{Kid: revs[0].Kid, EffectiveSize: revs[0].EffectiveSize}},
	}
	_, err = chain.VerifyAll(bytes.NewReader(logData), cfg.ChainID, opts)
	var f *chain.Failure
	if !errors.As(err, &f) || f.Reason != chain.ReasonRevokedKey || f.Seq != cp.Size {
		t.Fatalf("got %v, want revoked_key at seq %d", err, cp.Size)
	}

	lines := bytes.SplitAfter(bytes.TrimSuffix(logData, []byte("\n")), []byte("\n"))
	history := bytes.Join(lines[:cp.Size], nil)
	if _, err := chain.VerifyAll(bytes.NewReader(history), cfg.ChainID, opts); err != nil {
		t.Fatalf("the anchored history no longer verifies: %v", err)
	}
}
