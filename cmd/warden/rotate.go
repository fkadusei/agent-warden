package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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

// trustFile is where warden init writes the public keys a verifier trusts.
func trustFile(cfg *config.Config) string { return filepath.Join(cfg.Dir(), "keys.json") }

// trustedKeys reads the trust file beside the configuration.
func trustedKeys(cfg *config.Config) (map[string]*composite.PublicKey, error) {
	data, err := os.ReadFile(trustFile(cfg))
	if err != nil {
		return nil, err
	}
	trusted, err := keys.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", trustFile(cfg), err)
	}
	return trusted, nil
}

// addTrustedKey adds a public key to the trust file, keeping the keys already
// there. A rotated chain's older checkpoints are still signed by its older keys,
// so the local tools need every key the chain has used, even though an auditor
// holding the root needs only the first (ADR-0016).
func addTrustedKey(cfg *config.Config, kid string, pub *composite.PublicKey) error {
	path := trustFile(cfg)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var set keys.Set
	if err := json.Unmarshal(data, &set); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, k := range set.Keys {
		if k.Kid == kid {
			return fmt.Errorf("%s already holds a key under %q", path, kid)
		}
	}
	set.Keys = append(set.Keys, keys.PublicJWK(kid, pub))
	out, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	// Refuse to write a trust file the verifier could not read back.
	if _, err := keys.Parse(out); err != nil {
		return err
	}
	return replace(path, append(out, '\n'), 0o644)
}

// saveConfig rewrites the configuration file. Load rejects unknown fields, so
// what was read round-trips; defaults it filled in are written out explicitly.
func saveConfig(path string, cfg *config.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return replace(path, append(data, '\n'), 0o644)
}

func cmdRotateKey(ctx context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("rotate-key", out)
	cfgPath := configFlag(fs)
	newKid := fs.String("kid", "", "key ID for the incoming receipt-signing key")
	reason := fs.String("reason", "scheduled rotation", "why the outgoing key is being retired, recorded in the log")
	ttl := fs.Duration("ttl", 365*24*time.Hour, "how long the incoming key's epoch certificate is valid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newKid == "" {
		return errors.New("--kid is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *newKid == cfg.Kid {
		return fmt.Errorf("this chain already signs with %q; the incoming key needs a key ID of its own", cfg.Kid)
	}
	// A key ID names one key for the life of a chain: the genesis parameters and
	// every rotation bind a kid to a key digest. Reusing a retired one would
	// leave two different keys answering to the same name, and no verifier could
	// resolve that. Refuse before anything is written.
	if trusted, err := trustedKeys(cfg); err == nil {
		if _, used := trusted[*newKid]; used {
			return fmt.Errorf("%s already holds a key under %q; the chain has used that key ID, so the incoming key needs a new one",
				trustFile(cfg), *newKid)
		}
	}
	// Both are needed to hand a chain over: the outgoing key signs the handover,
	// and the CA certifies the key taking over (ADR-0016).
	ca, err := loadCA(cfg)
	if err != nil {
		return err
	}
	outgoing, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		return err
	}

	incoming, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		return err
	}
	now := time.Now()
	epochDER, err := ca.IssueKeyEpoch(*newKid, incoming.Public(), now.Add(-time.Minute), now.Add(*ttl))
	if err != nil {
		return err
	}

	// The incoming key gets files of its own. keyfile never overwrites, so a key
	// already in use cannot be replaced by accident.
	keyPath, certPath := filepath.Join("pki", "receipt-"+*newKid+".key"), filepath.Join("pki", "receipt-"+*newKid+".pem")
	absKey, absCert := cfg.Path(keyPath), cfg.Path(certPath)
	written := false
	cleanup := func() {
		if !written {
			os.Remove(absKey)
			os.Remove(absCert)
		}
	}
	if err := keyfile.WriteComposite(absKey, incoming); err != nil {
		return err
	}
	defer cleanup()
	if err := keyfile.WriteCertificate(absCert, epochDER); err != nil {
		return err
	}

	st, err := store.Open(cfg.Path(cfg.Store), outgoing, cfg.Kid, cfg.ChainID)
	if err != nil {
		return fmt.Errorf("%w\n(stop Warden before rotating: a running server holds the outgoing key)", err)
	}
	defer st.Close()

	r := &receipt.Receipt{
		V: receipt.Version, Domain: receipt.Domain,
		TS:   now.UTC().Format(receipt.TimeFormat),
		Type: receipt.TypeKeyRotation,
		Rotation: &receipt.Rotation{
			From: cfg.Kid, To: *newKid,
			Key:         digest.SHA256(incoming.Public().Bytes()),
			Certificate: base64.RawURLEncoding.EncodeToString(epochDER),
			Reason:      *reason,
		},
	}
	a, err := st.Rotate(ctx, r, incoming)
	if err != nil {
		return err
	}
	// The log has handed over. From here the new files must be kept, and a
	// failure leaves the operator something to fix rather than something to undo.
	written = true
	if err := addTrustedKey(cfg, *newKid, incoming.Public()); err != nil {
		return fmt.Errorf("the log rotated to %s at receipt #%d, but the trust file was not updated: %w", *newKid, a.Seq, err)
	}
	retiredKey := cfg.Path(cfg.ReceiptKey)
	cfg.Kid, cfg.ReceiptKey, cfg.ReceiptCert = *newKid, keyPath, certPath
	if err := saveConfig(*cfgPath, cfg); err != nil {
		return fmt.Errorf("the log rotated to %s at receipt #%d, but %s still names the old key: %w", *newKid, a.Seq, *cfgPath, err)
	}

	fmt.Fprintf(out, "Rotated %s to %s at receipt #%d.\n\n", r.Rotation.From, *newKid, a.Seq)
	fmt.Fprintf(out, "  private key  %s (mode 0600)\n  certificate  %s\n  trust file   %s\n  config       %s\n\n",
		absKey, absCert, trustFile(cfg), *cfgPath)
	fmt.Fprintf(out, "The outgoing key signed the handover and signs nothing further. Restart Warden\n"+
		"to pick up the new key. Keep %s: the receipts it signed are still verified with it.\n", retiredKey)
	return nil
}

func cmdRevokeKey(_ context.Context, args []string, stdin io.Reader, out io.Writer) error {
	fs := flags("revoke-key", out)
	cfgPath := configFlag(fs)
	kid := fs.String("kid", "", "the key ID to withdraw trust in")
	size := fs.Int64("size", 0, "size of the last checkpoint believed good (default: the newest anchored checkpoint)")
	reason := fs.String("reason", "", "why trust is being withdrawn, recorded in the revocation")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kid == "" {
		return errors.New("--kid is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	// The root signs revocations: it is the one authority a stolen receipt key
	// cannot impersonate (ADR-0016).
	ca, err := loadCA(cfg)
	if err != nil {
		return fmt.Errorf("revoking a key needs the root: %w", err)
	}
	trusted, err := trustedKeys(cfg)
	if err != nil {
		return err
	}
	if _, ok := trusted[*kid]; !ok {
		known := make([]string, 0, len(trusted))
		for k := range trusted {
			known = append(known, k)
		}
		slices.Sort(known)
		return fmt.Errorf("no key %q in %s (known: %s)", *kid, trustFile(cfg), strings.Join(known, ", "))
	}

	// A revocation is only meaningful against an anchored checkpoint: that is
	// what makes "believed good up to here" checkable by someone else.
	anchorData, err := os.ReadFile(cfg.Path(cfg.Anchor))
	if err != nil {
		return fmt.Errorf("revoking a key needs an anchored checkpoint: %w", err)
	}
	cps, err := checkpoint.ReadVerified(bytes.NewReader(anchorData), cfg.ChainID, keys.Resolver(trusted))
	if err != nil {
		return err
	}
	if len(cps) == 0 {
		return fmt.Errorf("%s holds no checkpoints for chain %s", cfg.Path(cfg.Anchor), cfg.ChainID)
	}
	cp := cps[len(cps)-1]
	if *size != 0 {
		i := slices.IndexFunc(cps, func(c *checkpoint.Checkpoint) bool { return c.Size == *size })
		if i < 0 {
			sizes := make([]string, len(cps))
			for j, c := range cps {
				sizes[j] = fmt.Sprint(c.Size)
			}
			return fmt.Errorf("no anchored checkpoint of size %d (anchored: %s)", *size, strings.Join(sizes, ", "))
		}
		cp = cps[i]
	}

	r := &revocation.Revocation{
		V: revocation.Version, Domain: revocation.Domain,
		ChainID: cfg.ChainID, Kid: *kid,
		EffectiveSize: cp.Size, EffectiveHead: cp.Head,
		Reason: *reason,
		TS:     time.Now().UTC().Format(receipt.TimeFormat),
	}
	if err := r.Validate(); err != nil {
		return err
	}

	fmt.Fprintf(out, "Revoke %s on chain %s, effective from the checkpoint of size %d (%s).\n",
		*kid, cfg.ChainID, cp.Size, cp.TS)
	fmt.Fprintf(out, "Receipts 0 to %d keep verifying. Anything %s signed from receipt #%d onward\n"+
		"will be refused, by everyone, permanently.\n", cp.Size-1, *kid, cp.Size)
	if !*yes {
		fmt.Fprint(out, "Publish this revocation? [y/N] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			return errors.New("not published")
		}
	}

	signed, err := revocation.Sign(ca.Key, r)
	if err != nil {
		return err
	}
	path := cfg.Path(cfg.Revocations)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := revocation.Publish(path, signed); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nPublished to %s.\n\n", path)
	fmt.Fprintf(out, "Send it where the anchor goes: a revocation Warden's operator can delete\n"+
		"protects no one. Verify with:\n  go run ./cmd/warden-verify --log LOG --chain %s --keys %s --anchor %s --revocations %s\n",
		cfg.ChainID, trustFile(cfg), cfg.Path(cfg.Anchor), path)
	return nil
}
