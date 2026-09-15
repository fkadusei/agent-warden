package main

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fkadusei/agent-warden/internal/broker"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/exampletools"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/store"
	"github.com/fkadusei/agent-warden/internal/upstream"
)

const examplePolicy = `// Example policy for the example tool servers. Every policy needs a unique @id.

// Support staff can use the CRM without approval.
@id("support_crm")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource in Server::"crm");

// Refunds need a human approver...
@id("refunds_need_approval")
permit (principal in Role::"support", action == Action::"call", resource == Tool::"payments/refund");

// ...unless they are small.
@id("small_refunds_unattended")
permit (principal in Role::"support", action == Action::"call_unattended", resource == Tool::"payments/refund")
when { context.args.amount <= 100 };

@id("web_fetch")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"web/fetch");

@id("mail_allowed")
permit (principal in Role::"support", action in [Action::"call", Action::"call_unattended"], resource == Tool::"mail/send");

// Once untrusted web content is in the task, no email goes out.
@id("no_email_while_tainted")
forbid (principal, action, resource == Tool::"mail/send")
when { context.taint.contains("web") };

// Planted instructions or content written by another principal can still be read,
// but refunds and email then need a human approver.
@id("suspicious_content_needs_approval")
forbid (principal, action == Action::"call_unattended", resource)
when {
  (resource == Tool::"payments/refund" || resource == Tool::"mail/send") &&
  (context.taint.contains("flag:instruction") || context.taint.contains("foreign_principal"))
};

// Customer data never leaves the tenant by email.
@id("no_pii_outside_tenant")
forbid (principal, action, resource == Tool::"mail/send")
when { context.taint.contains("pii") && !(context.args.to like "*@tenant-a.example") };
`

const exampleBroker = `{
  "v": 1,
  "bindings": [
    {"server": "payments", "tool": "*", "inject": "header", "name": "Authorization", "prefix": "Bearer ", "secret": "env:WARDEN_SECRET_PAYMENTS"}
  ]
}
`

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func cmdInit(_ context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("init", out)
	dir := fs.String("dir", "warden-local", "directory to create")
	dns := fs.String("dns", "localhost", "comma-separated DNS names for Warden's server certificate")
	ipList := fs.String("ip", "127.0.0.1", "comma-separated IP addresses for Warden's server certificate")
	chainID := fs.String("chain", "", "chain ID (default: warden-<UTC time>)")
	kid := fs.String("kid", "warden-e1", "key ID for the receipt-signing key")
	toolsURL := fs.String("tools-url", "http://127.0.0.1:9100", "base URL of the example tool servers")
	listen := fs.String("listen", "127.0.0.1:8443", "agent MCP endpoint address")
	approverListen := fs.String("approver-listen", "127.0.0.1:8444", "approver API address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if entries, err := os.ReadDir(*dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty", *dir)
	}
	var ips []net.IP
	for _, s := range splitList(*ipList) {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("invalid IP address %q", s)
		}
		ips = append(ips, ip)
	}
	if *chainID == "" {
		*chainID = "warden-" + time.Now().UTC().Format("20060102T150405Z")
	}
	for _, d := range []string{"pki", "data", "secrets"} {
		if err := os.MkdirAll(filepath.Join(*dir, d), 0o700); err != nil {
			return err
		}
	}
	p := func(parts ...string) string { return filepath.Join(append([]string{*dir}, parts...)...) }
	now := time.Now()

	caKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	ca, err := identity.NewCA("Warden Local Root", caKey, now.Add(-time.Minute), now.AddDate(1, 0, 0))
	if err != nil {
		return err
	}
	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	serverDER, err := ca.IssueServer(splitList(*dns), ips, serverKey.PublicKey(), now.Add(-time.Minute), now.Add(identity.MaxServerLifetime-time.Hour))
	if err != nil {
		return err
	}
	receiptKey, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		return err
	}
	epochDER, err := ca.IssueKeyEpoch(*kid, receiptKey.Public(), now.Add(-time.Minute), now.AddDate(1, 0, 0))
	if err != nil {
		return err
	}
	for _, step := range []error{
		keyfile.WriteMLDSA(p("pki", "ca.key"), caKey),
		keyfile.WriteCertificate(p("pki", "ca.pem"), ca.Cert.Raw),
		keyfile.WriteMLDSA(p("pki", "server.key"), serverKey),
		keyfile.WriteCertificate(p("pki", "server.pem"), serverDER),
		keyfile.WriteComposite(p("pki", "receipt.key"), receiptKey),
		keyfile.WriteCertificate(p("pki", "receipt.pem"), epochDER),
	} {
		if step != nil {
			return step
		}
	}

	keySet, err := json.MarshalIndent(keys.Set{Keys: []keys.JWK{keys.PublicJWK(*kid, receiptKey.Public())}}, "", "  ")
	if err != nil {
		return err
	}
	base := strings.TrimSuffix(*toolsURL, "/")
	cfg := config.Config{
		ChainID: *chainID, Kid: *kid, Listen: *listen, ApproverListen: *approverListen,
		TLS:        config.TLS{CACert: "pki/ca.pem", CAKey: "pki/ca.key", ServerCert: "pki/server.pem", ServerKey: "pki/server.key"},
		ReceiptKey: "pki/receipt.key", ReceiptCert: "pki/receipt.pem",
		Store: "data/receipts.db", Anchor: "data/anchor.jsonl",
		CheckpointEvery: 100, CheckpointInterval: config.Duration{Duration: time.Minute},
		Policy: "policy.cedar", Pins: "pins.json", Broker: "broker.json", SecretsDir: "secrets", Approvers: "approvers.json",
		Roles:     map[string][]string{"alice@tenant-a": {"support"}},
		Taint:     map[string]string{"web": "web"},
		ToolTaint: map[string]string{"crm/lookup": "pii"},
	}
	for _, s := range exampletools.Servers {
		cfg.Servers = append(cfg.Servers, config.Server{Name: s, URL: base + "/" + s})
	}
	cfgData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
	}{
		{p("keys.json"), append(keySet, '\n')},
		{p("policy.cedar"), []byte(examplePolicy)},
		{p("broker.json"), []byte(exampleBroker)},
		{p("warden.json"), append(cfgData, '\n')},
	} {
		if err := writeNew(f.path, f.data, 0o644); err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "Created %s (chain %s, receipt key %s).\n\n", *dir, *chainID, *kid)
	fmt.Fprintln(out, "Private keys are in pki/ with mode 0600. Next:")
	fmt.Fprintf(out, "  1. Start the example tools:  EXAMPLE_PAYMENTS_TOKEN=demo go run ./cmd/example-tools\n")
	fmt.Fprintf(out, "  2. Review and pin the tools: go run ./cmd/warden pin --config %s --write\n", p("warden.json"))
	fmt.Fprintf(out, "  3. Add an approver:          go run ./cmd/warden add-approver --config %s --id bob@tenant-a --out %s\n", p("warden.json"), p("bob.key"))
	fmt.Fprintf(out, "  4. Issue an agent credential: go run ./cmd/warden issue-task --config %s --agent support-agent-7 --principal alice@tenant-a --task ticket-4821 --out %s\n", p("warden.json"), p("agent"))
	fmt.Fprintf(out, "  5. Run Warden:               WARDEN_SECRET_PAYMENTS=demo go run ./cmd/warden serve --config %s\n", p("warden.json"))
	return nil
}

// configFlag adds the --config flag shared by commands that read warden.json.
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", "warden-local/warden.json", "path to warden.json")
}

func loadBroker(cfg *config.Config) (*broker.Broker, error) {
	data, err := os.ReadFile(cfg.Path(cfg.Broker))
	if err != nil {
		return nil, err
	}
	return broker.Load(data, broker.Sources{Dir: cfg.Path(cfg.SecretsDir)})
}

func upstreamServers(cfg *config.Config) ([]upstream.Server, []string) {
	var servers []upstream.Server
	var names []string
	for _, s := range cfg.Servers {
		servers = append(servers, upstream.Server{Name: s.Name, URL: s.URL, Command: s.Command})
		names = append(names, s.Name)
	}
	return servers, names
}

func cmdPin(ctx context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("pin", out)
	cfgPath := configFlag(fs)
	write := fs.Bool("write", false, "write every listed tool to the pins file (after you have reviewed the list)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	brk, err := loadBroker(cfg)
	if err != nil {
		return err
	}
	servers, names := upstreamServers(cfg)
	up, err := upstream.Connect(ctx, servers, brk, nil)
	if err != nil {
		return err
	}
	defer up.Close()

	var existing *registry.Registry
	if data, err := os.ReadFile(cfg.Path(cfg.Pins)); err == nil {
		if existing, err = registry.Load(data); err != nil {
			return err
		}
	}
	var all []registry.Manifest
	for _, name := range names {
		ms, err := up.Tools(ctx, name)
		if err != nil {
			return err
		}
		for _, m := range ms {
			d, err := m.Digest()
			if err != nil {
				fmt.Fprintf(out, "  %-24s INVALID: %v\n", m.ID(), err)
				continue
			}
			status := "new"
			if existing != nil {
				switch _, err := existing.Check(m); {
				case err == nil:
					status = "pinned"
				case errors.Is(err, registry.ErrChanged):
					status = "CHANGED since pinned"
				}
			}
			fmt.Fprintf(out, "  %-24s %s  %s\n      %s\n", m.ID(), d, status, m.Description)
			all = append(all, m)
		}
	}
	if !*write {
		fmt.Fprintln(out, "\nReview the tools above, then run again with --write to pin them.")
		return nil
	}
	data, err := registry.PinAll(all)
	if err != nil {
		return err
	}
	if err := replace(cfg.Path(cfg.Pins), data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nPinned %d tools in %s.\n", len(all), cfg.Path(cfg.Pins))
	return nil
}

func cmdAddApprover(_ context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("add-approver", out)
	cfgPath := configFlag(fs)
	id := fs.String("id", "", "approver identity, e.g. bob@tenant-a (also the key ID)")
	keyOut := fs.String("out", "", "where to write the approver's private key (give it to the approver)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *keyOut == "" {
		return errors.New("--id and --out are required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	set := keys.Set{}
	path := cfg.Path(cfg.Approvers)
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &set); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, k := range set.Keys {
			if k.Kid == *id {
				return fmt.Errorf("approver %q already exists", *id)
			}
		}
	}
	k, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		return err
	}
	set.Keys = append(set.Keys, keys.PublicJWK(*id, k.Public()))
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	if _, err := keys.Parse(data); err != nil {
		return err
	}
	if err := keyfile.WriteComposite(*keyOut, k); err != nil {
		return err
	}
	if err := replace(path, append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Approver %s trusted in %s; private key written to %s (mode 0600).\n", *id, path, *keyOut)
	return nil
}

func loadCA(cfg *config.Config) (*identity.CA, error) {
	if cfg.TLS.CAKey == "" {
		return nil, errors.New("tls.ca_key is not configured")
	}
	key, err := keyfile.ReadMLDSA(cfg.Path(cfg.TLS.CAKey))
	if err != nil {
		return nil, err
	}
	der, err := keyfile.ReadCertificate(cfg.Path(cfg.TLS.CACert))
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &identity.CA{Cert: cert, Key: key}, nil
}

func cmdIssueTask(_ context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("issue-task", out)
	cfgPath := configFlag(fs)
	agent := fs.String("agent", "", "agent identity")
	principal := fs.String("principal", "", "the person the agent acts for")
	task := fs.String("task", "", "task identity")
	ttl := fs.Duration("ttl", identity.MaxTaskLifetime, "credential lifetime (at most 15m)")
	prefix := fs.String("out", "", "output prefix: writes PREFIX.pem and PREFIX.key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agent == "" || *principal == "" || *task == "" || *prefix == "" {
		return errors.New("--agent, --principal, --task, and --out are required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ca, err := loadCA(cfg)
	if err != nil {
		return err
	}
	agentKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	now := time.Now()
	der, err := ca.IssueTask(identity.TaskClaims{Agent: *agent, Principal: *principal, Task: *task},
		agentKey.PublicKey(), now.Add(-time.Minute), now.Add(*ttl))
	if err != nil {
		return err
	}
	if err := keyfile.WriteMLDSA(*prefix+".key", agentKey); err != nil {
		return err
	}
	if err := keyfile.WriteCertificate(*prefix+".pem", der); err != nil {
		return err
	}
	fmt.Fprintf(out, "Task credential for %s acting for %s on %s, valid until %s:\n  %s.pem\n  %s.key\n",
		*agent, *principal, *task, now.Add(*ttl).UTC().Format(time.RFC3339), *prefix, *prefix)
	return nil
}

func cmdExport(ctx context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("export", out)
	cfgPath := configFlag(fs)
	dest := fs.String("out", "", "file to write the receipt log to (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dest == "" {
		return errors.New("--out is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	key, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Path(cfg.Store), key, cfg.Kid, cfg.ChainID)
	if err != nil {
		return err
	}
	defer st.Close()
	f, err := os.OpenFile(*dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if err := st.Export(ctx, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Wrote %d receipts to %s. Verify with:\n  go run ./cmd/warden-verify --log %s --chain %s --keys %s --anchor %s\n",
		st.Next(), *dest, *dest, cfg.ChainID, filepath.Join(cfg.Dir(), "keys.json"), cfg.Path(cfg.Anchor))
	return nil
}
