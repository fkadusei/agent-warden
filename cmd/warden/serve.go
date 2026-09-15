package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fkadusei/agent-warden/internal/approverapi"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/inspect"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/mcpgw"
	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/store"
	"github.com/fkadusei/agent-warden/internal/upstream"
)

func cmdServe(ctx context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("serve", out)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	return serve(ctx, cfg, out, nil)
}

type addrs struct{ Agent, Approver string }

// serve runs until ctx is done. ready, if set, is called once both listeners are up.
func serve(ctx context.Context, cfg *config.Config, out io.Writer, ready func(addrs)) error {
	caDER, err := keyfile.ReadCertificate(cfg.Path(cfg.TLS.CACert))
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	serverKey, err := keyfile.ReadMLDSA(cfg.Path(cfg.TLS.ServerKey))
	if err != nil {
		return err
	}
	serverDER, err := keyfile.ReadCertificate(cfg.Path(cfg.TLS.ServerCert))
	if err != nil {
		return err
	}
	serverCert := tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}

	receiptKey, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		return err
	}
	if cfg.ReceiptCert != "" {
		der, err := keyfile.ReadCertificate(cfg.Path(cfg.ReceiptCert))
		if err != nil {
			return err
		}
		ep, err := identity.VerifyKeyEpoch(der, pool, time.Now())
		if err != nil {
			return fmt.Errorf("receipt certificate: %w", err)
		}
		if ep.Kid != cfg.Kid || !bytes.Equal(ep.Key.Bytes(), receiptKey.Public().Bytes()) {
			return errors.New("receipt certificate does not match the configured kid and receipt key")
		}
	}

	st, err := store.Open(cfg.Path(cfg.Store), receiptKey, cfg.Kid, cfg.ChainID)
	if err != nil {
		return err
	}
	defer st.Close()

	policyText, err := os.ReadFile(cfg.Path(cfg.Policy))
	if err != nil {
		return err
	}
	eng, err := policy.Load(cfg.Policy, policyText)
	if err != nil {
		return err
	}
	pins, err := os.ReadFile(cfg.Path(cfg.Pins))
	if err != nil {
		return fmt.Errorf("%w (run `warden pin --write` after reviewing the tools)", err)
	}
	reg, err := registry.Load(pins)
	if err != nil {
		return err
	}
	brk, err := loadBroker(cfg)
	if err != nil {
		return err
	}
	approvers, err := loadApprovers(cfg.Path(cfg.Approvers))
	if err != nil {
		return err
	}

	servers, names := upstreamServers(cfg)
	up, err := upstream.Connect(ctx, servers, brk, nil)
	if err != nil {
		return err
	}
	defer up.Close()

	// The inspector looks for directives naming the exposed tools, which are known
	// only once the handler is built; it is set before anything is served.
	var toolNames []string
	gw, err := gateway.New(gateway.Config{
		Store: st, Registry: reg, Policy: eng, Broker: brk, Roots: pool, Approvers: approvers, Upstream: up,
		Roles:   func(p string) []string { return cfg.Roles[p] },
		Taint:   func(server, _ string) string { return cfg.Taint[server] },
		Inspect: func(content string) []string { return inspect.Flags(inspect.Inspect(content, toolNames)) },
	})
	if err != nil {
		return err
	}
	handler, exposed, err := mcpgw.NewHandler(ctx, gw, reg, up, names)
	if err != nil {
		return err
	}
	toolNames = exposed.Tools

	agentLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	approverLn, err := net.Listen("tcp", cfg.ApproverListen)
	if err != nil {
		agentLn.Close()
		return err
	}
	agentSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13,
	}}
	approverSrv := &http.Server{Handler: approverapi.NewServer(gw, st, approvers, nil).Handler(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}}

	errc := make(chan error, 2)
	go func() { errc <- agentSrv.ServeTLS(agentLn, "", "") }()
	go func() { errc <- approverSrv.ServeTLS(approverLn, "", "") }()

	cp, err := newCheckpointer(st, receiptKey, cfg)
	if err != nil {
		agentSrv.Close()
		approverSrv.Close()
		return err
	}
	cpCtx, stopCP := context.WithCancel(ctx)
	var cpDone sync.WaitGroup
	cpDone.Add(1)
	go func() { defer cpDone.Done(); cp.run(cpCtx, out) }()

	fmt.Fprintf(out, "Warden serving chain %s\n  agents (MCP, mutual TLS): https://%s\n  approvers:                https://%s\n",
		cfg.ChainID, agentLn.Addr(), approverLn.Addr())
	fmt.Fprintf(out, "  tools exposed: %v\n", exposed.Tools)
	for id, reason := range exposed.Withheld {
		fmt.Fprintf(out, "  withheld %s: %s\n", id, reason)
	}
	if ready != nil {
		ready(addrs{Agent: agentLn.Addr().String(), Approver: approverLn.Addr().String()})
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agentSrv.Shutdown(shutdownCtx)
	approverSrv.Shutdown(shutdownCtx)
	stopCP()
	cpDone.Wait()
	if err := cp.checkpoint(context.Background(), true); err != nil {
		fmt.Fprintf(out, "final checkpoint failed: %v\n", err)
	}
	fmt.Fprintln(out, "Warden stopped.")
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}

func loadApprovers(path string) (func(string) (*composite.PublicKey, error), error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return func(kid string) (*composite.PublicKey, error) {
			return nil, fmt.Errorf("no approvers are configured")
		}, nil
	}
	if err != nil {
		return nil, err
	}
	trusted, err := keys.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return keys.Resolver(trusted), nil
}

// checkpointer periodically signs checkpoints over the receipt log and appends
// them to the anchor file.
type checkpointer struct {
	st     *store.Store
	key    *composite.PrivateKey
	kid    string
	chain  string
	anchor string
	policy checkpoint.Policy

	mu       sync.Mutex
	lastSize int64
	lastAt   time.Time
}

func newCheckpointer(st *store.Store, key *composite.PrivateKey, cfg *config.Config) (*checkpointer, error) {
	c := &checkpointer{
		st: st, key: key, kid: cfg.Kid, chain: cfg.ChainID, anchor: cfg.Path(cfg.Anchor),
		policy: checkpoint.Policy{Every: cfg.CheckpointEvery, Interval: cfg.CheckpointInterval.Duration},
		lastAt: time.Now(),
	}
	data, err := os.ReadFile(c.anchor)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	resolve := func(kid string) (*composite.PublicKey, error) {
		if kid == c.kid {
			return key.Public(), nil
		}
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	cps, err := checkpoint.ReadVerified(bytes.NewReader(data), c.chain, resolve)
	if err != nil {
		return nil, fmt.Errorf("existing anchor: %w", err)
	}
	if len(cps) > 0 {
		c.lastSize = cps[len(cps)-1].Size
	}
	return c, nil
}

func (c *checkpointer) run(ctx context.Context, out io.Writer) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.checkpoint(ctx, false); err != nil {
				fmt.Fprintf(out, "checkpoint failed: %v\n", err)
			}
		}
	}
}

func (c *checkpointer) checkpoint(ctx context.Context, force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := c.st.Next()
	now := time.Now()
	if size == 0 || size <= c.lastSize || (!force && !c.policy.Due(c.lastSize, size, c.lastAt, now)) {
		return nil
	}
	var buf bytes.Buffer
	if err := c.st.Export(ctx, &buf); err != nil {
		return err
	}
	b := checkpoint.NewBuilder(c.chain)
	for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
		b.Add(line)
	}
	cp, err := b.Checkpoint(now.UTC().Format(receipt.TimeFormat))
	if err != nil {
		return err
	}
	signed, err := checkpoint.Sign(c.key, c.kid, cp)
	if err != nil {
		return err
	}
	if err := (checkpoint.FileAnchor{Path: c.anchor}).Publish(signed); err != nil {
		return err
	}
	c.lastSize, c.lastAt = cp.Size, now
	return nil
}
