package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
	"github.com/fkadusei/agent-warden/internal/anchor/s3/s3fake"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/store"
)

// Synthetic credentials for the in-process store only.
var storeCreds = s3.Credentials{AccessKeyID: "WARDENTESTKEY", SecretAccessKey: "warden-test-secret-not-real"}

// withAnchorStore points cfg at a fresh in-process object store.
func withAnchorStore(t *testing.T, cfg *config.Config) (*s3fake.Server, *s3.Client) {
	t.Helper()
	fake := s3fake.New("anchors", "eu-west-1", storeCreds)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	cfg.AnchorStore = &config.AnchorStore{Endpoint: srv.URL, Region: "eu-west-1", Bucket: "anchors",
		Prefix: "warden", PathStyle: true, RetentionDays: 30, Timeout: config.Duration{Duration: 5 * time.Second}}
	t.Setenv(config.EnvAnchorAccessKeyID, storeCreds.AccessKeyID)
	t.Setenv(config.EnvAnchorSecretAccessKey, storeCreds.SecretAccessKey)
	return fake, &s3.Client{Endpoint: srv.URL, Region: "eu-west-1", Bucket: "anchors", PathStyle: true, Creds: storeCreds}
}

// openCheckpointer opens the log and a checkpointer over it, as serve does.
func openCheckpointer(t *testing.T, cfg *config.Config, out *bytes.Buffer) (*store.Store, *checkpointer) {
	t.Helper()
	key, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.Path(cfg.Store), key, cfg.Kid, cfg.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c, err := newCheckpointer(st, key, cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	return st, c
}

func appendTo(t *testing.T, st *store.Store, n int) {
	t.Helper()
	for range n {
		if _, err := st.Append(context.Background(), decisionAt(st.Next())); err != nil {
			t.Fatal(err)
		}
	}
}

// anchorLines returns the file anchor's lines.
func anchorLines(t *testing.T, cfg *config.Config) [][]byte {
	t.Helper()
	data, err := os.ReadFile(cfg.Path(cfg.Anchor))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimSpace(data), []byte("\n"))
}

// requireStored checks that the store holds exactly line for the checkpoint of
// size, locked in compliance mode.
func requireStored(t *testing.T, client *s3.Client, cfg *config.Config, size int64, line []byte) {
	t.Helper()
	name := s3.ObjectName("warden", cfg.ChainID, size)
	obj, err := client.Get(context.Background(), name, "")
	if err != nil {
		t.Fatalf("checkpoint %d not in the store: %v", size, err)
	}
	if !bytes.Equal(obj.Body, line) {
		t.Fatalf("store holds %q for size %d, file anchor holds %q", obj.Body, size, line)
	}
	if obj.LockMode != s3.LockCompliance || obj.RetainUntil.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("checkpoint %d stored with lock %q until %v", size, obj.LockMode, obj.RetainUntil)
	}
}

func TestCheckpointsReachTheAnchorStore(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	fake, client := withAnchorStore(t, cfg)
	var out bytes.Buffer
	st, c := openCheckpointer(t, cfg, &out)

	appendTo(t, st, 3)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	appendTo(t, st, 2)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	lines := anchorLines(t, cfg)
	if len(lines) != 2 {
		t.Fatalf("%d file-anchored checkpoints, want 2", len(lines))
	}
	requireStored(t, client, cfg, 3, lines[0])
	requireStored(t, client, cfg, 5, lines[1])
	if n := len(fake.Keys()); n != 2 {
		t.Fatalf("%d objects in the store, want 2", n)
	}
	if out.Len() != 0 {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

// A store that is down costs evidence, never availability: checkpoints keep
// going to the file anchor, retries wait, and the newest checkpoint lands when
// the store returns, even if the log has gone quiet.
func TestAnUnreachableStoreNeverStopsCheckpointing(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	fake, client := withAnchorStore(t, cfg)
	var out bytes.Buffer
	st, c := openCheckpointer(t, cfg, &out)

	fake.SetDown(true)
	appendTo(t, st, 3)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatalf("a store that is down failed the checkpoint: %v", err)
	}
	if len(anchorLines(t, cfg)) != 1 {
		t.Fatal("the file anchor did not get the checkpoint")
	}
	if !strings.Contains(out.String(), "anchor store unreachable (attempt 1") {
		t.Fatalf("output:\n%s", out.String())
	}
	// The next tick is inside the wait, so it does not try again.
	if err := c.checkpoint(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if c.failures != 1 {
		t.Fatalf("%d attempts, want 1 while waiting", c.failures)
	}
	// The log grows while the store is down: the newer checkpoint replaces the
	// pending one, since it covers everything the older one did.
	appendTo(t, st, 2)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if c.pending == nil || c.pending.c.Size != 5 {
		t.Fatalf("pending checkpoint %+v, want size 5", c.pending)
	}

	fake.SetDown(false)
	c.nextTry = time.Time{} // the wait has passed
	if err := c.checkpoint(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if c.pending != nil {
		t.Fatal("the newest checkpoint is still pending after the store returned")
	}
	requireStored(t, client, cfg, 5, anchorLines(t, cfg)[1])
	if !strings.Contains(out.String(), "checkpoint at size 5 anchored after 2 failed attempts") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	fake, _ := withAnchorStore(t, cfg)
	var out bytes.Buffer
	st, c := openCheckpointer(t, cfg, &out)
	fake.SetDown(true)
	appendTo(t, st, 1)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var last time.Duration
	for range 12 {
		c.anchorExternally(context.Background(), c.nextTry, false)
		wait := c.nextTry.Sub(now)
		if wait <= last && wait < maxAnchorBackoff {
			t.Fatalf("wait %s did not grow from %s", wait, last)
		}
		last, now = wait, c.nextTry
	}
	if last != maxAnchorBackoff {
		t.Fatalf("wait settled at %s, want %s", last, maxAnchorBackoff)
	}
	if c.failures != 13 {
		t.Fatalf("%d attempts, want 13", c.failures)
	}
}

// A checkpoint file-anchored while the store was down, just before Warden
// stopped, is offered again when Warden starts.
func TestRestartOffersTheLastCheckpointAgain(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	fake, client := withAnchorStore(t, cfg)
	var out bytes.Buffer
	st, c := openCheckpointer(t, cfg, &out)
	fake.SetDown(true)
	appendTo(t, st, 4)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	st.Close()

	fake.SetDown(false)
	_, c2 := openCheckpointer(t, cfg, &out)
	if c2.pending == nil || c2.pending.c.Size != 4 {
		t.Fatalf("restart did not pick up the unanchored checkpoint: %+v", c2.pending)
	}
	if err := c2.checkpoint(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	requireStored(t, client, cfg, 4, anchorLines(t, cfg)[0])

	// Starting again once it is stored adds nothing.
	_, c3 := openCheckpointer(t, cfg, &out)
	if err := c3.checkpoint(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if n := fake.Puts(); n != 1 {
		t.Fatalf("%d versions stored, want 1", n)
	}
}

// A different checkpoint already under the same name means a fork or someone
// else writing to the store: reported, not retried, and never overwritten.
func TestAConflictingStoredCheckpointIsReported(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	fake, client := withAnchorStore(t, cfg)
	name := s3.ObjectName("warden", cfg.ChainID, 2)
	if _, err := client.PutLocked(context.Background(), name, []byte(`{"not":"this chain's checkpoint"}`),
		time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	st, c := openCheckpointer(t, cfg, &out)
	appendTo(t, st, 2)
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "WARNING: the anchor store already holds a different checkpoint at size 2") {
		t.Fatalf("output:\n%s", out.String())
	}
	if c.pending != nil {
		t.Fatal("a conflicting checkpoint is still being retried")
	}
	if n := len(fake.Versions(name)); n != 1 {
		t.Fatalf("%d versions under %s, want the original only", n, name)
	}
}

func TestTheAnchorStoreNeedsItsCredentialsAndASafeName(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	withAnchorStore(t, cfg)
	t.Setenv(config.EnvAnchorSecretAccessKey, "")
	key, err := keyfile.ReadComposite(cfg.Path(cfg.ReceiptKey))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.Path(cfg.Store), key, cfg.Kid, cfg.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := newCheckpointer(st, key, cfg, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), config.EnvAnchorSecretAccessKey) {
		t.Fatalf("missing secret: %v", err)
	}
	t.Setenv(config.EnvAnchorSecretAccessKey, storeCreds.SecretAccessKey)
	cfg.AnchorStore.Prefix = "../escape"
	if _, err := newCheckpointer(st, key, cfg, &bytes.Buffer{}); err == nil {
		t.Fatal("a prefix with a dot segment was accepted")
	}
}

// The store never holds up a tool call: with the store hanging, a checkpoint
// returns within the configured timeout rather than waiting on it.
func TestAHangingStoreIsCutOff(t *testing.T) {
	_, cfgPath := initChain(t)
	cfg := loadCfg(t, cfgPath)
	block := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	t.Cleanup(func() { close(block); hang.Close() })
	withAnchorStore(t, cfg)
	cfg.AnchorStore.Endpoint = hang.URL
	cfg.AnchorStore.Timeout.Duration = time.Second
	var out bytes.Buffer
	st, c := openCheckpointer(t, cfg, &out)
	appendTo(t, st, 1)
	start := time.Now()
	if err := c.checkpoint(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("checkpoint waited %s on a hanging store", d)
	}
	if !strings.Contains(out.String(), "anchor store unreachable") {
		t.Fatalf("output:\n%s", out.String())
	}
}
