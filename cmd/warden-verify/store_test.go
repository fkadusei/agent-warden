package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
	"github.com/fkadusei/agent-warden/internal/anchor/s3/s3fake"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// Synthetic credentials for the in-process store only.
var storeCreds = s3.Credentials{AccessKeyID: "WARDENTESTKEY", SecretAccessKey: "warden-test-secret-not-real"}

type storeFixture struct {
	fake   *s3fake.Server
	url    string
	anchor *s3.Anchor
	flags  []string
}

func newStore(t *testing.T) *storeFixture {
	t.Helper()
	fake := s3fake.New("anchors", "eu-west-1", storeCreds)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvAnchorAccessKeyID, storeCreds.AccessKeyID)
	t.Setenv(config.EnvAnchorSecretAccessKey, storeCreds.SecretAccessKey)
	client := &s3.Client{Endpoint: srv.URL, Region: "eu-west-1", Bucket: "anchors", PathStyle: true, Creds: storeCreds}
	return &storeFixture{fake: fake, url: srv.URL,
		anchor: &s3.Anchor{Client: client, Prefix: "audit", ChainID: chainID, Retention: 30 * 24 * time.Hour},
		flags: []string{"--store-endpoint", srv.URL, "--store-region", "eu-west-1", "--store-bucket", "anchors",
			"--store-prefix", "audit", "--store-path-style"}}
}

// checkpointOver signs a checkpoint over the first n lines, made at ts.
func checkpointOver(t *testing.T, f fixture, lines [][]byte, n int, ts time.Time) (*checkpoint.Checkpoint, *receipt.Signed) {
	t.Helper()
	b := checkpoint.NewBuilder(chainID)
	for _, l := range lines[:n] {
		b.Add(l)
	}
	c, err := b.Checkpoint(ts.UTC().Format(receipt.TimeFormat))
	if err != nil {
		t.Fatal(err)
	}
	s, err := checkpoint.Sign(f.key, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func (st *storeFixture) publish(t *testing.T, c *checkpoint.Checkpoint, s *receipt.Signed) {
	t.Helper()
	if err := st.anchor.Publish(context.Background(), c, s); err != nil {
		t.Fatal(err)
	}
}

func (st *storeFixture) publishOver(t *testing.T, f fixture, n int, ts time.Time) {
	t.Helper()
	c, s := checkpointOver(t, f, f.lines, n, ts)
	st.publish(t, c, s)
}

// publishFileAnchor copies the fixture's file-anchored checkpoint into the store.
func (st *storeFixture) publishFileAnchor(t *testing.T, f fixture) {
	t.Helper()
	data, err := os.ReadFile(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	s, err := receipt.ParseLine([]byte(strings.TrimSpace(string(data))))
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkpoint.Verify(f.key.Public(), s)
	if err != nil {
		t.Fatal(err)
	}
	st.publish(t, c, s)
}

func (f fixture) args(extra ...string) []string {
	return append([]string{"--log", f.log, "--chain", chainID, "--keys", f.keys}, extra...)
}

func TestVerifiedAgainstTheStoreAndTheFile(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.publishFileAnchor(t, f)
	st.publishOver(t, f, 6, time.Now())

	code, out, errOut := runCLI(append(f.args("--anchor", f.anchor), st.flags...)...)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"VERIFIED", "6 receipts (2 anchored checkpoints)", "2 checkpoints in",
		"bucket anchors, audit/" + chainID + "/", "covers 6 receipts", "0 receipts after the store's newest checkpoint"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if errOut != "" {
		t.Errorf("stderr: %s", errOut)
	}

	code, out, _ = runCLI(append(f.args("--anchor", f.anchor, "--json"), st.flags...)...)
	var res result
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != exitVerified {
		t.Fatalf("exit %d, %v\n%s", code, err, out)
	}
	if res.Store == nil || len(res.Store.Checkpoints) != 2 || res.Store.Checkpoints[1].Object != s3.ObjectName("audit", chainID, 6) ||
		res.Store.Checkpoints[1].StoredAt.IsZero() || res.Store.Unanchored != 0 {
		t.Fatalf("store in JSON: %+v", res.Store)
	}
}

func TestVerifiedAgainstTheStoreAlone(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.publishFileAnchor(t, f)
	code, out, errOut := runCLI(append(f.args(), st.flags...)...)
	if code != exitVerified || !strings.Contains(out, "2 receipts after the store's newest checkpoint") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
}

// The case the store exists for: whoever runs Warden cuts the log back and
// rewrites the anchor file to match. The file agrees with the log; the store
// does not.
func TestTruncationIsCaughtAgainstTheStore(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.publishOver(t, f, 6, time.Now())

	write(t, f.log, f.lines[:4]) // the anchor file's checkpoint covers 4: still consistent
	if code, out, errOut := runCLI(f.args("--anchor", f.anchor)...); code != exitVerified {
		t.Fatalf("the file alone should not catch this: exit %d\n%s%s", code, out, errOut)
	}
	code, out, _ := runCLI(append(f.args("--anchor", f.anchor), st.flags...)...)
	if code != exitFailed || !strings.Contains(out, "FAILED") {
		t.Fatalf("truncation not caught against the store: exit %d\n%s", code, out)
	}
}

func TestTheFileAndTheStoreMustAgree(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	// Same size as the file's checkpoint, made at another time: different bytes.
	st.publishOver(t, f, 4, time.Now())
	code, out, _ := runCLI(append(f.args("--anchor", f.anchor), st.flags...)...)
	if code != exitFailed || !strings.Contains(out, "hold different checkpoints of size 4") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestStoreRulesFailVerification(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.publishFileAnchor(t, f)
	// Overwrite the checkpoint with an unlocked version, as an operator could.
	name := s3.ObjectName("audit", chainID, 4)
	req, _ := http.NewRequest("PUT", st.url+"/anchors/"+name, strings.NewReader("{}"))
	s3.Sign(req, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", storeCreds, "eu-west-1", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("overwrite: %v %v", err, resp)
	}
	resp.Body.Close()
	code, out, _ := runCLI(append(f.args("--anchor", f.anchor), st.flags...)...)
	if code != exitFailed || !strings.Contains(out, "anchor store") || !strings.Contains(out, "not locked") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestTheStoreTimeBoundsTheCheckpointTime(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.publishOver(t, f, 6, time.Now().Add(time.Hour))
	code, out, _ := runCLI(append(f.args(), st.flags...)...)
	if code != exitFailed || !strings.Contains(out, "but the store received it at") {
		t.Fatalf("a checkpoint dated after it was stored: exit %d\n%s", code, out)
	}
	if code, out, _ := runCLI(append(f.args("--store-skew", "2h"), st.flags...)...); code != exitVerified {
		t.Fatalf("within the allowed skew: exit %d\n%s", code, out)
	}
}

func TestAnEmptyStoreWarns(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	code, out, errOut := runCLI(append(f.args("--anchor", f.anchor), st.flags...)...)
	if code != exitVerified || !strings.Contains(out, "no checkpoints for this chain") ||
		!strings.Contains(errOut, noStoreCheckpointWarning) {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
}

func TestDeleteMarkersAreReported(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.publishFileAnchor(t, f)
	name := s3.ObjectName("audit", chainID, 4)
	req, _ := http.NewRequest("DELETE", st.url+"/anchors/"+name, nil)
	s3.Sign(req, s3.EmptyHash, storeCreds, "eu-west-1", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %v %v", err, resp)
	}
	resp.Body.Close()
	code, out, _ := runCLI(append(f.args(), st.flags...)...)
	if code != exitVerified || !strings.Contains(out, "delete marker on "+name) || !strings.Contains(out, "1 checkpoints in") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestStoreUsageErrors(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	st.fake.SetDown(true)
	if code, _, errOut := runCLI(append(f.args(), st.flags...)...); code != exitUsage || !strings.Contains(errOut, "unreadable") {
		t.Fatalf("a store that is down: exit %d %s", code, errOut)
	}
	st.fake.SetDown(false)
	for name, extra := range map[string][]string{
		"no region":            {"--store-endpoint", st.url, "--store-bucket", "anchors"},
		"plain http":           {"--store-endpoint", "http://s3.example.com", "--store-region", "r", "--store-bucket", "anchors"},
		"short timeout":        append(append([]string{}, st.flags...), "--store-timeout", "1ms"),
		"revocations, no root": append(append([]string{}, st.flags...), "--revocations", f.anchor),
	} {
		if code, _, _ := runCLI(append(f.args(), extra...)...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, exitUsage)
		}
	}
	t.Setenv(config.EnvAnchorSecretAccessKey, "")
	if code, _, errOut := runCLI(append(f.args(), st.flags...)...); code != exitUsage ||
		!strings.Contains(errOut, config.EnvAnchorSecretAccessKey) {
		t.Fatalf("no credentials: exit %d %s", code, errOut)
	}
}

// Timestamps cover store checkpoints the anchor file does not hold.
func TestTimestampsOverStoreCheckpoints(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	c, s := checkpointOver(t, f, f.lines, 6, time.Now())
	st.publish(t, c, s)
	line, err := s.Line()
	if err != nil {
		t.Fatal(err)
	}
	tokens, roots := stampAnchor(t, f, line)
	code, out, errOut := runCLI(append(f.args("--anchor", f.anchor, "--tsa-tokens", tokens, "--tsa-roots", roots), st.flags...)...)
	if code != exitVerified || !strings.Contains(out, "1 verified") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	// Store alone, no anchor file: still an anchor for the timestamps.
	if code, out, errOut := runCLI(append(f.args("--tsa-tokens", tokens, "--tsa-roots", roots), st.flags...)...); code != exitVerified {
		t.Fatalf("store alone: exit %d\n%s%s", code, out, errOut)
	}
}

// A store checkpoint signed by a key the chain rotated to is verified with the
// key learned from the log, with no anchor file at all.
func TestARotatedChainVerifiesAgainstTheStore(t *testing.T) {
	f := newRotatedFixture(t)
	st := newStore(t)
	data, err := os.ReadFile(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	s, err := receipt.ParseLine([]byte(strings.TrimSpace(string(data))))
	if err != nil {
		t.Fatal(err)
	}
	st.publish(t, f.cp, s)
	code, out, errOut := runCLI(append([]string{"--log", f.log, "--chain", chainID, "--keys", f.keys, "--root", f.root},
		st.flags...)...)
	if code != exitVerified || !strings.Contains(out, "4 receipts (1 anchored checkpoints)") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
}

// putLocked writes a locked version unconditionally, as an operator with the
// store's credentials could.
func (st *storeFixture) putLocked(t *testing.T, name string, body []byte) {
	t.Helper()
	req, _ := http.NewRequest("PUT", st.url+"/anchors/"+name, bytes.NewReader(body))
	md := md5.Sum(body)
	sum := sha256.Sum256(body)
	req.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString(md[:]))
	req.Header.Set("X-Amz-Object-Lock-Mode", s3.LockCompliance)
	req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339))
	s3.Sign(req, hex.EncodeToString(sum[:]), storeCreds, "eu-west-1", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("locked put: %v %v", err, resp)
	}
	resp.Body.Close()
}

// A real checkpoint filed under the wrong size would let a store claim more
// coverage than it has.
func TestAnObjectMustHoldTheCheckpointItIsNamedFor(t *testing.T) {
	f := newFixture(t)
	st := newStore(t)
	_, s := checkpointOver(t, f, f.lines, 4, time.Now())
	line, err := s.Line()
	if err != nil {
		t.Fatal(err)
	}
	st.putLocked(t, s3.ObjectName("audit", chainID, 6), line)
	code, out, _ := runCLI(append(f.args(), st.flags...)...)
	if code != exitFailed || !strings.Contains(out, "holds a checkpoint of size 4") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
