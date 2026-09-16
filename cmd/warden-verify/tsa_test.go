package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/tsa"
)

// stampAnchor timestamps the fixture's anchor lines with a local authority and writes
// the token and root files warden-verify is given.
func stampAnchor(t *testing.T, f fixture, message []byte) (tokens, roots string) {
	t.Helper()
	now := time.Now()
	authority, err := tsa.NewAuthority("Test TSA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(authority.Handler())
	defer srv.Close()

	token, err := (&tsa.Client{URL: srv.URL}).Stamp(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	tokens, roots = f.path("tokens.jsonl"), f.path("tsa-roots.pem")
	if err := tsa.AppendToken(tokens, message, token); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roots, authority.RootPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return tokens, roots
}

func anchorLine(t *testing.T, f fixture) []byte {
	t.Helper()
	data, err := os.ReadFile(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(data)
}

func TestTimestampsVerified(t *testing.T) {
	f := newFixture(t)
	tokens, roots := stampAnchor(t, f, anchorLine(t, f))
	code, out, errOut := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor,
		"--tsa-tokens", tokens, "--tsa-roots", roots)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "VERIFIED") || !strings.Contains(out, "timestamps") || !strings.Contains(out, "1 verified") {
		t.Fatalf("output:\n%s", out)
	}
}

// A token over anything other than the anchored bytes fails verification.
func TestTimestampOverOtherDataFails(t *testing.T) {
	f := newFixture(t)
	tokens, roots := stampAnchor(t, f, append(anchorLine(t, f), ' '))
	code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor,
		"--tsa-tokens", tokens, "--tsa-roots", roots)
	// The token's digest names data that is not in the anchor, so nothing verifies it.
	if code != exitVerified || strings.Contains(out, "timestamps") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}

	// Now claim that token covers the real anchor line: the digest matches, the
	// content does not.
	line := anchorLine(t, f)
	data, err := os.ReadFile(tokens)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tsa.ReadTokens(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var token []byte
	for _, ts := range parsed {
		token = ts[0]
	}
	relabelled := f.path("relabelled.jsonl")
	if err := os.Remove(relabelled); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := tsa.AppendToken(relabelled, line, token); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor,
		"--tsa-tokens", relabelled, "--tsa-roots", roots)
	if code != exitFailed || !strings.Contains(out, "FAILED") || !strings.Contains(out, "timestamp") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
}

func TestTimestampFromAnUntrustedAuthorityFails(t *testing.T) {
	f := newFixture(t)
	tokens, _ := stampAnchor(t, f, anchorLine(t, f))
	_, otherRoots := stampAnchor(t, f, []byte("something else"))
	code, out, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys, "--anchor", f.anchor,
		"--tsa-tokens", tokens, "--tsa-roots", otherRoots)
	if code != exitFailed || !strings.Contains(out, "timestamp") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
}

func TestTimestampFlagsNeedEachOther(t *testing.T) {
	f := newFixture(t)
	tokens, roots := stampAnchor(t, f, anchorLine(t, f))
	for _, args := range [][]string{
		{"--tsa-tokens", tokens},
		{"--tsa-roots", roots},
	} {
		code, _, errOut := runCLI(append([]string{"--log", f.log, "--chain", chainID, "--keys", f.keys,
			"--anchor", f.anchor}, args...)...)
		if code != exitUsage {
			t.Fatalf("%v: exit %d\n%s", args, code, errOut)
		}
	}
	// Tokens without an anchor have nothing to cover.
	code, _, _ := runCLI("--log", f.log, "--chain", chainID, "--keys", f.keys,
		"--tsa-tokens", tokens, "--tsa-roots", roots)
	if code != exitUsage {
		t.Fatalf("exit %d without --anchor", code)
	}
}
