package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const good = `{
  "chain_id": "c1", "kid": "k1",
  "listen": "127.0.0.1:8443", "approver_listen": "127.0.0.1:8444",
  "tls": {"ca_cert": "pki/ca.pem", "ca_key": "pki/ca.key", "server_cert": "pki/server.pem", "server_key": "pki/server.key"},
  "receipt_key": "pki/receipt.key", "store": "data/receipts.db", "anchor": "data/anchor.jsonl",
  "policy": "policy.cedar", "pins": "pins.json", "broker": "broker.json", "approvers": "approvers.json",
  "roles": {"alice@tenant-a": ["support"]}, "taint": {"web": "web"},
  "servers": [{"name": "crm", "url": "http://127.0.0.1:9100/crm"}]
}`

func write(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "warden.json")
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	p := write(t, good)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path("pins.json") != filepath.Join(filepath.Dir(p), "pins.json") {
		t.Fatalf("relative path resolved to %s", c.Path("pins.json"))
	}
	if c.Path("/etc/x") != "/etc/x" {
		t.Fatal("absolute path changed")
	}
	if c.CheckpointEvery != 100 || c.CheckpointInterval.Duration != time.Minute {
		t.Fatalf("defaults %d %s", c.CheckpointEvery, c.CheckpointInterval)
	}
	if c.Roles["alice@tenant-a"][0] != "support" || c.Taint["web"] != "web" {
		t.Fatal("roles or taint not loaded")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":      strings.Replace(good, `"kid": "k1"`, `"kid": "k1", "debug": true`, 1),
		"missing chain_id":   strings.Replace(good, `"chain_id": "c1", `, ``, 1),
		"no servers":         strings.Replace(good, `[{"name": "crm", "url": "http://127.0.0.1:9100/crm"}]`, `[]`, 1),
		"same listeners":     strings.Replace(good, `"127.0.0.1:8444"`, `"127.0.0.1:8443"`, 1),
		"bad interval":       strings.Replace(good, `"kid": "k1"`, `"kid": "k1", "checkpoint_interval": "soon"`, 1),
		"too short interval": strings.Replace(good, `"kid": "k1"`, `"kid": "k1", "checkpoint_interval": "10ms"`, 1),
		"trailing data":      good + ` {}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if data == good {
				t.Fatal("mutation did not apply")
			}
			if _, err := Load(write(t, data)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
