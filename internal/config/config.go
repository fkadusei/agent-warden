// Package config loads warden.json, the configuration for `warden serve` and the
// administrative subcommands. Relative paths are resolved against the directory
// that holds the configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Duration is a time.Duration written as a string such as "60s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// TLS names Warden's PKI files.
type TLS struct {
	CACert string `json:"ca_cert"`
	// CAKey is used only by issue-task; serve does not read it.
	CAKey      string `json:"ca_key,omitempty"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
}

// Server is an upstream tool server: a Streamable HTTP URL or a stdio command.
type Server struct {
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Command []string `json:"command,omitempty"`
}

// Config is warden.json.
type Config struct {
	ChainID        string `json:"chain_id"`
	Kid            string `json:"kid"`
	Listen         string `json:"listen"`
	ApproverListen string `json:"approver_listen"`
	TLS            TLS    `json:"tls"`

	ReceiptKey  string `json:"receipt_key"`
	ReceiptCert string `json:"receipt_cert,omitempty"`
	Store       string `json:"store"`
	Anchor      string `json:"anchor"`

	CheckpointEvery    int64    `json:"checkpoint_every"`
	CheckpointInterval Duration `json:"checkpoint_interval"`

	Policy     string `json:"policy"`
	Pins       string `json:"pins"`
	Broker     string `json:"broker"`
	SecretsDir string `json:"secrets_dir,omitempty"`
	Approvers  string `json:"approvers"`

	// Roles maps a principal to its roles for policy.
	Roles map[string][]string `json:"roles,omitempty"`
	// Taint maps a server to the taint label its output adds.
	Taint map[string]string `json:"taint,omitempty"`
	// ToolTaint maps a tool ID ("server/tool") to the label its output adds, such as
	// "pii" for a customer lookup; it takes precedence over the server's label.
	ToolTaint map[string]string `json:"tool_taint,omitempty"`

	// TSA, if set, timestamps each checkpoint with an RFC 3161 authority (ADR-0014).
	TSA *TSA `json:"tsa,omitempty"`

	Servers []Server `json:"servers"`

	dir string
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("config: %s: trailing data", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.dir = filepath.Dir(abs)
	if c.CheckpointEvery == 0 {
		c.CheckpointEvery = 100
	}
	if c.CheckpointInterval.Duration == 0 {
		c.CheckpointInterval.Duration = time.Minute
	}
	if c.TSA != nil {
		if c.TSA.Timeout.Duration == 0 {
			c.TSA.Timeout.Duration = 10 * time.Second
		}
		if c.TSA.Tokens == "" {
			c.TSA.Tokens = "data/tokens.jsonl"
		}
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	required := map[string]string{
		"chain_id": c.ChainID, "kid": c.Kid, "listen": c.Listen, "approver_listen": c.ApproverListen,
		"tls.ca_cert": c.TLS.CACert, "tls.server_cert": c.TLS.ServerCert, "tls.server_key": c.TLS.ServerKey,
		"receipt_key": c.ReceiptKey, "store": c.Store, "anchor": c.Anchor,
		"policy": c.Policy, "pins": c.Pins, "broker": c.Broker, "approvers": c.Approvers,
	}
	for field, v := range required {
		if v == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if len(c.Servers) == 0 {
		return errors.New("at least one server is required")
	}
	if c.CheckpointEvery < 1 || c.CheckpointInterval.Duration < time.Second {
		return errors.New("checkpoint_every must be at least 1 and checkpoint_interval at least 1s")
	}
	if c.Listen == c.ApproverListen {
		return errors.New("listen and approver_listen must differ")
	}
	for id, label := range c.ToolTaint {
		server, tool, ok := strings.Cut(id, "/")
		if !ok || server == "" || tool == "" || strings.Contains(tool, "/") {
			return fmt.Errorf("tool_taint key %q must be server/tool", id)
		}
		if label == "" {
			return fmt.Errorf("tool_taint label for %q is empty", id)
		}
	}
	for server, label := range c.Taint {
		if server == "" || label == "" {
			return errors.New("taint entries need a server and a label")
		}
	}
	if c.TSA != nil {
		if !strings.HasPrefix(c.TSA.URL, "http://") && !strings.HasPrefix(c.TSA.URL, "https://") {
			return errors.New("tsa.url must be an http or https URL")
		}
		if c.TSA.Timeout.Duration < time.Second {
			return errors.New("tsa.timeout must be at least 1s")
		}
	}
	return nil
}

// TSA is an RFC 3161 timestamp authority. Timestamps are evidence about when a
// checkpoint existed; Warden keeps working when the authority does not (ADR-0014).
type TSA struct {
	URL     string   `json:"url"`
	Timeout Duration `json:"timeout,omitempty"`
	// Tokens is where timestamps are appended, beside the anchor.
	Tokens string `json:"tokens,omitempty"`
}

// Label returns the taint label a tool's output adds: its tool_taint entry if
// present, otherwise its server's taint entry, otherwise "".
func (c *Config) Label(server, tool string) string {
	if l, ok := c.ToolTaint[server+"/"+tool]; ok {
		return l
	}
	return c.Taint[server]
}

// Path resolves p against the configuration file's directory.
func (c *Config) Path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// Dir is the directory holding the configuration file.
func (c *Config) Dir() string { return c.dir }
