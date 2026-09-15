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
	return nil
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
