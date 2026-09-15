// Package broker holds tool credentials on Warden's side of the boundary and
// hands them to tool transports at execution time (threat W3, design §2).
//
// The agent never receives a credential. A tool gets only the credentials bound
// to its server (or to it specifically); a binding whose secret cannot be
// resolved is an error, so the call is refused rather than run without it.
// Secret values print as [REDACTED] everywhere, and Scrub removes any credential
// a tool echoes back before its result reaches the agent.
package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Redacted is what a Secret prints as.
const Redacted = "[REDACTED]"

// EnvPrefix is required on every environment variable a binding reads, so a
// configuration cannot pull unrelated secrets from Warden's environment.
const EnvPrefix = "WARDEN_SECRET_"

const maxSecretSize = 64 << 10

// Secret is a credential value that never prints. Use Reveal only at the point
// the value is handed to a transport.
type Secret struct {
	v []byte
}

// Reveal returns the secret value.
func (s Secret) Reveal() string { return string(s.v) }

func (Secret) String() string               { return Redacted }
func (Secret) GoString() string             { return Redacted }
func (Secret) Format(f fmt.State, _ rune)   { f.Write([]byte(Redacted)) }
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// Inject says how a credential reaches the tool.
type Inject string

const (
	// Header sets an HTTP header on requests to the tool server.
	Header Inject = "header"
	// Env sets an environment variable for a stdio tool server process.
	Env Inject = "env"
)

// Credential is one value to inject for a call.
type Credential struct {
	Inject Inject
	Name   string
	Value  Secret
}

// Binding configures one credential.
type Binding struct {
	Server string `json:"server"`
	// Tool is a tool name, or "*" for every tool on the server.
	Tool   string `json:"tool"`
	Inject Inject `json:"inject"`
	Name   string `json:"name"`
	// Prefix is prepended to the secret, for example "Bearer ".
	Prefix string `json:"prefix,omitempty"`
	// Secret is "env:WARDEN_SECRET_..." or "file:<name>" within the secrets directory.
	Secret string `json:"secret"`
}

// Config is the broker configuration file.
type Config struct {
	V        int       `json:"v"`
	Bindings []Binding `json:"bindings"`
}

// Sources resolve secret references.
type Sources struct {
	// LookupEnv reads environment variables; os.LookupEnv if nil.
	LookupEnv func(string) (string, bool)
	// Dir holds file secrets; file references are refused if empty.
	Dir string
}

var (
	// ErrConfig is returned for an invalid configuration.
	ErrConfig = errors.New("broker: invalid configuration")
	// ErrSecret is returned when a bound secret cannot be resolved.
	ErrSecret = errors.New("broker: secret unavailable")
)

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	headerPattern  = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,128}$`)
	envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	fileRefPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

type bindingKey struct {
	server, tool string
}

// Broker resolves credentials for calls. It is safe for concurrent use.
type Broker struct {
	bindings map[bindingKey][]Binding
	sources  Sources
}

// Load parses a configuration. Secrets are not read until a call needs them, so
// rotated secrets take effect without reloading.
func Load(data []byte, src Sources) (*Broker, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrConfig)
	}
	if cfg.V != 1 {
		return nil, fmt.Errorf("%w: v is %d, want 1", ErrConfig, cfg.V)
	}
	if src.LookupEnv == nil {
		src.LookupEnv = os.LookupEnv
	}
	b := &Broker{bindings: map[bindingKey][]Binding{}, sources: src}
	type slot struct {
		server string
		inject Inject
		name   string
	}
	seen := map[slot][]string{} // tools per injected slot, to detect overlaps
	for i, bd := range cfg.Bindings {
		if err := checkBinding(bd, src); err != nil {
			return nil, fmt.Errorf("%w: binding %d: %v", ErrConfig, i, err)
		}
		s := slot{bd.Server, bd.Inject, canonicalName(bd.Inject, bd.Name)}
		for _, tool := range seen[s] {
			if tool == bd.Tool || tool == "*" || bd.Tool == "*" {
				return nil, fmt.Errorf("%w: binding %d: %s %q on server %q overlaps another binding", ErrConfig, i, bd.Inject, bd.Name, bd.Server)
			}
		}
		seen[s] = append(seen[s], bd.Tool)
		k := bindingKey{bd.Server, bd.Tool}
		b.bindings[k] = append(b.bindings[k], bd)
	}
	return b, nil
}

// canonicalName makes header names case-insensitive for overlap detection.
func canonicalName(inject Inject, name string) string {
	if inject == Header {
		return strings.ToLower(name)
	}
	return name
}

func checkBinding(bd Binding, src Sources) error {
	if !namePattern.MatchString(bd.Server) {
		return fmt.Errorf("server %q is not a valid name", bd.Server)
	}
	if bd.Tool != "*" && !namePattern.MatchString(bd.Tool) {
		return fmt.Errorf("tool %q is not a valid name or \"*\"", bd.Tool)
	}
	switch bd.Inject {
	case Header:
		if !headerPattern.MatchString(bd.Name) {
			return fmt.Errorf("header name %q is invalid", bd.Name)
		}
	case Env:
		if !envNamePattern.MatchString(bd.Name) {
			return fmt.Errorf("environment variable name %q is invalid", bd.Name)
		}
	default:
		return fmt.Errorf("unknown inject %q", bd.Inject)
	}
	if strings.ContainsAny(bd.Prefix, "\r\n\x00") {
		return errors.New("prefix contains a line break or NUL")
	}
	kind, ref, ok := strings.Cut(bd.Secret, ":")
	if !ok {
		return fmt.Errorf("secret %q must be env:NAME or file:NAME", bd.Secret)
	}
	switch kind {
	case "env":
		if !envNamePattern.MatchString(ref) || !strings.HasPrefix(ref, EnvPrefix) || ref == EnvPrefix {
			return fmt.Errorf("secret env variable %q must match %s and start with %s", ref, envNamePattern, EnvPrefix)
		}
	case "file":
		if src.Dir == "" {
			return errors.New("file secrets need a secrets directory")
		}
		if !fileRefPattern.MatchString(ref) || ref == "." || ref == ".." || strings.HasPrefix(ref, ".") {
			return fmt.Errorf("secret file %q must be a plain file name", ref)
		}
	default:
		return fmt.Errorf("unknown secret source %q", kind)
	}
	return nil
}

// For returns the credentials to inject for a call to tool on server. A tool
// with no bindings gets none. If any bound secret cannot be resolved, it returns
// ErrSecret and no credentials, and the call must be refused.
func (b *Broker) For(server, tool string) ([]Credential, error) {
	if tool == "*" {
		// "*" names every tool in a binding; as a called tool it would inject the
		// server-wide credentials twice.
		return nil, fmt.Errorf("%w: %q is reserved and cannot be called as a tool", ErrSecret, tool)
	}
	var out []Credential
	for _, k := range []bindingKey{{server, "*"}, {server, tool}} {
		for _, bd := range b.bindings[k] {
			v, err := b.resolve(bd.Secret)
			if err != nil {
				return nil, fmt.Errorf("%w: %s %q for %s/%s: %v", ErrSecret, bd.Inject, bd.Name, server, tool, err)
			}
			out = append(out, Credential{Inject: bd.Inject, Name: bd.Name, Value: Secret{v: append([]byte(bd.Prefix), v...)}})
		}
	}
	return out, nil
}

// ServerCredentials returns only the server-wide credentials (tool "*") for
// server. Transports that set credentials once per connection, such as a stdio
// process's environment, use this instead of For.
func (b *Broker) ServerCredentials(server string) ([]Credential, error) {
	var out []Credential
	for _, bd := range b.bindings[bindingKey{server, "*"}] {
		v, err := b.resolve(bd.Secret)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %q for %s: %v", ErrSecret, bd.Inject, bd.Name, server, err)
		}
		out = append(out, Credential{Inject: bd.Inject, Name: bd.Name, Value: Secret{v: append([]byte(bd.Prefix), v...)}})
	}
	return out, nil
}

// Describe returns the bindings configured for server, without resolving any
// secret, so a transport can refuse bindings it cannot honor.
func (b *Broker) Describe(server string) []Binding {
	var out []Binding
	for k, bds := range b.bindings {
		if k.server == server {
			out = append(out, bds...)
		}
	}
	return out
}

func (b *Broker) resolve(ref string) ([]byte, error) {
	kind, name, _ := strings.Cut(ref, ":")
	var v []byte
	switch kind {
	case "env":
		s, ok := b.sources.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", name)
		}
		v = []byte(s)
	case "file":
		path := filepath.Join(b.sources.Dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("secret file %s: %v", name, errors.Unwrap(err))
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("secret file %s is not a regular file", name)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("secret file %s has mode %v; group and other must have no access", name, info.Mode().Perm())
		}
		if info.Size() > maxSecretSize {
			return nil, fmt.Errorf("secret file %s is larger than %d bytes", name, maxSecretSize)
		}
		v, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("secret file %s: %v", name, errors.Unwrap(err))
		}
		v = bytes.TrimRight(v, "\r\n")
	default:
		return nil, fmt.Errorf("unknown secret source %q", kind)
	}
	if len(v) == 0 {
		return nil, errors.New("secret is empty")
	}
	if len(v) > maxSecretSize {
		return nil, fmt.Errorf("secret is larger than %d bytes", maxSecretSize)
	}
	if bytes.ContainsAny(v, "\r\n\x00") {
		return nil, errors.New("secret contains a line break or NUL")
	}
	return v, nil
}

// minScrubLen avoids redacting common short strings; shorter secrets are too
// weak to rely on anyway.
const minScrubLen = 8

// Scrub replaces every credential value that appears in data, raw or in standard
// or URL-safe base64, and reports whether any was found. It is a last line of
// defense against a tool echoing its credentials back to the agent, not a
// guarantee: transformed or partial leaks are not detected.
func Scrub(data []byte, creds []Credential) ([]byte, bool) {
	found := false
	out := data
	for _, c := range creds {
		v := c.Value.v
		if len(v) < minScrubLen {
			continue
		}
		for _, form := range [][]byte{
			v,
			[]byte(base64.StdEncoding.EncodeToString(v)),
			[]byte(base64.RawStdEncoding.EncodeToString(v)),
			[]byte(base64.URLEncoding.EncodeToString(v)),
			[]byte(base64.RawURLEncoding.EncodeToString(v)),
		} {
			if bytes.Contains(out, form) {
				out = bytes.ReplaceAll(out, form, []byte("[REDACTED:credential]"))
				found = true
			}
		}
	}
	return out, found
}
