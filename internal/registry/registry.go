// Package registry pins tool manifests by digest (threat W5, design §2).
//
// A tool's manifest is everything that shapes how the model sees and calls it:
// name, title, description, input and output schemas, and annotations, tied to
// the server that offers it. An operator reviews the tools and pins their
// digests. From then on a tool is callable only while its manifest still hashes
// to the pinned digest, so a changed description or schema ("rug pull") is
// refused until someone re-reviews and re-pins it.
package registry

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/digest"
)

// ManifestDomain separates manifest digests from every other hashed object.
const ManifestDomain = "agent-warden/tool-manifest/v1"

var (
	// ErrUnpinned is returned for a tool with no pin.
	ErrUnpinned = errors.New("registry: tool is not pinned")
	// ErrChanged is returned for a tool whose manifest differs from its pin.
	ErrChanged = errors.New("registry: tool manifest changed since it was pinned")
)

// Manifest is the part of a tool definition that is pinned.
type Manifest struct {
	Server       string `json:"server"`
	Name         string `json:"name"`
	Title        string `json:"title,omitempty"`
	Description  string `json:"description,omitempty"`
	InputSchema  any    `json:"input_schema"`
	OutputSchema any    `json:"output_schema,omitempty"`
	Annotations  any    `json:"annotations,omitempty"`
}

// ID is how the tool is addressed across servers: "server/name".
func (m Manifest) ID() string { return m.Server + "/" + m.Name }

// Digest is the SHA-256 of the canonical manifest with its domain.
func (m Manifest) Digest() (string, error) {
	if err := validName("server", m.Server); err != nil {
		return "", err
	}
	if err := validName("name", m.Name); err != nil {
		return "", err
	}
	if m.InputSchema == nil {
		return "", fmt.Errorf("registry: %s has no input schema", m.ID())
	}
	b, err := canonical.Encode(struct {
		Domain string `json:"domain"`
		Manifest
	}{ManifestDomain, m})
	if err != nil {
		return "", fmt.Errorf("registry: %s: %w", m.ID(), err)
	}
	return digest.SHA256(b), nil
}

func validName(field, s string) error {
	if s == "" || len(s) > 128 || strings.ContainsAny(s, "/") {
		return fmt.Errorf("registry: %s %q must be 1-128 bytes without '/'", field, s)
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return fmt.Errorf("registry: %s %q contains whitespace or a control character", field, s)
		}
	}
	return nil
}

// Pin records the reviewed manifest digest of one tool.
type Pin struct {
	Server   string `json:"server"`
	Tool     string `json:"tool"`
	Manifest string `json:"manifest"`
}

// PinFile is the on-disk pin set.
type PinFile struct {
	V    int   `json:"v"`
	Pins []Pin `json:"pins"`
}

// Registry answers whether a tool manifest matches its pin. It is read-only
// after construction and safe for concurrent use.
type Registry struct {
	pins map[string]string // server/tool -> manifest digest
}

// New builds a registry from pins, rejecting malformed and duplicate pins.
func New(pins []Pin) (*Registry, error) {
	r := &Registry{pins: make(map[string]string, len(pins))}
	for i, p := range pins {
		if err := validName("server", p.Server); err != nil {
			return nil, fmt.Errorf("registry: pin %d: %w", i, err)
		}
		if err := validName("tool", p.Tool); err != nil {
			return nil, fmt.Errorf("registry: pin %d: %w", i, err)
		}
		if !digest.Valid(p.Manifest) {
			return nil, fmt.Errorf("registry: pin %d (%s/%s): manifest is not a sha256 digest", i, p.Server, p.Tool)
		}
		id := p.Server + "/" + p.Tool
		if _, dup := r.pins[id]; dup {
			return nil, fmt.Errorf("registry: duplicate pin for %s", id)
		}
		r.pins[id] = p.Manifest
	}
	return r, nil
}

// Load parses a pin file. It must be canonical JSON with exactly the expected
// fields, like receipts.
func Load(data []byte) (*Registry, error) {
	var f PinFile
	if err := canonical.DecodeStrict(data, &f); err != nil {
		return nil, fmt.Errorf("registry: pin file: %w", err)
	}
	if f.V != 1 {
		return nil, fmt.Errorf("registry: pin file v is %d, want 1", f.V)
	}
	return New(f.Pins)
}

// Check returns the manifest's digest if it matches its pin. On ErrChanged the
// observed digest is still returned, so the refusal can be receipted with it.
func (r *Registry) Check(m Manifest) (string, error) {
	d, err := m.Digest()
	if err != nil {
		return "", err
	}
	pinned, ok := r.pins[m.ID()]
	switch {
	case !ok:
		return d, fmt.Errorf("%w: %s", ErrUnpinned, m.ID())
	case pinned != d:
		return d, fmt.Errorf("%w: %s is %s, pinned %s", ErrChanged, m.ID(), d, pinned)
	}
	return d, nil
}

// Checked is one manifest and its digest.
type Checked struct {
	Manifest Manifest
	Digest   string
	Err      error
}

// Review sorts manifests into allowed, unpinned, changed, and invalid.
type Review struct {
	Allowed  []Checked
	Unpinned []Checked
	Changed  []Checked
	Invalid  []Checked
}

// Review checks every manifest a server offers. Only Allowed tools may be exposed
// to the agent.
func (r *Registry) Review(ms []Manifest) Review {
	var out Review
	for _, m := range ms {
		d, err := r.Check(m)
		c := Checked{Manifest: m, Digest: d, Err: err}
		switch {
		case err == nil:
			out.Allowed = append(out.Allowed, c)
		case errors.Is(err, ErrUnpinned):
			out.Unpinned = append(out.Unpinned, c)
		case errors.Is(err, ErrChanged):
			out.Changed = append(out.Changed, c)
		default:
			out.Invalid = append(out.Invalid, c)
		}
	}
	return out
}

// PinAll produces a canonical pin file for manifests an operator has reviewed.
func PinAll(ms []Manifest) ([]byte, error) {
	f := PinFile{V: 1}
	for _, m := range ms {
		d, err := m.Digest()
		if err != nil {
			return nil, err
		}
		f.Pins = append(f.Pins, Pin{Server: m.Server, Tool: m.Name, Manifest: d})
	}
	slices.SortFunc(f.Pins, func(a, b Pin) int {
		return strings.Compare(a.Server+"/"+a.Tool, b.Server+"/"+b.Tool)
	})
	if _, err := New(f.Pins); err != nil {
		return nil, err
	}
	return canonical.Encode(f)
}
