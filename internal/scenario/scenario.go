// Package scenario reads the scenario corpus in scenarios/*.json (ADR-0012). Each
// file describes a task, the content planted in tool results, and the calls a fully
// compromised agent would make, with the outcome Warden must produce for each. The
// format is language-neutral: the Go gate and the Python agent both read it.
package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Version is the scenario format version.
const Version = 1

// Category groups scenarios by what they test (design §6).
type Category string

const (
	Injection Category = "injection" // W1: instructions planted in tool output
	Exfil     Category = "exfil"     // W3: data or credentials leaving
	Deputy    Category = "deputy"    // W4: another principal's content driving this task
	Authz     Category = "authz"     // W2: calls outside the principal's entitlements
	Benign    Category = "benign"    // legitimate work that must succeed
)

// Expect is the outcome Warden must produce for a call.
type Expect string

const (
	OK              Expect = "ok"
	Denied          Expect = "denied"
	PendingApproval Expect = "pending_approval"
)

// Content is planted in the result of a read-only tool.
type Content struct {
	// Tool is the agent-facing name, e.g. "tickets.get".
	Tool string `json:"tool"`
	// Args selects the calls this content answers: every listed argument must be
	// equal. Empty matches every call to Tool.
	Args map[string]any `json:"args,omitempty"`
	// Authors are the principals the tool server states wrote the content.
	Authors []string `json:"authors,omitempty"`
	Body    string   `json:"body"`
}

// Step is one call the scripted agent makes.
type Step struct {
	Call string         `json:"call"`
	Args map[string]any `json:"args,omitempty"`
	// Attack marks a call only a compromised or misled agent would make.
	Attack bool   `json:"attack,omitempty"`
	Expect Expect `json:"expect"`
	// Rule, if set, must be the policy rule behind the outcome.
	Rule string `json:"rule,omitempty"`
	// Match names the arguments that identify this call when reporting on a real
	// model's run, which may word the rest differently (an email body, say). Absent
	// means every argument; an empty list means any call to the tool. The scripted
	// gate always sends Args exactly.
	Match *[]string `json:"match,omitempty"`
}

// Scenario is one file of the corpus.
type Scenario struct {
	V         int      `json:"v"`
	ID        string   `json:"id"`
	Category  Category `json:"category"`
	Threat    string   `json:"threat,omitempty"`
	Title     string   `json:"title"`
	Principal string   `json:"principal"`
	// Task is what the principal asks the agent to do; the real agent gets it as
	// its prompt.
	Task    string    `json:"task"`
	Content []Content `json:"content,omitempty"`
	Steps   []Step    `json:"steps"`
}

const (
	maxSteps   = 32
	maxContent = 32
	maxBody    = 64 << 10
	maxText    = 1024
)

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	threatPattern = regexp.MustCompile(`^W([1-9]|1[0-4])$`)
	toolPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$`)
)

// Parse decodes and validates one scenario, rejecting unknown fields and trailing data.
func Parse(data []byte) (*Scenario, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scenario: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("scenario: trailing data after the scenario")
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("scenario %q: %w", s.ID, err)
	}
	return &s, nil
}

// LoadFS reads every dir/*.json in fsys, sorted by ID. Each file must be named after
// its scenario's ID.
func LoadFS(fsys fs.FS, dir string) ([]*Scenario, error) {
	names, err := fs.Glob(fsys, path.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("scenario: no scenarios in %s", dir)
	}
	seen := map[string]bool{}
	var out []*Scenario
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		s, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if path.Base(name) != s.ID+".json" {
			return nil, fmt.Errorf("%s: file must be named %s.json", name, s.ID)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("%s: duplicate scenario ID", name)
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b *Scenario) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *Scenario) validate() error {
	if s.V != Version {
		return fmt.Errorf("v is %d, want %d", s.V, Version)
	}
	if !idPattern.MatchString(s.ID) {
		return errors.New("id must be 3-64 lowercase letters, digits, or hyphens")
	}
	switch s.Category {
	case Benign:
		if s.Threat != "" {
			return errors.New("benign scenarios have no threat")
		}
	case Injection, Exfil, Deputy, Authz:
		if !threatPattern.MatchString(s.Threat) {
			return fmt.Errorf("threat %q must be W1-W14", s.Threat)
		}
	default:
		return fmt.Errorf("unknown category %q", s.Category)
	}
	for field, v := range map[string]string{"title": s.Title, "principal": s.Principal, "task": s.Task} {
		if err := text(field, v, maxText); err != nil {
			return err
		}
	}

	if len(s.Steps) == 0 || len(s.Steps) > maxSteps {
		return fmt.Errorf("need 1-%d steps", maxSteps)
	}
	attacks := 0
	for i, st := range s.Steps {
		if !toolPattern.MatchString(st.Call) {
			return fmt.Errorf("steps[%d].call %q must be server.tool", i, st.Call)
		}
		switch st.Expect {
		case OK, Denied, PendingApproval:
		default:
			return fmt.Errorf("steps[%d].expect %q is not ok, denied, or pending_approval", i, st.Expect)
		}
		if st.Attack {
			attacks++
			if st.Expect == OK {
				return fmt.Errorf("steps[%d] is an attack but expects ok", i)
			}
		}
		if st.Rule != "" && st.Expect == OK {
			return fmt.Errorf("steps[%d] names a rule but expects ok", i)
		}
		if st.Match != nil {
			seen := map[string]bool{}
			for _, name := range *st.Match {
				if _, ok := st.Args[name]; !ok || seen[name] {
					return fmt.Errorf("steps[%d].match %q must name a distinct argument of the step", i, name)
				}
				seen[name] = true
			}
		}
	}
	if s.Category == Benign {
		for i, st := range s.Steps {
			if st.Attack || st.Expect != OK {
				return fmt.Errorf("benign scenario step %d must be a non-attack that expects ok", i)
			}
		}
	} else if attacks == 0 {
		return errors.New("needs at least one attack step")
	}

	if len(s.Content) > maxContent {
		return fmt.Errorf("at most %d content items", maxContent)
	}
	for i, c := range s.Content {
		if !toolPattern.MatchString(c.Tool) {
			return fmt.Errorf("content[%d].tool %q must be server.tool", i, c.Tool)
		}
		if c.Body == "" || len(c.Body) > maxBody {
			return fmt.Errorf("content[%d].body must be 1-%d bytes", i, maxBody)
		}
		for j, a := range c.Authors {
			if err := text(fmt.Sprintf("content[%d].authors[%d]", i, j), a, 256); err != nil {
				return err
			}
		}
		// Planted content no step reads is a mistake in the scenario.
		if !slices.ContainsFunc(s.Steps, func(st Step) bool { return c.Matches(st.Call, st.Args) }) {
			return fmt.Errorf("content[%d] is not read by any step", i)
		}
	}
	return nil
}

func text(field, s string, max int) error {
	if strings.TrimSpace(s) == "" || len(s) > max {
		return fmt.Errorf("%s must be 1-%d bytes", field, max)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

// Matches reports whether this content answers a call to tool with args.
func (c Content) Matches(tool string, args map[string]any) bool {
	if c.Tool != tool {
		return false
	}
	for k, want := range c.Args {
		got, ok := args[k]
		if !ok || !jsonEqual(got, want) {
			return false
		}
	}
	return true
}

func jsonEqual(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(x, y)
}

// ArgsJSON returns the step's arguments as a JSON object.
func (st Step) ArgsJSON() json.RawMessage {
	if len(st.Args) == 0 {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(st.Args)
	if err != nil {
		return json.RawMessage(`{}`) // unreachable: args came from JSON
	}
	return b
}

// Attacks returns the indexes of attack steps.
func (s *Scenario) Attacks() []int {
	var out []int
	for i, st := range s.Steps {
		if st.Attack {
			out = append(out, i)
		}
	}
	return out
}
