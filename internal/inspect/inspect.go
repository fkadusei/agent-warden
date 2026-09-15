// Package inspect flags suspicious content in tool output (design §2, threat W1).
//
// Detection is heuristic and never the guarantee: the model only proposes, and every
// call is still authorized by policy. Flags become taint labels that policy can use
// and are recorded in receipts for auditors. Only the flag kinds are reported, never
// the matched text, so receipts carry no tool data (W13).
package inspect

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Kind is one kind of finding.
type Kind string

const (
	// Instruction: text addressed to a model — override phrases, fake role markers,
	// requests to hide things from the user or reveal secrets.
	Instruction Kind = "instruction"
	// Hidden: content a human reader would not see — zero-width, bidirectional
	// control, or Unicode tag characters, HTML comments, invisible styling.
	Hidden Kind = "hidden_text"
	// ToolDirective: text telling the reader to call one of the exposed tools.
	ToolDirective Kind = "tool_directive"
	// Encoded: a long base64 run that could smuggle instructions or data.
	Encoded Kind = "encoded_blob"
)

// Kinds lists every kind, in sorted order.
var Kinds = []Kind{Encoded, Hidden, Instruction, ToolDirective}

// Flag is the taint label for a kind.
func (k Kind) Flag() string { return "flag:" + string(k) }

var instructionPatterns = compile(
	`\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|preceding|all|your|the)\b.{0,20}\b(instructions?|directions?|rules|guidelines|prompts?|messages?|context)\b`,
	`\b(new|updated|revised|real|actual|hidden)\s+(system\s+)?(instructions?|directives?|prompt)\s*:`,
	`\byou are now\b`,
	`\bfrom now on\b.{0,40}\b(you|assistant|agent)\b`,
	`<\|?\s*(im_start|im_end|system|endoftext)\s*\|?>`,
	`\[/?inst\]`,
	`</?\s*(system|instructions?|assistant)\s*>`,
	`\b(ai|assistant|agent|model|llm|chatbot|copilot)s?\b.{0,40}\b(must|should|are instructed to|need to|have to)\b`,
	`\b(do not|don't|never)\s+(tell|inform|mention|reveal|show)\b.{0,30}\b(user|human|anyone|customer|operator)\b`,
	`\b(reveal|print|output|dump|send|share|leak|exfiltrate|email)\b.{0,40}\b(api[ _-]?keys?|credentials?|passwords?|secrets?|tokens?|system prompt|environment variables?)\b`,
)

var hiddenMarkup = compile(
	`<!--`,
	`display\s*:\s*none`,
	`visibility\s*:\s*hidden`,
	`font-size\s*:\s*0(\.0+)?(px|pt|em|rem|%)?\s*[;"'}]`,
	`opacity\s*:\s*0(\.0+)?\s*[;"'}]`,
)

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{120,}={0,2}`)

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(`(?is)` + p)
	}
	return out
}

// invisible reports runes a reader cannot see: zero-width characters, the word
// joiner, a byte-order mark, bidirectional controls, and Unicode tag characters.
func invisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, // zero-width space/joiners, LRM, RLM
		r >= 0x202A && r <= 0x202E,   // bidirectional embeddings and overrides
		r >= 0x2060 && r <= 0x2064,   // word joiner, invisible operators
		r >= 0x2066 && r <= 0x2069,   // bidirectional isolates
		r == 0xFEFF,                  // byte-order mark / zero-width no-break space
		r >= 0xE0000 && r <= 0xE007F: // tag characters
		return true
	}
	return false
}

// normalize removes invisible runes (so they cannot split trigger phrases) and
// collapses whitespace.
func normalize(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	hidden, space := false, false
	for _, r := range s {
		if invisible(r) {
			hidden = true
			continue
		}
		if unicode.IsSpace(r) {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String(), hidden
}

// Inspect returns the kinds found in text, sorted and without duplicates. tools are
// the tool names exposed to the agent (e.g. "mail.send").
func Inspect(text string, tools []string) []Kind {
	norm, hidden := normalize(text)
	var found []Kind
	if hidden || anyMatch(hiddenMarkup, norm) {
		found = append(found, Hidden)
	}
	if anyMatch(instructionPatterns, norm) {
		found = append(found, Instruction)
	}
	if directsTool(norm, tools) {
		found = append(found, ToolDirective)
	}
	if encoded(norm) {
		found = append(found, Encoded)
	}
	slices.Sort(found)
	return found
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

var verbs = `(call|use|invoke|run|execute|trigger)`

// directsTool reports an imperative verb shortly before an exposed tool's name, or
// the name written as a function call or a tool-call object.
func directsTool(s string, tools []string) bool {
	lower := strings.ToLower(s)
	for _, t := range tools {
		if t == "" {
			continue
		}
		name := strings.ToLower(t)
		variants := []string{name, strings.ReplaceAll(name, ".", "/"), strings.ReplaceAll(name, ".", "_")}
		for _, v := range slices.Compact(variants) {
			if !strings.Contains(lower, v) {
				continue
			}
			q := regexp.QuoteMeta(v)
			re := regexp.MustCompile(`\b` + verbs + `\b.{0,30}` + q + `|` + q + `\s*\(|"(name|tool)"\s*:\s*"` + q + `"`)
			if re.MatchString(lower) {
				return true
			}
		}
	}
	return false
}

// encoded reports a long base64 run mixing upper case, lower case, and digits (so
// long hex digests and plain identifiers are not flagged).
func encoded(s string) bool {
	for _, m := range base64Run.FindAllString(s, -1) {
		var upper, lower, digit bool
		for _, r := range m {
			switch {
			case r >= 'A' && r <= 'Z':
				upper = true
			case r >= 'a' && r <= 'z':
				lower = true
			case r >= '0' && r <= '9':
				digit = true
			}
		}
		if upper && lower && digit {
			return true
		}
	}
	return false
}

// Flags returns the taint labels for kinds.
func Flags(kinds []Kind) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = k.Flag()
	}
	return out
}
