package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const root = "../.."

// The HTML pages in docs/ say what their Markdown sources say.
func TestHTMLMatchesMarkdown(t *testing.T) {
	problems, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if len(problems) > 0 {
		t.Log("Edit the HTML to match the Markdown, which is the source. If the Markdown is what is wrong, fix it and then copy the change across.")
	}
}

// A check that compares nothing passes. Make sure each parser still finds what it
// is meant to, so a page whose markup drifts out of the parser's reach fails here
// instead of silently passing.
func TestTheCheckSeesTheDocs(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, tw := range Twins {
		md := ParseMarkdown(read(tw.Markdown))
		part, err := Part(read(tw.HTML), tw.Part)
		if err != nil {
			t.Fatal(err)
		}
		page := ParseHTML(part)
		if len(md.Headings) < 5 || len(page.Headings) < 5 {
			t.Errorf("%s: only %d headings in the Markdown and %d in the HTML", tw.Markdown, len(md.Headings), len(page.Headings))
		}
		if len(md.Tables) == 0 || len(page.Tables) == 0 {
			t.Errorf("%s: %d tables in the Markdown, %d in the HTML", tw.Markdown, len(md.Tables), len(page.Tables))
		}
	}
	files, _ := filepath.Glob(filepath.Join(root, "docs/decisions/ADR-*.md"))
	part, err := Part(read(ADRPage), ADRPart)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(PageADRs(part)); got != len(files) || got < 16 {
		t.Errorf("found %d decisions on the page and %d files", got, len(files))
	}
}

// copyDocs copies the Markdown, HTML, and decision records into a scratch
// repository, so a test can plant drift without touching the real files.
func copyDocs(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	for _, pattern := range []string{"docs/*.md", "docs/*.html", "docs/decisions/*.md"} {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			rel, _ := filepath.Rel(root, m)
			b, err := os.ReadFile(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, rel)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dst, rel), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dst
}

// The check names each kind of drift it exists to catch.
func TestTheCheckCatchesDrift(t *testing.T) {
	cases := []struct {
		name, file string
		old, new   string // a literal replacement that must apply exactly once
		pattern    string // or a regular expression whose matches are removed
		want       string
	}{
		{name: "a table row dropped from the HTML", file: "docs/design.html",
			pattern: `(?m)^.*<code>revoked_key</code></td>.*\n`, want: "rows in the Markdown"},
		{name: "a table cell reworded in the HTML", file: "docs/design.html",
			old: "Pins each tool manifest by digest.", new: "Pins each tool.", want: "Pins each tool manifest by digest."},
		{name: "a table cell changed in the Markdown only", file: "docs/design.md",
			old: "| `wrong_key` | A key signed", new: "| `wrong_key` | Some key signed", want: "Some key signed"},
		{name: "a heading renamed in the HTML", file: "docs/design.html",
			old: `<span class="id">W11</span>Signing key compromise`, new: `<span class="id">W11</span>Key compromise`,
			want: `heading "W11 Signing key compromise" is in the Markdown but not the HTML`},
		{name: "a section missing from the HTML", file: "docs/design.html",
			old: `<h2 id="benchmark">6. Benchmark</h2>`, new: "", want: `heading "6. Benchmark"`},
		{name: "a phase done in one copy only", file: "docs/design.html",
			old: `<td><strong>6</strong> <span class="pill g">done</span></td>`, new: `<td><strong>6</strong></td>`, want: "6 ✅"},
		{name: "a write-up table header changed", file: "docs/writeup.html",
			old: `<th class="num">p99</th>`, new: `<th class="num">p95</th>`, want: "p95"},
		{name: "a decision's status differs", file: "docs/design.html",
			old: `Key rotation and revocation <span class="pill g">Accepted</span>`,
			new: `Key rotation and revocation <span class="pill">Proposed</span>`, want: "ADR-0016: status"},
		{name: "a decision missing from the page", file: "docs/design.html",
			old: "<h3>ADR-0016 — ", new: "<h3>", want: "ADR-0016 (Key rotation and revocation) is not on the page"},
		{name: "a decision retitled on the page", file: "docs/design.html",
			old: "ADR-0013 — Validate arguments against the pinned input schema", new: "ADR-0013 — Schema validation",
			want: "ADR-0013: titled"},
		{name: "a new decision with no page entry", file: "docs/decisions/ADR-0099-new.md",
			new: "# ADR-0099: Something new\n\n- **Status:** Proposed\n", want: "ADR-0099 (Something new) is not on the page"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyDocs(t)
			path := filepath.Join(dir, c.file)
			b, _ := os.ReadFile(path) // a new file starts empty
			s := string(b)
			switch {
			case c.pattern != "":
				re := regexp.MustCompile(c.pattern)
				if n := len(re.FindAllString(s, -1)); n != 1 {
					t.Fatalf("pattern matched %d times, want 1", n)
				}
				s = re.ReplaceAllString(s, "")
			case c.old != "":
				if n := strings.Count(s, c.old); n != 1 {
					t.Fatalf("%q appears %d times, want 1", c.old, n)
				}
				s = strings.Replace(s, c.old, c.new, 1)
			default:
				s = c.new
			}
			if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
			problems, err := Check(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				if strings.Contains(p, c.want) {
					return
				}
			}
			t.Fatalf("no problem mentions %q; got %d:\n%s", c.want, len(problems), strings.Join(problems, "\n"))
		})
	}
}

func TestInlineMarkup(t *testing.T) {
	md := map[string]string{
		"**Gateway**":                      "Gateway",
		"`WARDEN_SECRET_*` variables":      "WARDEN_SECRET_* variables",
		"Default *N*=100":                  "Default N=100",
		"[`README.md`](../README.md)":      "README.md",
		"W11 — Signing key compromise":     "W11 Signing key compromise",
		"`a \\| b`":                        `a \| b`,
		"spaced   out  ":                   "spaced out",
		"5. What `warden-verify` proves":   "5. What warden-verify proves",
		"Untrusted. **Never** decides":     "Untrusted. Never decides",
		"`seq` is at most 2<sup>53</sup>":  "seq is at most 2<sup>53</sup>",
		"keeps `x < y` literal":            "keeps x < y literal",
		"plain text stays":                 "plain text stays",
		"the `<base64url>` part":           "the <base64url> part",
		"`**` inside code is kept":         "** inside code is kept",
		"outside code ** is dropped":       "outside code is dropped",
		"tail:   `code` ":                  "tail: code",
		"`go test -fuzz`":                  "go test -fuzz",
		"pipe \\| escaped outside code":    "pipe | escaped outside code",
		"`x` and `y`":                      "x and y",
		"mixed **bold `code`** end":        "mixed bold code end",
		"emoji ✅ stays":                    "emoji ✅ stays",
		"&amp; in Markdown is decoded":     "& in Markdown is decoded",
		"en–dash and — em dash":            "en–dash and em dash",
		"no—space dash stays":              "no—space dash stays",
		"[link](http://x) and [b](y)":      "link and b",
		"*single* and **double** emphasis": "single and double emphasis",
		"`unterminated code":               "unterminated code",
		"":                                 "",
		"   ":                              "",
		"a\tb":                             "a b",
	}
	for in, want := range md {
		if got := mdInline(in); got != want {
			t.Errorf("mdInline(%q) = %q, want %q", in, got, want)
		}
	}

	page := map[string]string{
		`<strong>Gateway</strong>`:                            "Gateway",
		`(<code>internal/mcpgw</code>)`:                       "(internal/mcpgw)",
		`text <span class="pill g">passing</span>`:            "text",
		`<strong>6</strong> <span class="pill g">done</span>`: "6 ✅",
		`<span class="pill g">Verified</span> locally`:        "Verified locally",
		`<span class="id">W11</span>Signing key compromise`:   "W11 Signing key compromise",
		`<span class="part">Design</span>1. The idea`:         "1. The idea",
		`a &lt;b&gt; &amp; c`:                                 "a <b> & c",
	}
	for in, want := range page {
		if got := htmlText(in); got != want {
			t.Errorf("htmlText(%q) = %q, want %q", in, got, want)
		}
	}
}
