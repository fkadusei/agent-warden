// Package doccheck checks that the hand-maintained HTML pages in docs/ still say
// what their Markdown sources say.
//
// The HTML is written by hand beside the Markdown, with no generator, so a change
// made to one can be missed in the other. The check compares what can be compared
// mechanically: section headings and their order, every table cell, and the index
// of architecture decisions with their status. Prose is not compared. The HTML
// rewords paragraphs for its layout, so a prose check would mostly report that.
package doccheck

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Twin is a Markdown file and the part of an HTML page that copies it. An empty
// Part means the whole page.
type Twin struct {
	Markdown, HTML, Part string
}

// Twins are the copies kept by hand. design.html carries three sources, each
// under its own part label.
var Twins = []Twin{
	{"docs/design.md", "docs/design.html", "Design"},
	{"docs/threat-model.md", "docs/design.html", "Threat model"},
	{"docs/writeup.md", "docs/writeup.html", ""},
}

// ADRPage is the page that indexes every decision in docs/decisions, under the
// part labelled ADRPart.
const (
	ADRPage = "docs/design.html"
	ADRPart = "Decisions"
)

// Doc is what a page says, as far as the check compares it.
type Doc struct {
	Headings []string
	Tables   [][][]string // table, row, cell
}

// ADR is one decision as a page or a file states it.
type ADR struct {
	Number, Title, Status string
}

var (
	mdHeading = regexp.MustCompile(`^#{2,3} (.+)$`)
	mdRule    = regexp.MustCompile(`^\|(\s*:?-+:?\s*\|)+$`)
	mdLink    = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	mdADR     = regexp.MustCompile(`^# (ADR-\d{4}): (.+)$`)
	mdStatus  = regexp.MustCompile(`(?m)^- \*\*Status:\*\*\s+([A-Za-z]+)`)

	htmlPart    = regexp.MustCompile(`<span class="part">([^<]*)</span>`)
	htmlHeading = regexp.MustCompile(`(?s)<h[2-4]\b[^>]*>(.*?)</h[2-4]>`)
	htmlTable   = regexp.MustCompile(`(?s)<table\b.*?</table>`)
	htmlRow     = regexp.MustCompile(`(?s)<tr\b[^>]*>(.*?)</tr>`)
	htmlCell    = regexp.MustCompile(`(?s)<t[hd]\b[^>]*>(.*?)</t[hd]>`)
	htmlPill    = regexp.MustCompile(`<span class="pill[^"]*">([^<]*)</span>`)
	htmlID      = regexp.MustCompile(`<span class="id">([^<]*)</span>`)
	htmlTag     = regexp.MustCompile(`<[^>]+>`)
	htmlADR     = regexp.MustCompile(`(?s)<h3>\s*(ADR-\d{4})\s*—\s*(.*?)</h3>`)
)

// normalize makes a string from either format comparable: entities decoded,
// whitespace collapsed, and the spaced dash that separates a label from its title
// ("W11 — Signing key compromise") dropped, since the HTML sets labels apart with
// markup instead.
func normalize(s string) string {
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, " — ", " ")
}

// mdInline reduces Markdown inline markup to its text. Code spans are kept
// verbatim; emphasis markers outside them are dropped.
func mdInline(s string) string {
	s = mdLink.ReplaceAllString(s, "$1")
	parts := strings.Split(s, "`")
	for i := 0; i < len(parts); i += 2 {
		parts[i] = strings.NewReplacer(`\|`, "|", "*", "").Replace(parts[i])
	}
	return normalize(strings.Join(parts, ""))
}

// htmlText reduces HTML inline markup to its text. A pill is text like any other,
// with two exceptions: "passing" marks progress the Markdown does not track, so it
// goes, and "done" is the HTML's way of writing the Markdown's ✅. A threat's id
// keeps a space before its title.
func htmlText(s string) string {
	s = htmlPill.ReplaceAllStringFunc(s, func(p string) string {
		switch text := htmlPill.FindStringSubmatch(p)[1]; text {
		case "passing":
			return ""
		case "done":
			return "✅"
		default:
			return text
		}
	})
	s = htmlPart.ReplaceAllString(s, "")
	s = htmlID.ReplaceAllString(s, "$1 ")
	return normalize(htmlTag.ReplaceAllString(s, ""))
}

func mdCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(strings.TrimSuffix(line, "|"), "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteString(`\|`)
			i++
		case line[i] == '|':
			cells = append(cells, mdInline(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(line[i])
		}
	}
	return append(cells, mdInline(cur.String()))
}

// ParseMarkdown reads level 2 and 3 headings and every table outside code blocks.
func ParseMarkdown(src string) Doc {
	var d Doc
	var table [][]string
	inFence := false
	flush := func() {
		if table != nil {
			d.Tables = append(d.Tables, table)
			table = nil
		}
	}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			flush()
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(line, "|") {
			if !mdRule.MatchString(line) {
				table = append(table, mdCells(line))
			}
			continue
		}
		flush()
		if m := mdHeading.FindStringSubmatch(line); m != nil {
			d.Headings = append(d.Headings, mdInline(m[1]))
		}
	}
	flush()
	return d
}

// ParseHTML reads level 2 to 4 headings and every table.
func ParseHTML(src string) Doc {
	var d Doc
	for _, m := range htmlHeading.FindAllStringSubmatch(src, -1) {
		d.Headings = append(d.Headings, htmlText(m[1]))
	}
	for _, t := range htmlTable.FindAllString(src, -1) {
		var table [][]string
		for _, r := range htmlRow.FindAllStringSubmatch(t, -1) {
			var row []string
			for _, c := range htmlCell.FindAllStringSubmatch(r[1], -1) {
				row = append(row, htmlText(c[1]))
			}
			table = append(table, row)
		}
		d.Tables = append(d.Tables, table)
	}
	return d
}

// Part returns the section of a page that starts at the heading labelled name
// and runs to the next labelled heading. An empty name returns the whole page.
func Part(page, name string) (string, error) {
	if name == "" {
		return page, nil
	}
	locs := htmlPart.FindAllStringSubmatchIndex(page, -1)
	for i, loc := range locs {
		if page[loc[2]:loc[3]] != name {
			continue
		}
		// Start at the heading that carries the label, so it is part of the section.
		start := strings.LastIndex(page[:loc[0]], "<h")
		end := len(page)
		if i+1 < len(locs) {
			end = strings.LastIndex(page[:locs[i+1][0]], "<h")
		}
		return page[start:end], nil
	}
	return "", fmt.Errorf("no part labelled %q", name)
}

// Compare reports every way the HTML copy differs from its Markdown source.
func Compare(md, page Doc) []string {
	var out []string
	out = append(out, compareHeadings(md.Headings, page.Headings)...)

	if len(md.Tables) != len(page.Tables) {
		out = append(out, fmt.Sprintf("%d tables in the Markdown, %d in the HTML", len(md.Tables), len(page.Tables)))
	}
	for i := range min(len(md.Tables), len(page.Tables)) {
		out = append(out, compareTable(i+1, md.Tables[i], page.Tables[i])...)
	}
	return out
}

func compareHeadings(md, page []string) []string {
	var out []string
	for _, h := range md {
		if !slices.Contains(page, h) {
			out = append(out, fmt.Sprintf("heading %q is in the Markdown but not the HTML", h))
		}
	}
	for _, h := range page {
		if !slices.Contains(md, h) {
			out = append(out, fmt.Sprintf("heading %q is in the HTML but not the Markdown", h))
		}
	}
	if out == nil && !slices.Equal(md, page) {
		out = append(out, fmt.Sprintf("headings are in a different order:\n  Markdown: %q\n  HTML:     %q", md, page))
	}
	return out
}

func compareTable(n int, md, page [][]string) []string {
	label := fmt.Sprintf("table %d", n)
	if len(md) > 0 {
		label = fmt.Sprintf("table %d (%s)", n, strings.Join(md[0], " | "))
	}
	var out []string
	if len(md) != len(page) {
		out = append(out, fmt.Sprintf("%s: %d rows in the Markdown, %d in the HTML", label, len(md), len(page)))
	}
	for r := range min(len(md), len(page)) {
		key := ""
		if len(md[r]) > 0 {
			key = md[r][0]
		}
		if len(md[r]) != len(page[r]) {
			out = append(out, fmt.Sprintf("%s, row %q: %d cells in the Markdown, %d in the HTML", label, key, len(md[r]), len(page[r])))
			continue
		}
		for c := range md[r] {
			if md[r][c] != page[r][c] {
				out = append(out, fmt.Sprintf("%s, row %q, column %d:\n  Markdown: %s\n  HTML:     %s", label, key, c+1, md[r][c], page[r][c]))
			}
		}
	}
	return out
}

// FileADR reads a decision's number, title, and status from its Markdown file.
// The status is its first word, so "Accepted (2026-09-14); superseded in part"
// is Accepted.
func FileADR(src string) (ADR, error) {
	first, _, _ := strings.Cut(src, "\n")
	m := mdADR.FindStringSubmatch(strings.TrimSpace(first))
	if m == nil {
		return ADR{}, fmt.Errorf("first line is not \"# ADR-NNNN: Title\"")
	}
	s := mdStatus.FindStringSubmatch(src)
	if s == nil {
		return ADR{}, fmt.Errorf("%s has no \"- **Status:**\" line", m[1])
	}
	return ADR{Number: m[1], Title: mdInline(m[2]), Status: s[1]}, nil
}

// PageADRs reads every decision a page indexes, with the status of its first pill.
func PageADRs(src string) []ADR {
	var out []ADR
	for _, m := range htmlADR.FindAllStringSubmatch(src, -1) {
		a := ADR{Number: m[1], Title: htmlText(htmlPill.ReplaceAllString(m[2], ""))}
		if p := htmlPill.FindStringSubmatch(m[2]); p != nil {
			a.Status = normalize(p[1])
		}
		out = append(out, a)
	}
	return out
}

// CompareADRs reports decisions the page is missing, has extra, or states
// differently from their files.
func CompareADRs(files, page []ADR) []string {
	var out []string
	byNumber := map[string]ADR{}
	for _, a := range page {
		byNumber[a.Number] = a
	}
	for _, f := range files {
		p, ok := byNumber[f.Number]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s (%s) is not on the page", f.Number, f.Title))
		case p.Status != f.Status:
			out = append(out, fmt.Sprintf("%s: status is %q in its file, %q on the page", f.Number, f.Status, p.Status))
		case p.Title != f.Title:
			out = append(out, fmt.Sprintf("%s: titled %q in its file, %q on the page", f.Number, f.Title, p.Title))
		}
		delete(byNumber, f.Number)
	}
	for n := range byNumber {
		out = append(out, fmt.Sprintf("%s is on the page but has no file in docs/decisions", n))
	}
	slices.Sort(out)
	return out
}

// Check runs every comparison against the repository at root and returns the
// problems, each prefixed with the files it concerns.
func Check(root string) ([]string, error) {
	read := func(p string) (string, error) {
		b, err := os.ReadFile(filepath.Join(root, p))
		return string(b), err
	}
	var out []string
	for _, t := range Twins {
		md, err := read(t.Markdown)
		if err != nil {
			return nil, err
		}
		page, err := read(t.HTML)
		if err != nil {
			return nil, err
		}
		part, err := Part(page, t.Part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.HTML, err)
		}
		where := t.HTML
		if t.Part != "" {
			where = fmt.Sprintf("%s (%s)", t.HTML, t.Part)
		}
		for _, p := range Compare(ParseMarkdown(md), ParseHTML(part)) {
			out = append(out, fmt.Sprintf("%s vs %s: %s", t.Markdown, where, p))
		}
	}

	files, err := filepath.Glob(filepath.Join(root, "docs/decisions/ADR-*.md"))
	if err != nil {
		return nil, err
	}
	var adrs []ADR
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		a, err := FileADR(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		adrs = append(adrs, a)
	}
	page, err := read(ADRPage)
	if err != nil {
		return nil, err
	}
	part, err := Part(page, ADRPart)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ADRPage, err)
	}
	for _, p := range CompareADRs(adrs, PageADRs(part)) {
		out = append(out, fmt.Sprintf("docs/decisions vs %s (%s): %s", ADRPage, ADRPart, p))
	}
	return out, nil
}
