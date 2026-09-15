package canonical

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

// esc turns the placeholder "%u" into a JSON "\u" escape, so the JSON escape
// sequences under test stay visible in this file as plain text.
func esc(s string) string { return strings.ReplaceAll(s, "%u", `\`+"u") }

// RFC 8785 section 3.2.2 input and its canonical form from section 3.2.3.
func TestRFC8785Example(t *testing.T) {
	in := esc(`{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "%u20ac$%u000F%u000aA'%u0042%u0022%u005c\\\"\/",
  "literals": [null, true, false]
}`)
	want := esc(`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"` +
		"€" + `$%u000f\nA'B\"\\\\\"/"}`)
	got, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if err := Check(got); err != nil {
		t.Fatalf("canonical output fails Check: %v", err)
	}
	if err := Check([]byte(in)); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("non-canonical input: got %v, want ErrNotCanonical", err)
	}
}

// RFC 8785 section 3.2.3: property sorting by UTF-16 code units.
func TestRFC8785Sorting(t *testing.T) {
	in := esc(`{
  "%u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "%ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "%ud83d%ude00": "Emoji: Grinning Face",
  "%u0080": "Control",
  "%u00f6": "Latin Small Letter O With Diaeresis"
}`)
	order := []string{
		"Carriage Return",
		"One",
		"Control",
		"Latin Small Letter O With Diaeresis",
		"Euro Sign",
		"Emoji: Grinning Face",
		"Hebrew Letter Dalet With Dagesh",
	}
	got, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	last := -1
	for _, v := range order {
		i := strings.Index(string(got), `"`+v+`"`)
		if i <= last {
			t.Fatalf("%q out of order in %s", v, got)
		}
		last = i
	}
}

// RFC 8785 Appendix B, Table 1.
func TestRFC8785NumberSamples(t *testing.T) {
	samples := []struct {
		ieee string
		want string // empty means the value must be rejected
	}{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"7fffffffffffffff", ""},
		{"7ff0000000000000", ""},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	}
	for _, s := range samples {
		bits, err := strconv.ParseUint(s.ieee, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := jcs.NumberToJSON(math.Float64frombits(bits))
		if s.want == "" {
			if err == nil {
				t.Errorf("%s: got %q, want error", s.ieee, got)
			}
			continue
		}
		if err != nil || got != s.want {
			t.Errorf("%s: got %q (%v), want %q", s.ieee, got, err, s.want)
		}
	}
}

func TestCheckRejects(t *testing.T) {
	cases := map[string]string{
		"invalid UTF-8":                         "{\"s\":\"\xff\"}",
		"duplicate keys":                        `{"a":1,"a":2}`,
		"unsorted keys":                         `{"b":1,"a":2}`,
		"whitespace":                            `{"a": 1}`,
		"integer above 2^53-1":                  `{"seq":9007199254740993}`,
		"non-canonical number":                  `{"seq":1.0}`,
		"escaped character that JCS writes raw": esc(`{"s":"%u00e9"}`),
		"lone surrogate":                        esc(`{"s":"%ud800"}`),
		"trailing data":                         `{"a":1} {"b":2}`,
		"not JSON":                              `nope`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(in, "%u") {
				t.Fatal("placeholder not expanded")
			}
			if err := Check([]byte(in)); err == nil {
				t.Fatalf("Check(%q) = nil, want error", in)
			}
		})
	}
}

func TestEncodeUndoesGoHTMLEscaping(t *testing.T) {
	got, err := Encode(map[string]string{"s": "<a&b>"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"s":"<a&b>"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if err := Check([]byte(`{"seq":9007199254740991}`)); err != nil {
		t.Fatalf("MaxSafeInteger rejected: %v", err)
	}
}
