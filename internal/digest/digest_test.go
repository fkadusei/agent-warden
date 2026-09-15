package digest

import (
	"strings"
	"testing"
)

func TestSHA256(t *testing.T) {
	// SHA-256 of the empty string (FIPS 180-4 test value).
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := SHA256(nil); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if !Valid(want) {
		t.Fatal("SHA256 output is not Valid")
	}
}

func TestValidRejects(t *testing.T) {
	good := SHA256([]byte("x"))
	hexPart := strings.TrimPrefix(good, Prefix)
	cases := map[string]string{
		"empty":            "",
		"no prefix":        hexPart,
		"wrong algorithm":  "sha512:" + hexPart,
		"uppercase prefix": "SHA256:" + hexPart,
		"uppercase hex":    Prefix + strings.ToUpper(hexPart),
		"too short":        good[:len(good)-1],
		"too long":         good + "0",
		"non-hex":          Prefix + strings.Repeat("g", 64),
	}
	for name, s := range cases {
		if Valid(s) {
			t.Errorf("%s: Valid(%q) = true", name, s)
		}
	}
}
