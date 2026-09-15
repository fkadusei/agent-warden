package broker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const token = "tok_live_9f2c4d1e7a"

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func secretsDir(t *testing.T, files map[string]os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	for name, mode := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("file-secret-"+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const config = `{
  "v": 1,
  "bindings": [
    {"server": "payments", "tool": "*", "inject": "header", "name": "Authorization", "prefix": "Bearer ", "secret": "env:WARDEN_SECRET_PAYMENTS"},
    {"server": "crm", "tool": "export", "inject": "header", "name": "X-Export-Key", "secret": "file:crm-export"},
    {"server": "mail", "tool": "*", "inject": "env", "name": "SMTP_PASSWORD", "secret": "env:WARDEN_SECRET_SMTP"}
  ]
}`

func broker(t *testing.T) *Broker {
	t.Helper()
	b, err := Load([]byte(config), Sources{
		LookupEnv: envOf(map[string]string{"WARDEN_SECRET_PAYMENTS": token, "WARDEN_SECRET_SMTP": "smtp-pass-123"}),
		Dir:       secretsDir(t, map[string]os.FileMode{"crm-export": 0o600}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFor(t *testing.T) {
	b := broker(t)
	cases := []struct {
		server, tool string
		want         []string // "inject name=value"
	}{
		{"payments", "refund", []string{"header Authorization=Bearer " + token}},
		{"payments", "status", []string{"header Authorization=Bearer " + token}},
		{"crm", "export", []string{"header X-Export-Key=file-secret-crm-export"}},
		{"crm", "lookup", nil},
		{"mail", "send", []string{"env SMTP_PASSWORD=smtp-pass-123"}},
		{"unknown", "tool", nil},
	}
	for _, c := range cases {
		t.Run(c.server+"/"+c.tool, func(t *testing.T) {
			creds, err := b.For(c.server, c.tool)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, cr := range creds {
				got = append(got, fmt.Sprintf("%s %s=%s", cr.Inject, cr.Name, cr.Value.Reveal()))
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestWildcardIsNotACallableTool(t *testing.T) {
	creds, err := broker(t).For("payments", "*")
	if !errors.Is(err, ErrSecret) || creds != nil {
		t.Fatalf("got %v, %v; want no credentials and an error", creds, err)
	}
}

func TestMissingSecretsFailClosed(t *testing.T) {
	cases := map[string]Sources{
		"env variable not set": {LookupEnv: envOf(map[string]string{"WARDEN_SECRET_SMTP": "x"}), Dir: secretsDir(t, map[string]os.FileMode{"crm-export": 0o600})},
		"env variable empty":   {LookupEnv: envOf(map[string]string{"WARDEN_SECRET_PAYMENTS": "", "WARDEN_SECRET_SMTP": "x"}), Dir: secretsDir(t, map[string]os.FileMode{"crm-export": 0o600})},
		"secret with newline":  {LookupEnv: envOf(map[string]string{"WARDEN_SECRET_PAYMENTS": "a\nb", "WARDEN_SECRET_SMTP": "x"}), Dir: secretsDir(t, map[string]os.FileMode{"crm-export": 0o600})},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			b, err := Load([]byte(config), src)
			if err != nil {
				t.Fatal(err)
			}
			creds, err := b.For("payments", "refund")
			if !errors.Is(err, ErrSecret) || creds != nil {
				t.Fatalf("got %v, %v; want no credentials and ErrSecret", creds, err)
			}
		})
	}

	fileCases := map[string]func(dir string){
		"file missing":           func(dir string) { os.Remove(filepath.Join(dir, "crm-export")) },
		"file readable by group": func(dir string) { os.Chmod(filepath.Join(dir, "crm-export"), 0o640) },
		"file is a symlink": func(dir string) {
			target := filepath.Join(dir, "real")
			os.WriteFile(target, []byte("x-secret-value"), 0o600)
			os.Remove(filepath.Join(dir, "crm-export"))
			os.Symlink(target, filepath.Join(dir, "crm-export"))
		},
		"file is a directory": func(dir string) {
			os.Remove(filepath.Join(dir, "crm-export"))
			os.Mkdir(filepath.Join(dir, "crm-export"), 0o700)
		},
	}
	for name, mutate := range fileCases {
		t.Run(name, func(t *testing.T) {
			dir := secretsDir(t, map[string]os.FileMode{"crm-export": 0o600})
			mutate(dir)
			b, err := Load([]byte(config), Sources{LookupEnv: envOf(map[string]string{"WARDEN_SECRET_PAYMENTS": token, "WARDEN_SECRET_SMTP": "x"}), Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.For("crm", "export"); !errors.Is(err, ErrSecret) {
				t.Fatalf("got %v, want ErrSecret", err)
			}
		})
	}
}

func TestSecretsNeverPrint(t *testing.T) {
	b := broker(t)
	creds, err := b.For("payments", "refund")
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{
		fmt.Sprint(creds), fmt.Sprintf("%v", creds), fmt.Sprintf("%+v", creds), fmt.Sprintf("%#v", creds),
		fmt.Sprintf("%s", creds[0].Value), fmt.Sprintf("%q", creds[0].Value), fmt.Sprintf("%x", creds[0].Value),
		string(j),
	}
	for _, o := range outputs {
		if strings.Contains(o, token) || strings.Contains(o, fmt.Sprintf("%x", token)) {
			t.Fatalf("secret leaked in %q", o)
		}
		if !strings.Contains(o, Redacted) {
			t.Fatalf("output %q does not show the redaction marker", o)
		}
	}

	// Errors name the variable, never a value.
	b2, _ := Load([]byte(config), Sources{LookupEnv: envOf(map[string]string{"WARDEN_SECRET_SMTP": token}), Dir: t.TempDir()})
	_, err = b2.For("payments", "refund")
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "WARDEN_SECRET_PAYMENTS") {
		t.Fatalf("error %v", err)
	}
}

func TestScrub(t *testing.T) {
	b := broker(t)
	creds, err := b.For("payments", "refund")
	if err != nil {
		t.Fatal(err)
	}
	full := "Bearer " + token
	cases := map[string]string{
		"raw":             `{"echo":"` + full + `"}`,
		"standard base64": base64.StdEncoding.EncodeToString([]byte(full)),
		"url base64":      base64.RawURLEncoding.EncodeToString([]byte(full)),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, found := Scrub([]byte(in), creds)
			if !found || strings.Contains(string(out), token) || strings.Contains(string(out), in) {
				t.Fatalf("not scrubbed: %s", out)
			}
		})
	}
	clean := `{"status":"refunded"}`
	if out, found := Scrub([]byte(clean), creds); found || string(out) != clean {
		t.Fatalf("clean output changed: %s", out)
	}
}

func TestLoadRejects(t *testing.T) {
	good := `{"server":"s","tool":"*","inject":"header","name":"Authorization","secret":"env:WARDEN_SECRET_X"}`
	wrap := func(bindings ...string) string { return `{"v":1,"bindings":[` + strings.Join(bindings, ",") + `]}` }
	with := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	src := Sources{LookupEnv: envOf(nil), Dir: t.TempDir()}
	cases := map[string]string{
		"env without prefix":     wrap(with("WARDEN_SECRET_X", "AWS_SECRET_ACCESS_KEY")),
		"bare prefix":            wrap(with("WARDEN_SECRET_X", "WARDEN_SECRET_")),
		"lowercase env":          wrap(with("WARDEN_SECRET_X", "warden_secret_x")),
		"file path traversal":    wrap(with("env:WARDEN_SECRET_X", "file:../etc/passwd")),
		"file with slash":        wrap(with("env:WARDEN_SECRET_X", "file:a/b")),
		"hidden file":            wrap(with("env:WARDEN_SECRET_X", "file:.token")),
		"unknown source":         wrap(with("env:WARDEN_SECRET_X", "vault:x")),
		"no source kind":         wrap(with("env:WARDEN_SECRET_X", "WARDEN_SECRET_X")),
		"unknown inject":         wrap(with(`"inject":"header"`, `"inject":"query"`)),
		"header with space":      wrap(with("Authorization", "Bad Header")),
		"header with colon":      wrap(with("Authorization", "X:Y")),
		"env name lowercase":     wrap(with(`"inject":"header","name":"Authorization"`, `"inject":"env","name":"token"`)),
		"prefix with newline":    wrap(with(`"secret"`, `"prefix":"Bearer\n","secret"`)),
		"bad server":             wrap(with(`"server":"s"`, `"server":"a/b"`)),
		"unknown field":          wrap(with(`"server":"s"`, `"server":"s","scope":"all"`)),
		"wrong version":          strings.Replace(wrap(good), `"v":1`, `"v":2`, 1),
		"trailing data":          wrap(good) + ` {}`,
		"wildcard overlaps tool": wrap(good, with(`"tool":"*"`, `"tool":"refund"`)),
		"duplicate binding":      wrap(good, good),
		"header case overlap":    wrap(good, with("Authorization", "authorization")),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(cfg), src); !errors.Is(err, ErrConfig) {
				t.Fatalf("got %v, want ErrConfig", err)
			}
		})
	}
	t.Run("file secret without a directory", func(t *testing.T) {
		if _, err := Load([]byte(wrap(with("env:WARDEN_SECRET_X", "file:tok"))), Sources{}); !errors.Is(err, ErrConfig) {
			t.Fatalf("got %v, want ErrConfig", err)
		}
	})
	t.Run("same name on different servers is fine", func(t *testing.T) {
		if _, err := Load([]byte(wrap(good, with(`"server":"s"`, `"server":"t"`))), src); err != nil {
			t.Fatal(err)
		}
	})
}
