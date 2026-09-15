package keyfile

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/composite"
)

func mldsaKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func certDER(t *testing.T, k *mldsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.PublicKey(), k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRoundTrips(t *testing.T) {
	dir := t.TempDir()

	mk := mldsaKey(t)
	p := filepath.Join(dir, "server.key")
	if err := WriteMLDSA(p, mk); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("key written with mode %v", info.Mode().Perm())
	}
	got, err := ReadMLDSA(p)
	if err != nil || !bytes.Equal(got.PublicKey().Bytes(), mk.PublicKey().Bytes()) {
		t.Fatalf("ML-DSA key round trip: %v", err)
	}

	ck, err := composite.MLDSA65Ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(dir, "receipt.key")
	if err := WriteComposite(cp, ck); err != nil {
		t.Fatal(err)
	}
	gotC, err := ReadComposite(cp)
	if err != nil || !bytes.Equal(gotC.Public().Bytes(), ck.Public().Bytes()) {
		t.Fatalf("composite key round trip: %v", err)
	}

	der := certDER(t, mk)
	certPath := filepath.Join(dir, "server.pem")
	if err := WriteCertificate(certPath, der); err != nil {
		t.Fatal(err)
	}
	gotDER, err := ReadCertificate(certPath)
	if err != nil || !bytes.Equal(gotDER, der) {
		t.Fatalf("certificate round trip: %v", err)
	}
}

func TestNeverOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := WriteMLDSA(p, mldsaKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := WriteMLDSA(p, mldsaKey(t)); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

func TestReadRefuses(t *testing.T) {
	dir := t.TempDir()
	mk := mldsaKey(t)
	good := filepath.Join(dir, "good.key")
	if err := WriteMLDSA(good, mk); err != nil {
		t.Fatal(err)
	}
	goodData, _ := os.ReadFile(good)
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}

	cases := map[string]func() error{
		"group-readable key": func() error {
			_, err := ReadMLDSA(write("group.key", goodData, 0o640))
			return err
		},
		"symlinked key": func() error {
			link := filepath.Join(dir, "link.key")
			os.Symlink(good, link)
			_, err := ReadMLDSA(link)
			return err
		},
		"trailing data": func() error {
			_, err := ReadMLDSA(write("trailing.key", append(bytes.Clone(goodData), []byte("extra")...), 0o600))
			return err
		},
		"two PEM blocks": func() error {
			_, err := ReadMLDSA(write("two.key", append(bytes.Clone(goodData), goodData...), 0o600))
			return err
		},
		"wrong PEM type": func() error {
			_, err := ReadComposite(good)
			return err
		},
		"not PEM": func() error {
			_, err := ReadMLDSA(write("garbage.key", []byte("not a key"), 0o600))
			return err
		},
		"PEM headers": func() error {
			_, err := ReadMLDSA(write("headers.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}}), 0o600))
			return err
		},
		"short composite seed": func() error {
			_, err := ReadComposite(write("short.key", pem.EncodeToMemory(&pem.Block{Type: CompositePEMType, Bytes: make([]byte, 32)}), 0o600))
			return err
		},
		"certificate that does not parse": func() error {
			_, err := ReadCertificate(write("bad.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")}), 0o644))
			return err
		},
		"missing file": func() error {
			_, err := ReadMLDSA(filepath.Join(dir, "missing.key"))
			return err
		},
	}
	for name, read := range cases {
		t.Run(name, func(t *testing.T) {
			if read() == nil {
				t.Fatal("accepted")
			}
		})
	}
}
