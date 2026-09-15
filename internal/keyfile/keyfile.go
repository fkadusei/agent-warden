// Package keyfile reads and writes Warden's keys and certificates as PEM files.
//
// ML-DSA-65 private keys use standard PKCS#8 ("PRIVATE KEY"). Composite
// ML-DSA-65 + Ed25519 keys have no standard encoding yet, so they are stored as
// their 64-byte seed under a Warden-specific PEM type.
//
// Files are never overwritten. Private keys are written owner-only (0600), and a
// private key file that is readable by group or others, is a symlink, or holds
// anything besides one PEM block is refused.
package keyfile

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/fkadusei/agent-warden/internal/composite"
)

const (
	// CompositePEMType labels a composite ML-DSA-65 + Ed25519 private key seed.
	CompositePEMType = "WARDEN ML-DSA-65-ED25519 PRIVATE KEY"
	privateKeyType   = "PRIVATE KEY"
	certificateType  = "CERTIFICATE"

	mldsa65PublicKeySize = 1952
)

// ErrExists is returned instead of overwriting a file.
var ErrExists = errors.New("keyfile: file already exists")

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: %s", ErrExists, path)
	}
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("keyfile: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("keyfile: %w", err)
	}
	return f.Close()
}

func readPEM(path, wantType string, private bool) ([]byte, error) {
	if private {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("keyfile: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("keyfile: %s is not a regular file", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("keyfile: %s has mode %v; a private key must not be accessible to group or others", path, info.Mode().Perm())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keyfile: %s holds no PEM block", path)
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("keyfile: %s holds %q, want %q", path, block.Type, wantType)
	}
	if len(block.Headers) > 0 {
		return nil, fmt.Errorf("keyfile: %s has PEM headers", path)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("keyfile: %s holds data after its PEM block", path)
	}
	return block.Bytes, nil
}

// WriteMLDSA writes an ML-DSA-65 private key as PKCS#8 PEM, owner-only.
func WriteMLDSA(path string, k *mldsa.PrivateKey) error {
	if len(k.PublicKey().Bytes()) != mldsa65PublicKeySize {
		return errors.New("keyfile: key is not ML-DSA-65")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return writeNew(path, pem.EncodeToMemory(&pem.Block{Type: privateKeyType, Bytes: der}), 0o600)
}

// ReadMLDSA reads an ML-DSA-65 private key.
func ReadMLDSA(path string) (*mldsa.PrivateKey, error) {
	der, err := readPEM(path, privateKeyType, true)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: %w", path, err)
	}
	k, ok := key.(*mldsa.PrivateKey)
	if !ok || len(k.PublicKey().Bytes()) != mldsa65PublicKeySize {
		return nil, fmt.Errorf("keyfile: %s is not an ML-DSA-65 private key", path)
	}
	return k, nil
}

// WriteComposite writes a composite ML-DSA-65 + Ed25519 private key seed, owner-only.
func WriteComposite(path string, k *composite.PrivateKey) error {
	return writeNew(path, pem.EncodeToMemory(&pem.Block{Type: CompositePEMType, Bytes: k.Seed()}), 0o600)
}

// ReadComposite reads a composite ML-DSA-65 + Ed25519 private key.
func ReadComposite(path string) (*composite.PrivateKey, error) {
	seed, err := readPEM(path, CompositePEMType, true)
	if err != nil {
		return nil, err
	}
	k, err := composite.MLDSA65Ed25519.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: %w", path, err)
	}
	return k, nil
}

// WriteCertificate writes a DER certificate as PEM.
func WriteCertificate(path string, der []byte) error {
	if _, err := x509.ParseCertificate(der); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return writeNew(path, pem.EncodeToMemory(&pem.Block{Type: certificateType, Bytes: der}), 0o644)
}

// ReadCertificate reads one PEM certificate and returns its DER.
func ReadCertificate(path string) ([]byte, error) {
	der, err := readPEM(path, certificateType, false)
	if err != nil {
		return nil, err
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("keyfile: %s: %w", path, err)
	}
	return der, nil
}
