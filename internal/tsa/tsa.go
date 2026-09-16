// Package tsa anchors checkpoints in time with RFC 3161 timestamps (ADR-0014,
// threats W10, W12).
//
// A timestamp is evidence about *when* a checkpoint existed, from a party that is not
// Warden. It is an addition, never a dependency: the hash chain and the signed
// checkpoints stand on their own, tokens live in their own file, and a timestamp
// authority that is slow or down never blocks a call.
//
// The authority signs with its own (classical) key, so a token is not post-quantum
// evidence; Warden's receipts and checkpoints remain ML-DSA-65 + Ed25519.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/digitorus/timestamp"
)

const (
	// ContentType is the RFC 3161 media type for a timestamp request.
	ContentType = "application/timestamp-query"
	// ReplyContentType is the media type of a response.
	ReplyContentType = "application/timestamp-reply"

	maxResponse = 1 << 20
	// TokenVersion is the version of a line in the token file.
	TokenVersion = 1
)

// ErrInvalid wraps every failed check of a token.
var ErrInvalid = errors.New("timestamp token is not valid for this data")

// Digest is the "sha256:<hex>" form Warden uses elsewhere.
func Digest(message []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(message))
}

// Client asks a timestamp authority to stamp bytes.
type Client struct {
	URL  string
	HTTP *http.Client
}

// Stamp returns the DER timestamp token over message. The authority sees only the
// hash of the message, never the message itself.
func (c *Client) Stamp(ctx context.Context, message []byte) ([]byte, error) {
	req, err := timestamp.CreateRequest(bytes.NewReader(message), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true, // the token must carry the TSA certificate, so it verifies offline
	})
	if err != nil {
		return nil, fmt.Errorf("tsa: build request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentType)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("tsa: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa: %s replied %s", c.URL, resp.Status)
	}
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}
	if len(ts.RawToken) == 0 {
		return nil, errors.New("tsa: response carried no token")
	}
	return ts.RawToken, nil
}

// Verify checks that token is a timestamp over exactly these bytes, signed by an
// authority that chains to roots, and returns the time it states.
func Verify(token, message []byte, roots *x509.CertPool) (time.Time, error) {
	ts, err := timestamp.Parse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if ts.HashAlgorithm != crypto.SHA256 {
		return time.Time{}, fmt.Errorf("%w: hashed with %v, want SHA-256", ErrInvalid, ts.HashAlgorithm)
	}
	sum := sha256.Sum256(message)
	if !bytes.Equal(ts.HashedMessage, sum[:]) {
		return time.Time{}, fmt.Errorf("%w: the token is over different data", ErrInvalid)
	}
	if len(ts.Certificates) == 0 {
		return time.Time{}, fmt.Errorf("%w: the token carries no certificate", ErrInvalid)
	}
	if roots == nil {
		return time.Time{}, fmt.Errorf("%w: no trusted timestamp roots were given", ErrInvalid)
	}

	// The signing certificate is the one allowed to timestamp; the rest may be
	// intermediates.
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	for _, c := range ts.Certificates {
		if canTimestamp(c) && leaf == nil {
			leaf = c
			continue
		}
		intermediates.AddCert(c)
	}
	if leaf == nil {
		return time.Time{}, fmt.Errorf("%w: no certificate in the token may act as a timestamp authority", ErrInvalid)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   ts.Time,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return ts.Time.UTC(), nil
}

func canTimestamp(c *x509.Certificate) bool {
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}

// Token is one line of the token file: a timestamp over the bytes whose digest it names.
type Token struct {
	V int `json:"v"`
	// Message is the digest of the exact bytes the token covers (an anchor line).
	Message string `json:"message"`
	// Token is the DER RFC 3161 token, base64 (standard, padded).
	Token string `json:"token"`
}

// AppendToken adds a token for message to the file, creating it if needed. Tokens are
// kept beside the anchor rather than inside it, so anchored checkpoints keep verifying
// byte for byte whether or not they are timestamped.
func AppendToken(path string, message, token []byte) error {
	line, err := json.Marshal(Token{V: TokenVersion, Message: Digest(message), Token: base64.StdEncoding.EncodeToString(token)})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ReadTokens reads a token file into a map from message digest to DER tokens. A digest
// may carry more than one token (several authorities, or a retry).
func ReadTokens(r io.Reader) (map[string][][]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out := map[string][][]byte{}
	for i, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var t Token
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("token line %d: %w", i+1, err)
		}
		if t.V != TokenVersion {
			return nil, fmt.Errorf("token line %d: v is %d, want %d", i+1, t.V, TokenVersion)
		}
		der, err := base64.StdEncoding.DecodeString(t.Token)
		if err != nil || len(der) == 0 {
			return nil, fmt.Errorf("token line %d: token is not base64 DER", i+1)
		}
		out[t.Message] = append(out[t.Message], der)
	}
	return out, nil
}

// LoadRoots reads PEM certificates trusted to act as timestamp authorities.
func LoadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return pool, nil
}
