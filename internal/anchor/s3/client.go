// Package s3 is a minimal client for an S3-compatible object store with Object
// Lock, and a checkpoint anchor built on it (ADR-0017).
//
// It implements only what anchoring needs: a conditional, locked PUT; GET; a
// listing of every version and delete marker; and reading a version's
// retention. Requests are signed with AWS Signature Version 4. The client never
// verifies a checkpoint; that stays in internal/checkpoint.
package s3

import (
	"bytes"
	"context"
	"crypto/md5" // Content-MD5 is an integrity header Object Lock uploads require, not a security hash.
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxObject bounds what Get reads. A checkpoint line is a few hundred bytes.
const MaxObject = 1 << 20

// LockCompliance is the only Object Lock mode an anchor accepts: nobody,
// the account's root user included, can shorten it or delete the version.
const LockCompliance = "COMPLIANCE"

var (
	// ErrExists is returned by PutLocked when the name already holds an object.
	ErrExists = errors.New("s3: object already exists")
	// ErrNotFound is returned when an object, version or retention is absent.
	ErrNotFound = errors.New("s3: not found")
)

// Error is an error response from the store.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("s3: %d %s: %s", e.Status, e.Code, e.Message)
}

// Client talks to one bucket.
type Client struct {
	// Endpoint is the store's base URL, such as https://s3.eu-west-1.amazonaws.com.
	Endpoint string
	Region   string
	Bucket   string
	// PathStyle puts the bucket in the path (endpoint/bucket/key) rather than
	// the host name (bucket.endpoint/key). Local stores usually need it.
	PathStyle bool
	Creds     Credentials
	HTTP      *http.Client
	// Now is the signing clock; nil means time.Now.
	Now func() time.Time
}

// Object is one version read back from the store.
type Object struct {
	Body         []byte
	VersionID    string
	LastModified time.Time
	LockMode     string
	RetainUntil  time.Time
}

// Version is one entry in a version listing: an object version or a delete
// marker. Listings keep the store's order, newest first within each name.
type Version struct {
	Key          string
	VersionID    string
	LastModified time.Time
	IsLatest     bool
	DeleteMarker bool
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) url(key string, query string) (*url.URL, error) {
	base, err := url.Parse(c.Endpoint)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("s3: endpoint %q is not an http or https URL", c.Endpoint)
	}
	u := &url.URL{Scheme: base.Scheme, Host: base.Host, RawQuery: query}
	path := strings.TrimSuffix(base.Path, "/")
	if c.PathStyle {
		path += "/" + c.Bucket
	} else {
		u.Host = c.Bucket + "." + base.Host
	}
	u.Path = path + "/" + key
	u.RawPath = uriEncode(u.Path, false)
	return u, nil
}

func (c *Client) do(ctx context.Context, method, key, query string, header http.Header, body []byte) (*http.Response, error) {
	u, err := c.url(key, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	Sign(req, hexSHA256(body), c.Creds, c.Region, c.now())
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3: %s %s: %w", method, key, err)
	}
	return resp, nil
}

func readError(resp *http.Response) error {
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e struct {
		Code    string
		Message string
	}
	_ = xml.Unmarshal(data, &e)
	if e.Code == "" {
		e.Code = http.StatusText(resp.StatusCode)
	}
	return &Error{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// PutLocked writes body under key only if no object is there, locked in
// compliance mode until retainUntil. It returns the new version ID, or
// ErrExists when the name is taken.
func (c *Client) PutLocked(ctx context.Context, key string, body []byte, retainUntil time.Time) (string, error) {
	sum := sha256.Sum256(body)
	md := md5.Sum(body)
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Md5", base64.StdEncoding.EncodeToString(md[:]))
	h.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
	h.Set("If-None-Match", "*")
	h.Set("X-Amz-Object-Lock-Mode", LockCompliance)
	h.Set("X-Amz-Object-Lock-Retain-Until-Date", retainUntil.UTC().Format(time.RFC3339))
	resp, err := c.do(ctx, http.MethodPut, key, "", h, body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusPreconditionFailed {
		resp.Body.Close()
		return "", fmt.Errorf("%w: %s", ErrExists, key)
	}
	if resp.StatusCode != http.StatusOK {
		return "", readError(resp)
	}
	resp.Body.Close()
	return resp.Header.Get("X-Amz-Version-Id"), nil
}

// Get reads one version of key, or the latest when versionID is empty.
func (c *Client) Get(ctx context.Context, key, versionID string) (*Object, error) {
	query := ""
	if versionID != "" {
		query = "versionId=" + uriEncode(versionID, true)
	}
	resp, err := c.do(ctx, http.MethodGet, key, query, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxObject+1))
	if err != nil {
		return nil, fmt.Errorf("s3: GET %s: %w", key, err)
	}
	if len(body) > MaxObject {
		return nil, fmt.Errorf("s3: GET %s: object larger than %d bytes", key, MaxObject)
	}
	o := &Object{Body: body, VersionID: resp.Header.Get("X-Amz-Version-Id"),
		LockMode: resp.Header.Get("X-Amz-Object-Lock-Mode")}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if o.LastModified, err = http.ParseTime(lm); err != nil {
			return nil, fmt.Errorf("s3: GET %s: Last-Modified %q", key, lm)
		}
	}
	if ru := resp.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"); ru != "" {
		if o.RetainUntil, err = time.Parse(time.RFC3339, ru); err != nil {
			return nil, fmt.Errorf("s3: GET %s: retain-until %q", key, ru)
		}
	}
	return o, nil
}

// Retention reads a version's Object Lock retention. A version with none
// returns ErrNotFound.
func (c *Client) Retention(ctx context.Context, key, versionID string) (mode string, until time.Time, err error) {
	query := "retention="
	if versionID != "" {
		query += "&versionId=" + uriEncode(versionID, true)
	}
	resp, err := c.do(ctx, http.MethodGet, key, query, nil, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		e := readError(resp)
		return "", time.Time{}, fmt.Errorf("%w: retention for %s: %v", ErrNotFound, key, e)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, readError(resp)
	}
	defer resp.Body.Close()
	var r struct {
		Mode            string
		RetainUntilDate string
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil {
		return "", time.Time{}, fmt.Errorf("s3: retention for %s: %w", key, err)
	}
	until, err = time.Parse(time.RFC3339, r.RetainUntilDate)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("s3: retention for %s: date %q", key, r.RetainUntilDate)
	}
	return r.Mode, until, nil
}

// listEntry decodes either a <Version> or a <DeleteMarker>; decoding them
// through one ",any" field keeps the store's interleaved order.
type listEntry struct {
	XMLName      xml.Name
	Key          string
	VersionID    string `xml:"VersionId"`
	IsLatest     bool
	LastModified string
}

type listResult struct {
	IsTruncated         bool
	NextKeyMarker       string
	NextVersionIDMarker string      `xml:"NextVersionIdMarker"`
	Entries             []listEntry `xml:",any"`
}

// ListVersions lists every version and delete marker under prefix, following
// pagination, in the store's order.
func (c *Client) ListVersions(ctx context.Context, prefix string) ([]Version, error) {
	var out []Version
	keyMarker, versionMarker := "", ""
	for page := 0; ; page++ {
		if page > 10000 {
			return nil, errors.New("s3: version listing does not end")
		}
		q := "versions=&prefix=" + uriEncode(prefix, true)
		if keyMarker != "" {
			q += "&key-marker=" + uriEncode(keyMarker, true)
		}
		if versionMarker != "" {
			q += "&version-id-marker=" + uriEncode(versionMarker, true)
		}
		resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, readError(resp)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("s3: version listing: %w", err)
		}
		r, vs, err := parseListing(data)
		if err != nil {
			return nil, err
		}
		out = append(out, vs...)
		if !r.IsTruncated {
			return out, nil
		}
		if r.NextKeyMarker == keyMarker && r.NextVersionIDMarker == versionMarker {
			return nil, errors.New("s3: version listing repeats a page")
		}
		keyMarker, versionMarker = r.NextKeyMarker, r.NextVersionIDMarker
	}
}

// parseListing decodes one page of a version listing. The bytes come from the
// store, so they are untrusted: it is fuzzed.
func parseListing(data []byte) (*listResult, []Version, error) {
	var r listResult
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, nil, fmt.Errorf("s3: version listing: %w", err)
	}
	var out []Version
	for _, e := range r.Entries {
		var marker bool
		switch e.XMLName.Local {
		case "Version":
		case "DeleteMarker":
			marker = true
		default:
			continue
		}
		if e.Key == "" || e.VersionID == "" {
			return nil, nil, errors.New("s3: version listing: an entry without a key or version ID")
		}
		lm, err := time.Parse(time.RFC3339, e.LastModified)
		if err != nil {
			return nil, nil, fmt.Errorf("s3: version listing: %s: LastModified %q", e.Key, e.LastModified)
		}
		out = append(out, Version{Key: e.Key, VersionID: e.VersionID, LastModified: lm,
			IsLatest: e.IsLatest, DeleteMarker: marker})
	}
	return &r, out, nil
}
