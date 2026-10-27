// Package s3fake is an in-process object store with the parts of the S3 API
// and Object Lock that the anchor relies on (ADR-0017): versions, delete
// markers, compliance and governance retention, server-set modification times,
// conditional writes, and signed requests.
//
// It exists so tests and the gate can run offline. It proves Warden's side of
// the protocol, not any real provider's; it serves one bucket, path-style.
package s3fake

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
)

// Version is one stored version or delete marker.
type Version struct {
	ID           string
	Data         []byte
	DeleteMarker bool
	Mode         string
	RetainUntil  time.Time
	Modified     time.Time
}

// Server is a single-bucket store. The zero value is not usable; use New.
type Server struct {
	Bucket string
	Region string
	Creds  s3.Credentials

	mu      sync.Mutex
	now     func() time.Time
	down    bool
	seq     int
	objects map[string][]*Version // newest last
	pageMax int
	puts    int
}

// New returns a store for bucket that accepts requests signed with creds.
func New(bucket, region string, creds s3.Credentials) *Server {
	return &Server{Bucket: bucket, Region: region, Creds: creds, now: time.Now,
		objects: map[string][]*Version{}, pageMax: 1000}
}

// SetNow replaces the store's clock, which sets modification times and decides
// whether retention has ended.
func (s *Server) SetNow(now func() time.Time) { s.mu.Lock(); s.now = now; s.mu.Unlock() }

// SetDown makes every request fail with 503 until called with false.
func (s *Server) SetDown(down bool) { s.mu.Lock(); s.down = down; s.mu.Unlock() }

// SetPageSize limits how many entries a version listing returns per page.
func (s *Server) SetPageSize(n int) { s.mu.Lock(); s.pageMax = n; s.mu.Unlock() }

// Versions returns a copy of key's versions, oldest first.
func (s *Server) Versions(key string) []Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Version
	for _, v := range s.objects[key] {
		out = append(out, *v)
	}
	return out
}

// Keys returns every name that has at least one version, sorted.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Puts counts the PUT requests that stored a version.
func (s *Server) Puts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.puts }

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, msg)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		fail(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		fail(w, http.StatusServiceUnavailable, "SlowDown", "the store is down")
		return
	}
	if code, msg := s.authenticate(r, body); code != "" {
		fail(w, http.StatusForbidden, code, msg)
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != s.Bucket {
		fail(w, http.StatusNotFound, "NoSuchBucket", bucket)
		return
	}
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && key == "" && q.Has("versions"):
		s.list(w, q)
	case r.Method == http.MethodPut && key != "" && len(q) == 0:
		s.put(w, r, key, body)
	case r.Method == http.MethodGet && key != "" && q.Has("retention"):
		s.retention(w, key, q.Get("versionId"))
	case r.Method == http.MethodGet && key != "":
		s.get(w, key, q.Get("versionId"))
	case r.Method == http.MethodDelete && key != "":
		s.delete(w, r, key, q.Get("versionId"))
	default:
		fail(w, http.StatusNotImplemented, "NotImplemented", r.Method+" "+r.URL.String())
	}
}

// authenticate re-signs the request with the store's own copy of the secret
// and compares, so a header changed after signing, or a body that does not
// match its hash, is refused.
func (s *Server) authenticate(r *http.Request, body []byte) (string, string) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+s.Creds.AccessKeyID+"/") {
		return "InvalidAccessKeyId", "unknown access key"
	}
	if !strings.Contains(auth, "/"+s.Region+"/s3/aws4_request") {
		return "AuthorizationHeaderMalformed", "wrong region"
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		return "XAmzContentSHA256Mismatch", "payload hash does not match the body"
	}
	t, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return "AccessDenied", "bad X-Amz-Date"
	}
	_, after, _ := strings.Cut(auth, "SignedHeaders=")
	signedList, _, _ := strings.Cut(after, ",")
	check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	check.Host = r.Host
	for _, h := range strings.Split(signedList, ";") {
		if h == "host" || h == "x-amz-date" || h == "x-amz-content-sha256" {
			continue
		}
		vals := r.Header.Values(h)
		if len(vals) == 0 {
			return "AccessDenied", "signed header " + h + " is missing"
		}
		for _, v := range vals {
			check.Header.Add(h, v)
		}
	}
	// Every header the client sent that S3 would treat as signed must be in the
	// signed list.
	for name := range r.Header {
		l := strings.ToLower(name)
		if (strings.HasPrefix(l, "x-amz-") || l == "if-none-match" || l == "content-md5") &&
			!strings.Contains(";"+signedList+";", ";"+l+";") {
			return "AccessDenied", "header " + l + " is not signed"
		}
	}
	s3.Sign(check, r.Header.Get("X-Amz-Content-Sha256"), s.Creds, s.Region, t)
	if check.Header.Get("Authorization") != auth {
		return "SignatureDoesNotMatch", "signature does not match"
	}
	return "", ""
}

func (s *Server) latest(key string) *Version {
	vs := s.objects[key]
	if len(vs) == 0 {
		return nil
	}
	return vs[len(vs)-1]
}

func (s *Server) find(key, id string) *Version {
	for _, v := range s.objects[key] {
		if v.ID == id {
			return v
		}
	}
	return nil
}

func (s *Server) newVersion() (string, time.Time) {
	s.seq++
	return fmt.Sprintf("v%06d", s.seq), s.now().UTC().Truncate(time.Second)
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, key string, body []byte) {
	mode := r.Header.Get("X-Amz-Object-Lock-Mode")
	untilStr := r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")
	var until time.Time
	if mode != "" || untilStr != "" {
		if mode != s3.LockCompliance && mode != "GOVERNANCE" {
			fail(w, http.StatusBadRequest, "InvalidArgument", "unknown lock mode")
			return
		}
		var err error
		if until, err = time.Parse(time.RFC3339, untilStr); err != nil || !until.After(s.now()) {
			fail(w, http.StatusBadRequest, "InvalidArgument", "retain-until must be a future date")
			return
		}
		if r.Header.Get("Content-Md5") == "" && r.Header.Get("X-Amz-Checksum-Sha256") == "" {
			fail(w, http.StatusBadRequest, "InvalidRequest", "Content-MD5 or a checksum is required with Object Lock")
			return
		}
	}
	if v := r.Header.Get("Content-Md5"); v != "" {
		sum := md5.Sum(body)
		if v != base64.StdEncoding.EncodeToString(sum[:]) {
			fail(w, http.StatusBadRequest, "BadDigest", "Content-MD5 does not match")
			return
		}
	}
	if v := r.Header.Get("X-Amz-Checksum-Sha256"); v != "" {
		sum := sha256.Sum256(body)
		if v != base64.StdEncoding.EncodeToString(sum[:]) {
			fail(w, http.StatusBadRequest, "BadDigest", "checksum does not match")
			return
		}
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if inm != "*" {
			fail(w, http.StatusNotImplemented, "NotImplemented", "If-None-Match supports only *")
			return
		}
		if l := s.latest(key); l != nil && !l.DeleteMarker {
			fail(w, http.StatusPreconditionFailed, "PreconditionFailed", "an object exists under this name")
			return
		}
	}
	id, mod := s.newVersion()
	s.objects[key] = append(s.objects[key], &Version{ID: id, Data: bytes.Clone(body), Mode: mode,
		RetainUntil: until, Modified: mod})
	s.puts++
	w.Header().Set("X-Amz-Version-Id", id)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) get(w http.ResponseWriter, key, id string) {
	v := s.latest(key)
	if id != "" {
		v = s.find(key, id)
	}
	if v == nil {
		fail(w, http.StatusNotFound, "NoSuchKey", key)
		return
	}
	if v.DeleteMarker {
		w.Header().Set("X-Amz-Delete-Marker", "true")
		if id != "" {
			fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "version is a delete marker")
			return
		}
		fail(w, http.StatusNotFound, "NoSuchKey", key)
		return
	}
	w.Header().Set("X-Amz-Version-Id", v.ID)
	w.Header().Set("Last-Modified", v.Modified.Format(http.TimeFormat))
	if v.Mode != "" {
		w.Header().Set("X-Amz-Object-Lock-Mode", v.Mode)
		w.Header().Set("X-Amz-Object-Lock-Retain-Until-Date", v.RetainUntil.UTC().Format(time.RFC3339))
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(v.Data)))
	w.WriteHeader(http.StatusOK)
	w.Write(v.Data)
}

func (s *Server) retention(w http.ResponseWriter, key, id string) {
	v := s.latest(key)
	if id != "" {
		v = s.find(key, id)
	}
	if v == nil || v.DeleteMarker {
		fail(w, http.StatusNotFound, "NoSuchKey", key)
		return
	}
	if v.Mode == "" {
		fail(w, http.StatusNotFound, "NoSuchObjectLockConfiguration", "no retention")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, "<Retention><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>",
		v.Mode, v.RetainUntil.UTC().Format(time.RFC3339))
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request, key, id string) {
	if id == "" {
		vid, mod := s.newVersion()
		s.objects[key] = append(s.objects[key], &Version{ID: vid, DeleteMarker: true, Modified: mod})
		w.Header().Set("X-Amz-Delete-Marker", "true")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	vs := s.objects[key]
	for i, v := range vs {
		if v.ID != id {
			continue
		}
		locked := v.Mode != "" && s.now().Before(v.RetainUntil)
		bypass := v.Mode == "GOVERNANCE" && r.Header.Get("X-Amz-Bypass-Governance-Retention") == "true"
		if locked && !bypass {
			fail(w, http.StatusForbidden, "AccessDenied", "the version is locked")
			return
		}
		s.objects[key] = append(vs[:i:i], vs[i+1:]...)
		if len(s.objects[key]) == 0 {
			delete(s.objects, key)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fail(w, http.StatusNotFound, "NoSuchVersion", id)
}

type entry struct {
	key string
	v   *Version
}

func (s *Server) list(w http.ResponseWriter, q url.Values) {
	prefix := q.Get("prefix")
	var all []entry
	for _, k := range s.sortedKeys() {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		vs := s.objects[k]
		for i := len(vs) - 1; i >= 0; i-- { // newest first, as S3 lists them
			all = append(all, entry{k, vs[i]})
		}
	}
	start := 0
	if km := q.Get("key-marker"); km != "" {
		vm := q.Get("version-id-marker")
		for i, e := range all {
			if e.key == km && e.v.ID == vm {
				start = i + 1
				break
			}
		}
	}
	end := min(start+s.pageMax, len(all))
	var b strings.Builder
	b.WriteString("<ListVersionsResult>")
	truncated := end < len(all)
	fmt.Fprintf(&b, "<IsTruncated>%t</IsTruncated>", truncated)
	if truncated {
		last := all[end-1]
		fmt.Fprintf(&b, "<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>",
			xmlEscape(last.key), last.v.ID)
	}
	for _, e := range all[start:end] {
		latest := s.latest(e.key) == e.v
		tag := "Version"
		if e.v.DeleteMarker {
			tag = "DeleteMarker"
		}
		fmt.Fprintf(&b, "<%s><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified></%s>",
			tag, xmlEscape(e.key), e.v.ID, latest, e.v.Modified.Format("2006-01-02T15:04:05.000Z"), tag)
	}
	b.WriteString("</ListVersionsResult>")
	w.Header().Set("Content-Type", "application/xml")
	io.WriteString(w, b.String())
}

func (s *Server) sortedKeys() []string {
	keys := make([]string, 0, len(s.objects))
	for k := range s.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
