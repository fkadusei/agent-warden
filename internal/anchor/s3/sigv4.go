package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Credentials are a static access key pair.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

const (
	amzDateFormat = "20060102T150405Z"
	algorithm     = "AWS4-HMAC-SHA256"
	service       = "s3"
)

// EmptyHash is the SHA-256 of an empty payload.
const EmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Sign adds AWS Signature Version 4 headers to req: X-Amz-Date,
// X-Amz-Content-Sha256 and Authorization. payloadHash is the hex SHA-256 of the
// body. Every header already on req is signed, along with Host, so nothing may
// be added to req after signing.
func Sign(req *http.Request, payloadHash string, c Credentials, region string, t time.Time) {
	t = t.UTC()
	req.Header.Del("Authorization")
	req.Header.Set("X-Amz-Date", t.Format(amzDateFormat))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	scope := t.Format("20060102") + "/" + region + "/" + service + "/aws4_request"
	signed, canonical := canonicalRequest(req, payloadHash)
	toSign := algorithm + "\n" + t.Format(amzDateFormat) + "\n" + scope + "\n" + hexSHA256([]byte(canonical))

	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), t.Format("20060102"))
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))

	req.Header.Set("Authorization", algorithm+" Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

// canonicalRequest returns the signed header list and the canonical request.
func canonicalRequest(req *http.Request, payloadHash string) (string, string) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "authorization" {
			continue
		}
		trimmed := make([]string, len(values))
		for i, v := range values {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		headers[lower] = strings.Join(trimmed, ",")
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + headers[n] + "\n")
	}
	signed := strings.Join(names, ";")

	// SigV4 encodes the path itself: Go leaves characters such as '$' bare on
	// the wire, but the canonical form needs them percent-encoded.
	path := uriEncode(req.URL.Path, false)
	if path == "" {
		path = "/"
	}
	canonical := req.Method + "\n" + path + "\n" + canonicalQuery(req.URL.RawQuery) + "\n" +
		ch.String() + "\n" + signed + "\n" + payloadHash
	return signed, canonical
}

// canonicalQuery sorts the query by name, then value, with each part encoded
// as SigV4 requires. A name without a value becomes "name=".
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		pairs = append(pairs, kv{uriEncode(unescape(k), true), uriEncode(unescape(v), true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

// uriEncode percent-encodes everything except unreserved characters, and
// leaves '/' alone when encodeSlash is false (object key paths).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// unescape reverses percent-encoding in a query part; '+' is left as is, since
// this client never encodes a space as '+'.
func unescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b = append(b, v[0])
				i += 2
				continue
			}
		}
		b = append(b, s[i])
	}
	return string(b)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
