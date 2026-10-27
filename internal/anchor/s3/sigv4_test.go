package s3

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The worked examples in AWS's documentation for Signature Version 4 with a
// single-chunk payload ("Signature Calculations for the Authorization Header").
// They use AWS's published example credentials, which grant nothing.
var awsExample = Credentials{
	AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

var awsExampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func signature(t *testing.T, req *http.Request) (signed, sig string) {
	t.Helper()
	auth := req.Header.Get("Authorization")
	_, after, ok := strings.Cut(auth, "SignedHeaders=")
	if !ok {
		t.Fatalf("Authorization: %q", auth)
	}
	signed, sig, ok = strings.Cut(after, ", Signature=")
	if !ok {
		t.Fatalf("Authorization: %q", auth)
	}
	return signed, sig
}

func TestSignMatchesAWSExamples(t *testing.T) {
	cases := []struct {
		name, method, url string
		headers           map[string]string
		payloadHash       string
		signed, sig       string
	}{
		{
			name: "GET object", method: "GET", url: "https://examplebucket.s3.amazonaws.com/test.txt",
			headers:     map[string]string{"Range": "bytes=0-9"},
			payloadHash: EmptyHash,
			signed:      "host;range;x-amz-content-sha256;x-amz-date",
			sig:         "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "PUT object", method: "PUT", url: "https://examplebucket.s3.amazonaws.com/test$file.text",
			headers: map[string]string{
				"Date":                "Fri, 24 May 2013 00:00:00 GMT",
				"X-Amz-Storage-Class": "REDUCED_REDUNDANCY",
			},
			payloadHash: hexSHA256([]byte("Welcome to Amazon S3.")),
			signed:      "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
			sig:         "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name: "GET bucket lifecycle", method: "GET", url: "https://examplebucket.s3.amazonaws.com/?lifecycle",
			payloadHash: EmptyHash,
			signed:      "host;x-amz-content-sha256;x-amz-date",
			sig:         "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name: "list objects", method: "GET", url: "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			payloadHash: EmptyHash,
			signed:      "host;x-amz-content-sha256;x-amz-date",
			sig:         "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			Sign(req, tc.payloadHash, awsExample, "us-east-1", awsExampleTime)
			signed, sig := signature(t, req)
			if signed != tc.signed {
				t.Errorf("signed headers %q, want %q", signed, tc.signed)
			}
			if sig != tc.sig {
				t.Errorf("signature %s, want %s", sig, tc.sig)
			}
		})
	}
}

func TestCanonicalQuery(t *testing.T) {
	for raw, want := range map[string]string{
		"":                           "",
		"versions":                   "versions=",
		"prefix=a%2Fb&versions":      "prefix=a%2Fb&versions=",
		"b=2&a=1&a=0":                "a=0&a=1&b=2",
		"key-marker=x%20y&max-keys=": "key-marker=x%20y&max-keys=",
	} {
		if got := canonicalQuery(raw); got != want {
			t.Errorf("canonicalQuery(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A header added after signing must change the signature, or the store would
// accept a request that differs from the one signed.
func TestSigningCoversEveryHeader(t *testing.T) {
	req, _ := http.NewRequest("PUT", "https://examplebucket.s3.amazonaws.com/k", nil)
	req.Header.Set("X-Amz-Object-Lock-Mode", "COMPLIANCE")
	Sign(req, EmptyHash, awsExample, "us-east-1", awsExampleTime)
	_, first := signature(t, req)
	req.Header.Set("X-Amz-Object-Lock-Mode", "GOVERNANCE")
	Sign(req, EmptyHash, awsExample, "us-east-1", awsExampleTime)
	_, second := signature(t, req)
	if first == second {
		t.Fatal("changing a signed header did not change the signature")
	}
}

func TestURLStyles(t *testing.T) {
	c := &Client{Endpoint: "https://s3.eu-west-1.amazonaws.com", Bucket: "anchors"}
	u, err := c.url("p/chain/00000000000000000003.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.String(); got != "https://anchors.s3.eu-west-1.amazonaws.com/p/chain/00000000000000000003.json" {
		t.Fatalf("virtual-hosted URL %q", got)
	}
	c.PathStyle, c.Endpoint = true, "http://127.0.0.1:9000/"
	u, _ = c.url("k", "versions=")
	if got := u.String(); got != "http://127.0.0.1:9000/anchors/k?versions=" {
		t.Fatalf("path-style URL %q", got)
	}
	for _, bad := range []string{"", "ftp://x", "s3.amazonaws.com", "https://"} {
		c.Endpoint = bad
		if _, err := c.url("k", ""); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
}
