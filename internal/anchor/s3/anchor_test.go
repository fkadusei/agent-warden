package s3_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
	"github.com/fkadusei/agent-warden/internal/anchor/s3/s3fake"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// Synthetic credentials for the fake store only.
var creds = s3.Credentials{AccessKeyID: "WARDENTESTKEY", SecretAccessKey: "warden-test-secret-not-real"}

const chainID = "warden-test-chain"

type fixture struct {
	store  *s3fake.Server
	srv    *httptest.Server
	client *s3.Client
	anchor *s3.Anchor
	key    *composite.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := s3fake.New("anchors", "eu-west-1", creds)
	srv := httptest.NewServer(store)
	t.Cleanup(srv.Close)
	client := &s3.Client{Endpoint: srv.URL, Region: "eu-west-1", Bucket: "anchors", PathStyle: true, Creds: creds}
	key, err := composite.MLDSA65Ed25519.NewPrivateKey(bytes.Repeat([]byte{9}, composite.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{store: store, srv: srv, client: client, key: key,
		anchor: &s3.Anchor{Client: client, Prefix: "warden/prod", ChainID: chainID, Retention: 24 * time.Hour}}
}

// checkpointOf signs a checkpoint over n synthetic lines.
func (f *fixture) checkpointOf(t *testing.T, n int, tag string) (*checkpoint.Checkpoint, *receipt.Signed) {
	t.Helper()
	b := checkpoint.NewBuilder(chainID)
	for i := range n {
		b.Add([]byte(fmt.Sprintf(`{"line":%d,"tag":%q}`, i, tag)))
	}
	c, err := b.Checkpoint(time.Now().UTC().Format(receipt.TimeFormat))
	if err != nil {
		t.Fatal(err)
	}
	s, err := checkpoint.Sign(f.key, "warden-e1", c)
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

// operator sends a signed request the anchor never would: an unconditional
// overwrite, a delete, a delete of a specific version.
func (f *fixture) operator(t *testing.T, method, key, query string, body []byte) int {
	t.Helper()
	u := f.srv.URL + "/anchors/" + key
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	h := checkpointHash(body)
	s3.Sign(req, h, creds, "eu-west-1", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func checkpointHash(b []byte) string {
	if len(b) == 0 {
		return s3.EmptyHash
	}
	// The fake checks the payload hash, so compute it the way Sign expects.
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func TestPublishStoresTheExactLineLocked(t *testing.T) {
	f := newFixture(t)
	c, s := f.checkpointOf(t, 3, "a")
	before := time.Now()
	if err := f.anchor.Publish(context.Background(), c, s); err != nil {
		t.Fatal(err)
	}
	name := s3.ObjectName("warden/prod", chainID, 3)
	if name != "warden/prod/warden-test-chain/00000000000000000003.json" {
		t.Fatalf("object name %q", name)
	}
	line, _ := s.Line()
	obj, err := f.client.Get(context.Background(), name, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obj.Body, line) {
		t.Fatalf("stored %q, want the checkpoint line %q", obj.Body, line)
	}
	mode, until, err := f.client.Retention(context.Background(), name, obj.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if mode != s3.LockCompliance {
		t.Fatalf("lock mode %q", mode)
	}
	if want := before.Add(24 * time.Hour); until.Before(want.Add(-2*time.Second)) || until.After(want.Add(time.Minute)) {
		t.Fatalf("retain-until %v, want about %v", until, want)
	}
	if obj.LastModified.IsZero() || obj.LockMode != s3.LockCompliance {
		t.Fatalf("GET lost metadata: %+v", obj)
	}
}

func TestRepublishingIsSafe(t *testing.T) {
	f := newFixture(t)
	c, s := f.checkpointOf(t, 3, "a")
	for range 3 {
		if err := f.anchor.Publish(context.Background(), c, s); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.store.Puts(); n != 1 {
		t.Fatalf("%d versions stored for one checkpoint published three times", n)
	}
}

// A second, different checkpoint of the same size is a fork: it must not be
// written, and the caller must hear about it.
func TestADifferentCheckpointOfTheSameSizeIsRefused(t *testing.T) {
	f := newFixture(t)
	c, s := f.checkpointOf(t, 3, "a")
	if err := f.anchor.Publish(context.Background(), c, s); err != nil {
		t.Fatal(err)
	}
	c2, s2 := f.checkpointOf(t, 3, "forked")
	err := f.anchor.Publish(context.Background(), c2, s2)
	if !errors.Is(err, s3.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if n := len(f.store.Versions(s3.ObjectName("warden/prod", chainID, 3))); n != 1 {
		t.Fatalf("%d versions after a refused fork", n)
	}
}

func TestPublishRefusesAnotherChain(t *testing.T) {
	f := newFixture(t)
	c, s := f.checkpointOf(t, 2, "a")
	f.anchor.ChainID = "some-other-chain"
	if err := f.anchor.Publish(context.Background(), c, s); err == nil {
		t.Fatal("published another chain's checkpoint")
	}
}

func TestAStoreThatIsDownFails(t *testing.T) {
	f := newFixture(t)
	f.store.SetDown(true)
	c, s := f.checkpointOf(t, 2, "a")
	if err := f.anchor.Publish(context.Background(), c, s); err == nil {
		t.Fatal("publish to a store that is down succeeded")
	}
	f.store.SetDown(false)
	if err := f.anchor.Publish(context.Background(), c, s); err != nil {
		t.Fatalf("publish after the store came back: %v", err)
	}
}

func TestWrongCredentialsAreRefused(t *testing.T) {
	f := newFixture(t)
	f.client.Creds.SecretAccessKey = "not-the-secret"
	c, s := f.checkpointOf(t, 2, "a")
	var e *s3.Error
	if err := f.anchor.Publish(context.Background(), c, s); !errors.As(err, &e) || e.Code != "SignatureDoesNotMatch" {
		t.Fatalf("got %v, want SignatureDoesNotMatch", err)
	}
}

// What an operator with the store's credentials can and cannot do to an
// anchored checkpoint. This is the property ADR-0017's verifier rules rest on.
func TestWhatTheOperatorCanDoToALockedCheckpoint(t *testing.T) {
	f := newFixture(t)
	c, s := f.checkpointOf(t, 3, "a")
	if err := f.anchor.Publish(context.Background(), c, s); err != nil {
		t.Fatal(err)
	}
	name := s3.ObjectName("warden/prod", chainID, 3)
	original := f.store.Versions(name)[0]

	// It cannot delete the locked version.
	if code := f.operator(t, "DELETE", name, "versionId="+original.ID, nil); code != http.StatusForbidden {
		t.Fatalf("deleting a locked version: HTTP %d", code)
	}
	// It can write a new version over the name, which hides the original from a
	// plain read...
	if code := f.operator(t, "PUT", name, "", []byte("rewritten")); code != http.StatusOK {
		t.Fatalf("overwrite: HTTP %d", code)
	}
	obj, err := f.client.Get(context.Background(), name, "")
	if err != nil || string(obj.Body) != "rewritten" {
		t.Fatalf("plain read after overwrite: %v %q", err, obj.Body)
	}
	// ...and add a delete marker, which hides it entirely...
	if code := f.operator(t, "DELETE", name, "", nil); code != http.StatusNoContent {
		t.Fatalf("delete marker: HTTP %d", code)
	}
	if _, err := f.client.Get(context.Background(), name, ""); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("plain read after delete marker: %v", err)
	}
	// ...but the locked original is still there, and a version listing shows
	// everything that happened.
	got, err := f.client.Get(context.Background(), name, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := s.Line()
	if !bytes.Equal(got.Body, line) {
		t.Fatal("the locked original changed")
	}
	vs, err := f.client.ListVersions(context.Background(), s3.ChainPrefix("warden/prod", chainID))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 || !vs[0].DeleteMarker || !vs[0].IsLatest || vs[2].VersionID != original.ID {
		t.Fatalf("version listing: %+v", vs)
	}
	// The overwrite has no lock, which a verifier must see.
	if _, _, err := f.client.Retention(context.Background(), name, vs[1].VersionID); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("retention of the unlocked overwrite: %v", err)
	}
}

func TestListVersionsFollowsPages(t *testing.T) {
	f := newFixture(t)
	f.store.SetPageSize(2)
	for n := 1; n <= 7; n++ {
		c, s := f.checkpointOf(t, n, "a")
		if err := f.anchor.Publish(context.Background(), c, s); err != nil {
			t.Fatal(err)
		}
	}
	// Something under another chain's prefix must not appear.
	other := &s3.Anchor{Client: f.client, Prefix: "warden/prod", ChainID: chainID + "-2", Retention: time.Hour}
	b := checkpoint.NewBuilder(chainID + "-2")
	b.Add([]byte(`{}`))
	oc, _ := b.Checkpoint(time.Now().UTC().Format(receipt.TimeFormat))
	osg, _ := checkpoint.Sign(f.key, "warden-e1", oc)
	if err := other.Publish(context.Background(), oc, osg); err != nil {
		t.Fatal(err)
	}
	vs, err := f.client.ListVersions(context.Background(), s3.ChainPrefix("warden/prod", chainID))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 7 {
		t.Fatalf("%d versions listed, want 7", len(vs))
	}
	for i, v := range vs {
		if want := s3.ObjectName("warden/prod", chainID, int64(i+1)); v.Key != want {
			t.Fatalf("entry %d is %q, want %q", i, v.Key, want)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		prefix, chain string
		ok            bool
	}{
		{"", "warden-20261027T120000Z", true},
		{"warden/prod", "chain.1_a", true},
		{"", "has space", false},
		{"", "a/b", false},
		{"", "..", false},
		{"/lead", "c", false},
		{"trail/", "c", false},
		{"a/../b", "c", false},
		{"a//b", "c", false},
	} {
		if err := s3.ValidName(tc.prefix, tc.chain); (err == nil) != tc.ok {
			t.Errorf("ValidName(%q, %q) = %v, want ok=%v", tc.prefix, tc.chain, err, tc.ok)
		}
	}
}
