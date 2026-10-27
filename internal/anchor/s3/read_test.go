package s3_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
)

// lockedHeaders are what an operator would send to write a locked version
// unconditionally.
func lockedHeaders(body []byte, mode string, until time.Time) map[string]string {
	md := md5.Sum(body)
	sum := sha256.Sum256(body)
	return map[string]string{
		"Content-Md5":                         base64.StdEncoding.EncodeToString(md[:]),
		"X-Amz-Checksum-Sha256":               base64.StdEncoding.EncodeToString(sum[:]),
		"X-Amz-Object-Lock-Mode":              mode,
		"X-Amz-Object-Lock-Retain-Until-Date": until.UTC().Format(time.RFC3339),
	}
}

// publishN anchors checkpoints of sizes 1..n and returns their lines.
func (f *fixture) publishN(t *testing.T, n int) [][]byte {
	t.Helper()
	var lines [][]byte
	for size := 1; size <= n; size++ {
		c, s := f.checkpointOf(t, size, "a")
		if err := f.anchor.Publish(context.Background(), c, s); err != nil {
			t.Fatal(err)
		}
		line, _ := s.Line()
		lines = append(lines, line)
	}
	return lines
}

func (f *fixture) read(t *testing.T) ([]s3.Anchored, *s3.Notices, error) {
	t.Helper()
	return s3.Read(context.Background(), f.client, "warden/prod", chainID, time.Now())
}

func TestReadReturnsCheckpointsInOrder(t *testing.T) {
	f := newFixture(t)
	lines := f.publishN(t, 3)
	got, notices, err := f.read(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || len(notices.DeleteMarkers)+len(notices.Duplicates) != 0 {
		t.Fatalf("read %d checkpoints, notices %+v", len(got), notices)
	}
	for i, a := range got {
		if a.Size != int64(i+1) || !bytes.Equal(a.Line, lines[i]) || a.StoredAt.IsZero() ||
			a.RetainUntil.Before(time.Now().Add(23*time.Hour)) {
			t.Fatalf("checkpoint %d: %+v", i, a)
		}
	}
}

func TestReadFailsOnAnUnlockedOverwrite(t *testing.T) {
	f := newFixture(t)
	f.publishN(t, 2)
	name := s3.ObjectName("warden/prod", chainID, 2)
	if code := f.operator(t, "PUT", name, "", []byte("rewritten")); code != http.StatusOK {
		t.Fatalf("overwrite: HTTP %d", code)
	}
	if _, _, err := f.read(t); !errors.Is(err, s3.ErrNotLocked) {
		t.Fatalf("got %v, want ErrNotLocked", err)
	}
}

// Locking the forgery does not help: the original is still there and differs.
func TestReadFailsOnALockedRewrite(t *testing.T) {
	f := newFixture(t)
	f.publishN(t, 2)
	name := s3.ObjectName("warden/prod", chainID, 2)
	_, s := f.checkpointOf(t, 2, "forged")
	forged, _ := s.Line()
	if code := f.operatorWith(t, "PUT", name, "", forged,
		lockedHeaders(forged, s3.LockCompliance, time.Now().Add(48*time.Hour))); code != http.StatusOK {
		t.Fatalf("locked overwrite: HTTP %d", code)
	}
	if _, _, err := f.read(t); !errors.Is(err, s3.ErrRewritten) {
		t.Fatalf("got %v, want ErrRewritten", err)
	}
}

func TestReadReportsDeleteMarkersAndKeepsTheCheckpoint(t *testing.T) {
	f := newFixture(t)
	lines := f.publishN(t, 2)
	name := s3.ObjectName("warden/prod", chainID, 2)
	for range 2 {
		if code := f.operator(t, "DELETE", name, "", nil); code != http.StatusNoContent {
			t.Fatalf("delete marker: HTTP %d", code)
		}
	}
	got, notices, err := f.read(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[1].Line, lines[1]) {
		t.Fatalf("a delete marker hid a locked checkpoint: %+v", got)
	}
	if len(notices.DeleteMarkers) != 1 || notices.DeleteMarkers[0] != name {
		t.Fatalf("notices %+v", notices)
	}
}

func TestReadReportsIdenticalDuplicates(t *testing.T) {
	f := newFixture(t)
	lines := f.publishN(t, 1)
	name := s3.ObjectName("warden/prod", chainID, 1)
	if code := f.operatorWith(t, "PUT", name, "", lines[0],
		lockedHeaders(lines[0], s3.LockCompliance, time.Now().Add(48*time.Hour))); code != http.StatusOK {
		t.Fatalf("duplicate: HTTP %d", code)
	}
	got, notices, err := f.read(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(notices.Duplicates) != 1 {
		t.Fatalf("checkpoints %d, notices %+v", len(got), notices)
	}
	if want := f.store.Versions(name)[0].ID; got[0].VersionID != want {
		t.Fatalf("anchor is version %s, want the oldest, %s", got[0].VersionID, want)
	}
}

func TestReadRefusesGovernanceAndEndedRetention(t *testing.T) {
	f := newFixture(t)
	_, s := f.checkpointOf(t, 1, "a")
	line, _ := s.Line()
	name := s3.ObjectName("warden/prod", chainID, 1)
	if code := f.operatorWith(t, "PUT", name, "", line,
		lockedHeaders(line, "GOVERNANCE", time.Now().Add(48*time.Hour))); code != http.StatusOK {
		t.Fatalf("governance put: HTTP %d", code)
	}
	if _, _, err := f.read(t); !errors.Is(err, s3.ErrNotLocked) {
		t.Fatalf("governance mode: got %v, want ErrNotLocked", err)
	}

	g := newFixture(t)
	g.publishN(t, 1)
	later := time.Now().Add(25 * time.Hour) // past the fixture's 24-hour retention
	if _, _, err := s3.Read(context.Background(), g.client, "warden/prod", chainID, later); !errors.Is(err, s3.ErrNotLocked) {
		t.Fatalf("ended retention: got %v, want ErrNotLocked", err)
	}
}

func TestReadRefusesAStrayObject(t *testing.T) {
	f := newFixture(t)
	f.publishN(t, 1)
	stray := s3.ChainPrefix("warden/prod", chainID) + "notes.txt"
	body := []byte("x")
	if code := f.operatorWith(t, "PUT", stray, "", body,
		lockedHeaders(body, s3.LockCompliance, time.Now().Add(48*time.Hour))); code != http.StatusOK {
		t.Fatalf("stray put: HTTP %d", code)
	}
	if _, _, err := f.read(t); !errors.Is(err, s3.ErrStray) {
		t.Fatalf("got %v, want ErrStray", err)
	}
}
