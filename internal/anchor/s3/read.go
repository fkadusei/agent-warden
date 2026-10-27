package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrNotLocked is returned when an anchored version is not locked in
	// compliance mode, or its retention has ended: it is not write-once.
	ErrNotLocked = errors.New("s3: anchored version is not locked in compliance mode")
	// ErrRewritten is returned when one name holds versions with different bytes.
	ErrRewritten = errors.New("s3: a checkpoint name holds different versions")
	// ErrStray is returned for an object under the chain's prefix that is not
	// named like a checkpoint.
	ErrStray = errors.New("s3: object under the chain's prefix is not a checkpoint")
)

// Anchored is one checkpoint as the store holds it: the bytes of the oldest
// version under its name, and what the store says about that version.
type Anchored struct {
	Object      string    `json:"object"`
	VersionID   string    `json:"version_id"`
	Size        int64     `json:"size"`
	Line        []byte    `json:"-"`
	StoredAt    time.Time `json:"stored_at"`
	RetainUntil time.Time `json:"retain_until"`
}

// Notices are things the store shows that do not make a checkpoint untrue but
// that an auditor should see.
type Notices struct {
	// DeleteMarkers name objects someone tried to hide. The locked versions
	// behind them still count.
	DeleteMarkers []string `json:"delete_markers,omitempty"`
	// Duplicates name objects holding more than one version with the same bytes.
	Duplicates []string `json:"duplicates,omitempty"`
}

// Read lists every version and delete marker under the chain's prefix and
// returns its checkpoints in size order, applying ADR-0017's rules:
//
//  1. every object version must be locked in compliance mode, with retention
//     that has not ended, read from the version's own retention;
//  2. every version under a name must hold the same bytes;
//  3. the checkpoint is the oldest version's bytes.
//
// Read does not verify signatures; the caller does, with the lines it returns.
func Read(ctx context.Context, c *Client, prefix, chainID string, now time.Time) ([]Anchored, *Notices, error) {
	if err := ValidName(prefix, chainID); err != nil {
		return nil, nil, err
	}
	base := ChainPrefix(prefix, chainID)
	vs, err := c.ListVersions(ctx, base)
	if err != nil {
		return nil, nil, err
	}
	// Group by name, keeping the store's order (newest first within a name).
	byName := map[string][]Version{}
	var names []string
	for _, v := range vs {
		if !strings.HasPrefix(v.Key, base) {
			continue // a store that ignores the prefix; not this chain's
		}
		if _, ok := byName[v.Key]; !ok {
			names = append(names, v.Key)
		}
		byName[v.Key] = append(byName[v.Key], v)
	}
	sort.Strings(names)

	notices := &Notices{}
	var out []Anchored
	for _, name := range names {
		var objects []Version
		for _, v := range byName[name] {
			if v.DeleteMarker {
				if dm := notices.DeleteMarkers; len(dm) == 0 || dm[len(dm)-1] != name {
					notices.DeleteMarkers = append(notices.DeleteMarkers, name)
				}
				continue
			}
			objects = append(objects, v)
		}
		if len(objects) == 0 {
			continue // only delete markers: nothing is anchored under this name
		}
		size, ok := sizeOf(base, name)
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s", ErrStray, name)
		}
		// The oldest version is the anchor. Within one stored second, the store's
		// own order (newest first) breaks the tie.
		oldest := len(objects) - 1
		for i := len(objects) - 2; i >= 0; i-- {
			if objects[i].LastModified.Before(objects[oldest].LastModified) {
				oldest = i
			}
		}
		var first *Anchored
		bodies := make([][]byte, len(objects))
		for i, v := range objects {
			mode, until, err := c.Retention(ctx, name, v.VersionID)
			if errors.Is(err, ErrNotFound) {
				return nil, nil, fmt.Errorf("%w: %s version %s has no retention", ErrNotLocked, name, v.VersionID)
			}
			if err != nil {
				return nil, nil, err
			}
			if mode != LockCompliance || !until.After(now) {
				return nil, nil, fmt.Errorf("%w: %s version %s is %q until %s", ErrNotLocked, name, v.VersionID,
					mode, until.UTC().Format(time.RFC3339))
			}
			obj, err := c.Get(ctx, name, v.VersionID)
			if err != nil {
				return nil, nil, err
			}
			bodies[i] = obj.Body
			if i == oldest {
				first = &Anchored{Object: name, VersionID: v.VersionID, Size: size, Line: obj.Body,
					StoredAt: v.LastModified, RetainUntil: until}
			}
		}
		for i, b := range bodies {
			if i != oldest && !bytes.Equal(b, bodies[oldest]) {
				return nil, nil, fmt.Errorf("%w: %s version %s differs from the original %s", ErrRewritten, name,
					objects[i].VersionID, objects[oldest].VersionID)
			}
		}
		if len(objects) > 1 {
			notices.Duplicates = append(notices.Duplicates, name)
		}
		out = append(out, *first)
	}
	return out, notices, nil
}

// sizeOf parses "<base><20 digits>.json".
func sizeOf(base, name string) (int64, bool) {
	digits, ok := strings.CutSuffix(strings.TrimPrefix(name, base), ".json")
	if !ok || len(digits) != 20 || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}
