package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/config"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// storeFlags name the write-once object store to read checkpoints from
// (ADR-0017). The verifier reads it itself, with read-only credentials of its
// own, rather than trusting a copy handed over by the operator.
type storeFlags struct {
	endpoint, region, bucket, prefix *string
	pathStyle                        *bool
	skew, timeout                    *time.Duration
}

func addStoreFlags(fs *flag.FlagSet) storeFlags {
	return storeFlags{
		endpoint: fs.String("store-endpoint", "", "anchor store base URL, such as https://s3.eu-west-1.amazonaws.com; "+
			"read-only credentials from "+config.EnvAnchorAccessKeyID+" and "+config.EnvAnchorSecretAccessKey),
		region:    fs.String("store-region", "", "anchor store region"),
		bucket:    fs.String("store-bucket", "", "anchor store bucket"),
		prefix:    fs.String("store-prefix", "", "prefix before <chain_id>/ in the store's object names"),
		pathStyle: fs.Bool("store-path-style", false, "put the bucket in the URL path (most local stores)"),
		skew: fs.Duration("store-skew", 5*time.Minute,
			"how much later than the store's own time a checkpoint may say it was made"),
		timeout: fs.Duration("store-timeout", 30*time.Second, "timeout for each request to the store"),
	}
}

func (f storeFlags) set() bool {
	return *f.endpoint != "" || *f.region != "" || *f.bucket != "" || *f.prefix != ""
}

// location is how the report names the store.
func (f storeFlags) location(chainID string) string {
	return fmt.Sprintf("%s, bucket %s, %s", *f.endpoint, *f.bucket, s3.ChainPrefix(*f.prefix, chainID))
}

// client checks the flags and builds a client. Errors are usage errors.
func (f storeFlags) client() (*s3.Client, error) {
	if *f.endpoint == "" || *f.region == "" || *f.bucket == "" {
		return nil, errors.New("--store-endpoint, --store-region and --store-bucket go together")
	}
	if err := config.CheckStoreEndpoint(*f.endpoint); err != nil {
		return nil, fmt.Errorf("--store-endpoint: %w", err)
	}
	if *f.skew < 0 || *f.timeout < time.Second {
		return nil, errors.New("--store-skew must not be negative and --store-timeout must be at least 1s")
	}
	creds := s3.Credentials{AccessKeyID: os.Getenv(config.EnvAnchorAccessKeyID),
		SecretAccessKey: os.Getenv(config.EnvAnchorSecretAccessKey)}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("the anchor store needs %s and %s", config.EnvAnchorAccessKeyID, config.EnvAnchorSecretAccessKey)
	}
	return &s3.Client{Endpoint: *f.endpoint, Region: *f.region, Bucket: *f.bucket, PathStyle: *f.pathStyle,
		Creds: creds, HTTP: &http.Client{Timeout: *f.timeout}}, nil
}

// storeView is what the report says about the store.
type storeView struct {
	Location    string        `json:"location"`
	Checkpoints []s3.Anchored `json:"checkpoints"`
	Notices     *s3.Notices   `json:"notices,omitempty"`
	// Unanchored is how many receipts come after the store's newest checkpoint:
	// the part of the log the store says nothing about.
	Unanchored int64 `json:"unanchored"`
}

// errStoreUnreadable marks a store that could not be read at all, as opposed
// to one whose contents fail ADR-0017's rules.
var errStoreUnreadable = errors.New("anchor store unreadable")

// readStore reads and checks the store's checkpoints for chainID:
//
//   - ADR-0017's store rules, applied by s3.Read;
//   - each line's signature, chain and order, as for the file anchor;
//   - each object's name matches the size of the checkpoint it holds;
//   - no checkpoint claims a time later than the store received it, beyond skew;
//   - every size the file anchor also holds has the same bytes in both.
func readStore(f storeFlags, client *s3.Client, chainID string, resolve func(string) (*composite.PublicKey, error),
	fileLines map[int64][]byte) ([]*checkpoint.Checkpoint, *storeView, error) {
	ctx := context.Background()
	stored, notices, err := s3.Read(ctx, client, *f.prefix, chainID, time.Now())
	switch {
	case errors.Is(err, s3.ErrNotLocked), errors.Is(err, s3.ErrRewritten), errors.Is(err, s3.ErrStray):
		return nil, nil, err
	case err != nil:
		return nil, nil, fmt.Errorf("%w: %v", errStoreUnreadable, err)
	}
	var joined bytes.Buffer
	for _, a := range stored {
		joined.Write(a.Line)
		joined.WriteByte('\n')
	}
	cps, err := checkpoint.ReadVerified(&joined, chainID, resolve)
	if err != nil {
		return nil, nil, err
	}
	for i, c := range cps {
		a := stored[i]
		if c.Size != a.Size {
			return nil, nil, fmt.Errorf("%s holds a checkpoint of size %d", a.Object, c.Size)
		}
		made, err := time.Parse(receipt.TimeFormat, c.TS)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: checkpoint time %q", a.Object, c.TS)
		}
		if made.After(a.StoredAt.Add(*f.skew)) {
			return nil, nil, fmt.Errorf("%s says it was made at %s, but the store received it at %s",
				a.Object, c.TS, a.StoredAt.UTC().Format(time.RFC3339))
		}
		if line, ok := fileLines[c.Size]; ok && !bytes.Equal(line, a.Line) {
			return nil, nil, fmt.Errorf("the anchor file and %s hold different checkpoints of size %d", a.Object, c.Size)
		}
	}
	return cps, &storeView{Location: f.location(chainID), Checkpoints: stored, Notices: notices}, nil
}

// merge combines checkpoints from both anchors, one per size, in size order.
// Where both hold a size, readStore has already checked they are identical.
func merge(a, b []*checkpoint.Checkpoint) []*checkpoint.Checkpoint {
	bySize := map[int64]*checkpoint.Checkpoint{}
	for _, c := range append(append([]*checkpoint.Checkpoint{}, a...), b...) {
		bySize[c.Size] = c
	}
	out := make([]*checkpoint.Checkpoint, 0, len(bySize))
	for _, c := range bySize {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Size < out[j].Size })
	return out
}
