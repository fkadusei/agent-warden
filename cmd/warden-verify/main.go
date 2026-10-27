// Command warden-verify checks a Warden receipt log, using only trusted public
// keys and, optionally, anchored checkpoints: from a file, from a write-once
// object store it reads itself (ADR-0017), or both. With a file alone it runs
// offline.
//
// Exit status: 0 if the log verified, 1 if verification failed, 2 for usage or
// file errors.
package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/fkadusei/agent-warden/internal/anchor/s3"
	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/keys"
	"github.com/fkadusei/agent-warden/internal/revocation"
	"github.com/fkadusei/agent-warden/internal/tsa"
)

const (
	exitVerified = 0
	exitFailed   = 1
	exitUsage    = 2
)

const noStoreCheckpointWarning = "WARNING: the anchor store holds no checkpoints for this chain. The log was checked " +
	"only against the anchor file, which whoever runs Warden can rewrite together with the log."

const noCheckpointWarning = "WARNING: no anchored checkpoints were checked. Without them, deleting the newest " +
	"receipts or rewriting the whole log with the signing key cannot be detected."

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// result is the --json output.
type result struct {
	Verified bool   `json:"verified"`
	ChainID  string `json:"chain_id"`
	// Set when verified.
	Receipts      int     `json:"receipts,omitempty"`
	LastSeq       *int64  `json:"last_seq,omitempty"`
	Head          string  `json:"head,omitempty"`
	Checkpoints   int     `json:"checkpoints"`
	Timestamps    int     `json:"timestamps,omitempty"`
	StampedAt     string  `json:"earliest_timestamp,omitempty"`
	Checkpointed  int64   `json:"checkpointed"`
	Unanchored    int64   `json:"unanchored"`
	OpenDecisions []int64 `json:"open_decisions,omitempty"`
	Warning       string  `json:"warning,omitempty"`
	// Rotations are the key handovers the log records (ADR-0016).
	Rotations []chain.KeyHandover `json:"rotations,omitempty"`
	// Revocations are the ones enforced against this log.
	Revocations []revokedView `json:"revocations,omitempty"`
	// Store is what the write-once object store holds for this chain (ADR-0017).
	Store *storeView `json:"store,omitempty"`
	// Set when verification failed.
	Stage   string         `json:"stage,omitempty"`
	Failure *chain.Failure `json:"failure,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// revokedView is a revocation that was matched to its anchored checkpoint.
type revokedView struct {
	Kid    string `json:"kid"`
	From   int64  `json:"effective_size"`
	Reason string `json:"reason,omitempty"`
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("warden-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("log", "", "receipt log: one signed receipt per line (required)")
	chainID := fs.String("chain", "", "the chain ID the log must belong to (required)")
	keysPath := fs.String("keys", "", "trusted public keys as a JWK Set (required)")
	anchorPath := fs.String("anchor", "", "anchored checkpoints, one per line (strongly recommended)")
	tokensPath := fs.String("tsa-tokens", "", "RFC 3161 timestamps over the anchored checkpoints")
	tsaRootsPath := fs.String("tsa-roots", "", "certificates trusted to act as timestamp authorities (PEM)")
	rootPath := fs.String("root", "", "Warden root certificate, so key rotations in the log can be followed (PEM)")
	revocationsPath := fs.String("revocations", "", "published revocations, one per line (needs --root and an anchor)")
	sf := addStoreFlags(fs)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	showVersion := fs.Bool("version", false, "print the commit and Go toolchain this binary was built from, and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: warden-verify --log FILE --chain ID --keys FILE [--anchor FILE]"+
			" [--store-endpoint URL --store-region R --store-bucket B [--store-prefix P]]"+
			" [--root FILE [--revocations FILE]] [--tsa-tokens FILE --tsa-roots FILE] [--json]")
		fmt.Fprintln(stderr, "\nExit status: 0 verified, 1 verification failed, 2 usage or file error.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, version())
		return exitVerified
	}
	if fs.NArg() > 0 || *logPath == "" || *chainID == "" || *keysPath == "" {
		fs.Usage()
		return exitUsage
	}

	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "warden-verify: "+format+"\n", a...)
		return exitUsage
	}

	keyData, err := os.ReadFile(*keysPath)
	if err != nil {
		return usageErr("%v", err)
	}
	trusted, err := keys.Parse(keyData)
	if err != nil {
		return usageErr("%v", err)
	}
	resolve := keys.Resolver(trusted)

	var store *s3.Client
	if sf.set() {
		if store, err = sf.client(); err != nil {
			return usageErr("%v", err)
		}
	}
	haveAnchor := *anchorPath != "" || store != nil

	if *revocationsPath != "" && (*rootPath == "" || !haveAnchor) {
		return usageErr("--revocations needs --root, which signs revocations, and an anchor (--anchor or the store), " +
			"because a revocation is effective from an anchored checkpoint")
	}

	// With the root, the trust file need only hold the chain's first key: every
	// later key is learned from the rotation receipts, each certified by the root
	// (ADR-0016). Without it, a rotation fails closed.
	var rotating *keys.Rotating
	var rootKey *mldsa.PublicKey
	chainKeys := chain.StaticKeys(resolve)
	if *rootPath != "" {
		der, err := keyfile.ReadCertificate(*rootPath)
		if err != nil {
			return usageErr("%v", err)
		}
		rootCert, err := x509.ParseCertificate(der)
		if err != nil {
			return usageErr("%v", err)
		}
		if rootKey, err = revocation.RootKey(rootCert); err != nil {
			return usageErr("%v", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(rootCert)
		rotating = keys.NewRotating(trusted, pool)
		chainKeys = rotating
	}

	res := result{ChainID: *chainID}
	emit := func(code int) int {
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.Encode(res)
		} else {
			printText(stdout, res)
		}
		if res.Warning != "" && !*asJSON {
			fmt.Fprintln(stderr, res.Warning)
		}
		return code
	}

	// The anchor is read before the log, but a rotated chain's later checkpoints
	// are signed by keys that only the log can introduce. So read the log once
	// first to learn them; accepting the same rotation again is a no-op.
	if rotating != nil && haveAnchor {
		lf, err := os.Open(*logPath)
		if err != nil {
			return usageErr("%v", err)
		}
		_, err = chain.VerifyAll(lf, *chainID, chain.Options{Keys: rotating})
		lf.Close()
		var failure *chain.Failure
		switch {
		case errors.As(err, &failure):
			res.Stage, res.Failure = "log", failure
			return emit(exitFailed)
		case err != nil:
			return usageErr("%v", err)
		}
		resolve = rotating.Resolve
	}

	// anchored is every anchored line, labelled, for checking timestamps;
	// fileLines are the file anchor's lines by checkpoint size.
	type labelled struct {
		label string
		line  []byte
	}
	var anchored []labelled
	fileLines := map[int64][]byte{}
	var cps []*checkpoint.Checkpoint
	if *anchorPath != "" {
		data, err := os.ReadFile(*anchorPath)
		if err != nil {
			return usageErr("%v", err)
		}
		cps, err = checkpoint.ReadVerified(bytes.NewReader(data), *chainID, resolve)
		if err != nil {
			res.Stage, res.Error = "anchor", err.Error()
			return emit(exitFailed)
		}
		var lines [][]byte
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			if len(bytes.TrimSpace(line)) > 0 {
				lines = append(lines, line)
			}
		}
		for i, line := range lines {
			anchored = append(anchored, labelled{fmt.Sprintf("anchor line %d", i+1), line})
			if i < len(cps) {
				fileLines[cps[i].Size] = line
			}
		}
	}
	if store != nil {
		storeCps, view, err := readStore(sf, store, *chainID, resolve, fileLines)
		if errors.Is(err, errStoreUnreadable) {
			return usageErr("%v", err)
		}
		if err != nil {
			res.Stage, res.Error = "anchor store", err.Error()
			return emit(exitFailed)
		}
		res.Store = view
		for _, a := range view.Checkpoints {
			if _, inFile := fileLines[a.Size]; !inFile {
				anchored = append(anchored, labelled{a.Object, a.Line})
			}
		}
		cps = merge(cps, storeCps)
	}
	res.Checkpoints = len(cps)

	var revoked []chain.Revoked
	if *revocationsPath != "" {
		f, err := os.Open(*revocationsPath)
		if err != nil {
			return usageErr("%v", err)
		}
		revs, err := revocation.ReadVerified(f, *chainID, rootKey)
		f.Close()
		if err != nil {
			res.Stage, res.Error = "revocation", err.Error()
			return emit(exitFailed)
		}
		// Each revocation has to name a checkpoint this anchor actually holds,
		// before it is allowed to condemn anything.
		effective, err := revocation.Match(revs, cps)
		if err != nil {
			res.Stage, res.Error = "revocation", err.Error()
			return emit(exitFailed)
		}
		for _, e := range effective {
			revoked = append(revoked, chain.Revoked{Kid: e.Kid, EffectiveSize: e.Size})
			res.Revocations = append(res.Revocations, revokedView{Kid: e.Kid, From: e.Size, Reason: e.Reason})
		}
	}

	if *tokensPath != "" || *tsaRootsPath != "" {
		if *tokensPath == "" || *tsaRootsPath == "" || !haveAnchor {
			return usageErr("--tsa-tokens and --tsa-roots go together, and need an anchor (--anchor or the store)")
		}
		roots, err := tsa.LoadRoots(*tsaRootsPath)
		if err != nil {
			return usageErr("%v", err)
		}
		tokenData, err := os.ReadFile(*tokensPath)
		if err != nil {
			return usageErr("%v", err)
		}
		tokens, err := tsa.ReadTokens(bytes.NewReader(tokenData))
		if err != nil {
			return usageErr("%v", err)
		}
		var earliest time.Time
		for _, a := range anchored {
			// A token must cover the anchored bytes exactly; anything else fails.
			for _, token := range tokens[tsa.Digest(a.line)] {
				when, err := tsa.Verify(token, a.line, roots)
				if err != nil {
					res.Stage, res.Error = "timestamp", fmt.Sprintf("%s: %v", a.label, err)
					return emit(exitFailed)
				}
				res.Timestamps++
				if earliest.IsZero() || when.Before(earliest) {
					earliest = when
				}
			}
		}
		if !earliest.IsZero() {
			res.StampedAt = earliest.UTC().Format(time.RFC3339)
		}
	}

	lf, err := os.Open(*logPath)
	if err != nil {
		return usageErr("%v", err)
	}
	defer lf.Close()

	rep, err := chain.VerifyAll(lf, *chainID, chain.Options{Keys: chainKeys, Checkpoints: cps, Revocations: revoked})
	var failure *chain.Failure
	switch {
	case errors.As(err, &failure):
		res.Stage, res.Failure = "log", failure
		return emit(exitFailed)
	case err != nil:
		return usageErr("%v", err)
	}

	res.Verified = true
	res.Rotations = rep.Rotations
	res.Receipts = rep.Receipts
	res.LastSeq = &rep.LastSeq
	res.Head = rep.Head
	res.Checkpointed = rep.Checkpointed
	res.Unanchored = rep.Unanchored
	res.OpenDecisions = rep.OpenDecisions
	if res.Store != nil {
		res.Store.Unanchored = int64(rep.Receipts)
		if n := len(res.Store.Checkpoints); n > 0 {
			res.Store.Unanchored -= res.Store.Checkpoints[n-1].Size
		}
	}
	switch {
	case len(cps) == 0:
		res.Warning = noCheckpointWarning
	case res.Store != nil && len(res.Store.Checkpoints) == 0:
		res.Warning = noStoreCheckpointWarning
	}
	return emit(exitVerified)
}

// version names the commit and toolchain the binary was built from, read from
// the build information Go records, so a downloaded binary can be rebuilt and
// compared byte for byte. It adds nothing to the build that could differ.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "warden-verify (no build information)"
	}
	rev, modified := "unknown commit", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				modified = ", with uncommitted changes"
			}
		}
	}
	return fmt.Sprintf("warden-verify %s%s, built with %s", rev, modified, info.GoVersion)
}

func printText(w io.Writer, r result) {
	row := func(label, value string) { fmt.Fprintf(w, "  %-16s%s\n", label+":", value) }
	if !r.Verified {
		fmt.Fprintln(w, "FAILED")
		row("chain", r.ChainID)
		if r.Failure != nil {
			row("line", strconv.Itoa(r.Failure.Line))
			row("seq", strconv.FormatInt(r.Failure.Seq, 10))
			row("reason", string(r.Failure.Reason))
			row("detail", r.Failure.Detail)
		} else {
			row(r.Stage, r.Error)
		}
		return
	}
	fmt.Fprintln(w, "VERIFIED")
	row("chain", r.ChainID)
	row("receipts", fmt.Sprintf("%d (seq 0-%d)", r.Receipts, *r.LastSeq))
	row("head", r.Head)
	if r.Checkpoints > 0 {
		row("checkpointed", fmt.Sprintf("%d receipts (%d anchored checkpoints)", r.Checkpointed, r.Checkpoints))
		row("unanchored", fmt.Sprintf("%d receipts after the last checkpoint", r.Unanchored))
		if r.Timestamps > 0 {
			row("timestamps", fmt.Sprintf("%d verified, earliest %s", r.Timestamps, r.StampedAt))
		}
	} else {
		row("checkpointed", "none")
	}
	if st := r.Store; st != nil {
		if n := len(st.Checkpoints); n > 0 {
			last := st.Checkpoints[n-1]
			row("anchor store", fmt.Sprintf("%d checkpoints in %s", n, st.Location))
			row("store newest", fmt.Sprintf("covers %d receipts, stored %s, locked until %s", last.Size,
				last.StoredAt.UTC().Format(time.RFC3339), last.RetainUntil.UTC().Format(time.RFC3339)))
			row("not in store", fmt.Sprintf("%d receipts after the store's newest checkpoint", st.Unanchored))
		} else {
			row("anchor store", "no checkpoints for this chain in "+st.Location)
		}
		if st.Notices != nil {
			for _, name := range st.Notices.DeleteMarkers {
				row("store notice", "delete marker on "+name+" (the locked checkpoint still counts)")
			}
			for _, name := range st.Notices.Duplicates {
				row("store notice", "identical copies of "+name)
			}
		}
	}
	for _, h := range r.Rotations {
		detail := fmt.Sprintf("%s to %s at seq %d", h.From, h.To, h.Seq)
		if h.Reason != "" {
			detail += " (" + h.Reason + ")"
		}
		row("key rotation", detail)
	}
	for _, rev := range r.Revocations {
		detail := fmt.Sprintf("%s, from seq %d onward", rev.Kid, rev.From)
		if rev.Reason != "" {
			detail += " (" + rev.Reason + ")"
		}
		row("revoked", detail)
	}
	if len(r.OpenDecisions) > 0 {
		seqs := make([]string, len(r.OpenDecisions))
		for i, s := range r.OpenDecisions {
			seqs[i] = strconv.FormatInt(s, 10)
		}
		row("open decisions", "seq "+strings.Join(seqs, ", ")+" (allowed, no result receipt)")
	}
}
