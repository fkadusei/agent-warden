// Command warden-verify checks a Warden receipt log offline, using only trusted
// public keys and, optionally, anchored checkpoints.
//
// Exit status: 0 if the log verified, 1 if verification failed, 2 for usage or
// file errors.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/fkadusei/agent-warden/internal/chain"
	"github.com/fkadusei/agent-warden/internal/checkpoint"
	"github.com/fkadusei/agent-warden/internal/keys"
)

const (
	exitVerified = 0
	exitFailed   = 1
	exitUsage    = 2
)

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
	Checkpointed  int64   `json:"checkpointed"`
	Unanchored    int64   `json:"unanchored"`
	OpenDecisions []int64 `json:"open_decisions,omitempty"`
	Warning       string  `json:"warning,omitempty"`
	// Set when verification failed.
	Stage   string         `json:"stage,omitempty"`
	Failure *chain.Failure `json:"failure,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("warden-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("log", "", "receipt log: one signed receipt per line (required)")
	chainID := fs.String("chain", "", "the chain ID the log must belong to (required)")
	keysPath := fs.String("keys", "", "trusted public keys as a JWK Set (required)")
	anchorPath := fs.String("anchor", "", "anchored checkpoints, one per line (strongly recommended)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: warden-verify --log FILE --chain ID --keys FILE [--anchor FILE] [--json]")
		fmt.Fprintln(stderr, "\nExit status: 0 verified, 1 verification failed, 2 usage or file error.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
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

	var cps []*checkpoint.Checkpoint
	if *anchorPath != "" {
		f, err := os.Open(*anchorPath)
		if err != nil {
			return usageErr("%v", err)
		}
		cps, err = checkpoint.ReadVerified(f, *chainID, resolve)
		f.Close()
		if err != nil {
			res.Stage, res.Error = "anchor", err.Error()
			return emit(exitFailed)
		}
	}
	res.Checkpoints = len(cps)

	lf, err := os.Open(*logPath)
	if err != nil {
		return usageErr("%v", err)
	}
	defer lf.Close()

	rep, err := chain.VerifyWithCheckpoints(lf, *chainID, resolve, cps)
	var failure *chain.Failure
	switch {
	case errors.As(err, &failure):
		res.Stage, res.Failure = "log", failure
		return emit(exitFailed)
	case err != nil:
		return usageErr("%v", err)
	}

	res.Verified = true
	res.Receipts = rep.Receipts
	res.LastSeq = &rep.LastSeq
	res.Head = rep.Head
	res.Checkpointed = rep.Checkpointed
	res.Unanchored = rep.Unanchored
	res.OpenDecisions = rep.OpenDecisions
	if len(cps) == 0 {
		res.Warning = noCheckpointWarning
	}
	return emit(exitVerified)
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
	} else {
		row("checkpointed", "none")
	}
	if len(r.OpenDecisions) > 0 {
		seqs := make([]string, len(r.OpenDecisions))
		for i, s := range r.OpenDecisions {
			seqs[i] = strconv.FormatInt(s, 10)
		}
		row("open decisions", "seq "+strings.Join(seqs, ", ")+" (allowed, no result receipt)")
	}
}
