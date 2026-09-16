// Command warden runs Agent Warden and its administrative tasks.
//
//	warden init          create a local PKI, receipt key, and example configuration
//	warden pin           list upstream tools and (with --write) pin them after review
//	warden add-approver  create an approver key and trust it
//	warden issue-task    issue a short-lived task credential for an agent
//	warden serve         run the agent MCP endpoint and the approver API
//	warden call          act as an agent: list or call tools through Warden
//	warden approve       list pending calls and approve or reject one
//	warden export        write the receipt log for warden-verify
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usage = `usage: warden <command> [flags]

commands:
  init          create a local PKI, receipt key, and example configuration
  pin           list upstream tools; --write pins them after you review the list
  add-approver  create an approver key and add it to the trusted approvers
  issue-task    issue a short-lived task credential for an agent
  serve         run the agent MCP endpoint and the approver API
  call          act as an agent: --list tools or --tool NAME --args JSON
  approve       list pending calls, or --decision N to approve (or --reject) one
  console       a local page: what was decided, what waits for a person, and the evidence
  export        write the receipt log for warden-verify

Run "warden <command> -h" for a command's flags.
`

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	commands := map[string]func(context.Context, []string, io.Reader, io.Writer) error{
		"init":         cmdInit,
		"pin":          cmdPin,
		"add-approver": cmdAddApprover,
		"issue-task":   cmdIssueTask,
		"serve":        cmdServe,
		"call":         cmdCall,
		"approve":      cmdApprove,
		"console":      cmdConsole,
		"export":       cmdExport,
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "warden: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err := cmd(ctx, args[1:], stdin, stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintf(stderr, "warden %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// flags returns a flag set whose usage and errors go to stdout.
func flags(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("warden "+name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

// writeNew creates path with data, refusing to overwrite an existing file.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// replace atomically replaces path with data.
func replace(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
