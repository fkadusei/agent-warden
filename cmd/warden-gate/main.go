// Command warden-gate runs Warden's attack gates against complete deployments
// (agent MCP client over mutual TLS, gateway, approver API, and real MCP tool
// servers that count every call):
//
//   - Phase 2: authorization, approval, tool-poisoning, fail-closed, identity, and
//     evidence attacks.
//   - Phase 3: the scenario corpus (injection, exfiltration, confused deputy, and
//     benign work), played by a scripted agent that makes every attack call.
//
// It exits 1 if any defense fails.
package main

import (
	"context"
	"fmt"
	"os"

	agentwarden "github.com/fkadusei/agent-warden"
	"github.com/fkadusei/agent-warden/internal/gate"
)

func main() {
	ctx := context.Background()
	failed := false

	fmt.Println("Phase 2 gate: each attack runs in a fresh deployment.")
	fmt.Println()
	results, err := gate.Run(ctx, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden-gate:", err)
		os.Exit(2)
	}
	for _, r := range results {
		failed = failed || r.Err != nil
	}

	scenarios, err := agentwarden.Scenarios()
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden-gate:", err)
		os.Exit(2)
	}
	fmt.Println()
	fmt.Println("Phase 3 gate: scenarios/ against the example deployment, played by an agent that obeys every planted instruction.")
	fmt.Println()
	for _, r := range gate.RunCorpus(ctx, os.Stdout, scenarios, gate.CorpusOptions{}) {
		failed = failed || r.Err != nil
	}
	if failed {
		os.Exit(1)
	}
}
