// Command warden-gate runs the Phase 2 gate: attack scenarios against a complete
// Warden deployment (agent MCP client over mutual TLS, gateway, approver API, and
// real MCP tool servers that count executions). It exits 1 if any defense fails.
package main

import (
	"context"
	"fmt"
	"os"
)

import "github.com/fkadusei/agent-warden/internal/gate"

func main() {
	fmt.Println("Warden Phase 2 gate: each scenario runs in a fresh deployment.")
	fmt.Println()
	results, err := gate.Run(context.Background(), os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden-gate:", err)
		os.Exit(2)
	}
	for _, r := range results {
		if r.Err != nil {
			os.Exit(1)
		}
	}
}
