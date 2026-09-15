// Command example-tools serves synthetic MCP tool servers for trying Warden
// locally. Each server lives at its own path: /crm, /payments, /web, /mail,
// /tickets, /hr. All data is made up.
//
// The payments server requires the bearer token in EXAMPLE_PAYMENTS_TOKEN; give
// Warden the same value as WARDEN_SECRET_PAYMENTS so it can inject it.
//
// With --scenario, read-only tools serve that scenario's planted content (see
// scenarios/). --list prints the scenarios.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	agentwarden "github.com/fkadusei/agent-warden"
	"github.com/fkadusei/agent-warden/internal/exampletools"
	"github.com/fkadusei/agent-warden/internal/scenario"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to listen on (keep it on loopback)")
	scenarioID := flag.String("scenario", "", "serve the planted content of this scenario")
	list := flag.Bool("list", false, "list the scenarios and exit")
	flag.Parse()

	all, err := agentwarden.Scenarios()
	if err != nil {
		fmt.Fprintln(os.Stderr, "example-tools:", err)
		os.Exit(1)
	}
	if *list {
		for _, s := range all {
			fmt.Printf("%-30s %-9s %-3s %s\n", s.ID, s.Category, s.Threat, s.Title)
		}
		return
	}

	var chosen *scenario.Scenario
	if *scenarioID != "" {
		for _, s := range all {
			if s.ID == *scenarioID {
				chosen = s
			}
		}
		if chosen == nil {
			fmt.Fprintf(os.Stderr, "example-tools: no scenario %q (see --list)\n", *scenarioID)
			os.Exit(2)
		}
	}

	token := os.Getenv("EXAMPLE_PAYMENTS_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "example-tools: set EXAMPLE_PAYMENTS_TOKEN to the token the payments server should accept")
		os.Exit(2)
	}
	fmt.Printf("example tool servers on http://%s/{%s}\n", *listen, strings.Join(exampletools.Servers, ","))
	var content []scenario.Content
	if chosen != nil {
		content = chosen.Content
		fmt.Printf("scenario %s: %s\n  task for the agent: %s\n", chosen.ID, chosen.Title, chosen.Task)
	}
	srv := &http.Server{Addr: *listen, Handler: exampletools.Handler(token, content...), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "example-tools:", err)
		os.Exit(1)
	}
}
