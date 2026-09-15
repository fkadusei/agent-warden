// Command example-tools serves synthetic MCP tool servers for trying Warden
// locally. Each server lives at its own path: /crm, /payments, /web, /mail, /hr.
// All data is made up.
//
// The payments server requires the bearer token in EXAMPLE_PAYMENTS_TOKEN; give
// Warden the same value as WARDEN_SECRET_PAYMENTS so it can inject it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fkadusei/agent-warden/internal/exampletools"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to listen on (keep it on loopback)")
	flag.Parse()
	token := os.Getenv("EXAMPLE_PAYMENTS_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "example-tools: set EXAMPLE_PAYMENTS_TOKEN to the token the payments server should accept")
		os.Exit(2)
	}
	fmt.Printf("example tool servers on http://%s/{crm,payments,web,mail,hr}\n", *listen)
	srv := &http.Server{Addr: *listen, Handler: exampletools.Handler(token), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "example-tools:", err)
		os.Exit(1)
	}
}
