// Package agentwarden holds files shared by Warden's commands: the scenario corpus.
package agentwarden

import (
	"embed"

	"github.com/fkadusei/agent-warden/internal/scenario"
)

//go:embed scenarios/*.json
var corpus embed.FS

// Scenarios returns the scenario corpus in scenarios/, sorted by ID.
func Scenarios() ([]*scenario.Scenario, error) {
	return scenario.LoadFS(corpus, "scenarios")
}
