package exampletools

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fkadusei/agent-warden/internal/scenario"
	"github.com/fkadusei/agent-warden/internal/upstream"
)

func connect(t *testing.T, base, server string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: base + "/" + server}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func text(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) (string, *mcp.CallToolResult) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res.Content[0].(*mcp.TextContent).Text, res
}

func TestToolLists(t *testing.T) {
	want := []string{"crm.lookup", "hr.salaries", "mail.inbox", "mail.send", "payments.refund", "tickets.get", "web.fetch"}
	if got := Tools(); !slices.Equal(got, want) {
		t.Fatalf("Tools() = %v", got)
	}
	if got := Readable(); !slices.Equal(got, []string{"crm.lookup", "mail.inbox", "tickets.get", "web.fetch"}) {
		t.Fatalf("Readable() = %v", got)
	}
}

func TestHandlerServesPlantedContent(t *testing.T) {
	srv := httptest.NewServer(Handler("tok",
		scenario.Content{Tool: "tickets.get", Args: map[string]any{"id": "T-1"}, Authors: []string{"bob@tenant-b"}, Body: "planted ticket"},
		scenario.Content{Tool: "mail.inbox", Body: "planted inbox"},
		scenario.Content{Tool: "payments.refund", Body: "must never be served"},
	))
	defer srv.Close()

	tickets := connect(t, srv.URL, "tickets")
	body, res := text(t, tickets, "get", map[string]any{"id": "T-1"})
	if body != "planted ticket" {
		t.Fatalf("planted ticket body %q", body)
	}
	if authors, err := upstream.Authors(res.Meta); err != nil || !slices.Equal(authors, []string{"bob@tenant-b"}) {
		t.Fatalf("authors %v, %v", authors, err)
	}
	// The SDK adds its own _meta (server info); what matters is that no authors are claimed.
	body, res = text(t, tickets, "get", map[string]any{"id": "T-2"})
	if authors, err := upstream.Authors(res.Meta); !strings.Contains(body, "T-2") || err != nil || len(authors) != 0 {
		t.Fatalf("unmatched ticket got %q authors %v (%v)", body, authors, err)
	}

	if body, _ := text(t, connect(t, srv.URL, "mail"), "inbox", map[string]any{}); body != "planted inbox" {
		t.Fatalf("inbox %q", body)
	}
	// Content is only served by read-only tools: a refund still checks its token.
	body, res = text(t, connect(t, srv.URL, "payments"), "refund", map[string]any{"payment_id": "p-1", "amount": 5})
	if !res.IsError || !strings.Contains(body, "unauthorized") {
		t.Fatalf("refund without token: %q", body)
	}
	if body, _ := text(t, connect(t, srv.URL, "crm"), "lookup", map[string]any{"id": "c-7"}); !strings.Contains(body, "customer-c-7@tenant-a.example") {
		t.Fatalf("default lookup %q", body)
	}
}
