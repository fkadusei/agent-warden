package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fkadusei/agent-warden/internal/approverapi"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/keyfile"
	"github.com/fkadusei/agent-warden/internal/receipt"
)

// rootPool reads the Warden root certificate for server verification.
func rootPool(caPath string) (*x509.CertPool, error) {
	der, err := keyfile.ReadCertificate(caPath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// agentSession connects to Warden as an agent, presenting a task credential.
func agentSession(ctx context.Context, url, caPath, certPath, keyPath string) (*mcp.ClientSession, error) {
	pool, err := rootPool(caPath)
	if err != nil {
		return nil, err
	}
	certDER, err := keyfile.ReadCertificate(certPath)
	if err != nil {
		return nil, err
	}
	key, err := keyfile.ReadMLDSA(keyPath)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS13, VerifyConnection: identity.CheckServer,
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
	}}
	client := mcp.NewClient(&mcp.Implementation{Name: "warden-call", Version: "0.1.0"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: url, HTTPClient: &http.Client{Transport: transport}, DisableStandaloneSSE: true, MaxRetries: -1,
	}, nil)
}

// callTool calls one tool and returns its text and whether Warden or the tool
// reported an error.
func callTool(ctx context.Context, s *mcp.ClientSession, tool string, args json.RawMessage) (string, bool, error) {
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", false, err
	}
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n"), res.IsError, nil
}

func cmdCall(ctx context.Context, args []string, _ io.Reader, out io.Writer) error {
	fs := flags("call", out)
	url := fs.String("url", "https://127.0.0.1:8443", "Warden's agent endpoint")
	caPath := fs.String("ca", "warden-local/pki/ca.pem", "Warden root certificate")
	certPath := fs.String("cert", "warden-local/agent.pem", "task credential")
	keyPath := fs.String("key", "warden-local/agent.key", "task credential private key")
	list := fs.Bool("list", false, "list the tools Warden exposes")
	tool := fs.String("tool", "", "tool to call, e.g. crm.lookup")
	argJSON := fs.String("args", "{}", "tool arguments as a JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*list && *tool == "" {
		return errors.New("use --list or --tool")
	}
	s, err := agentSession(ctx, *url, *caPath, *certPath, *keyPath)
	if err != nil {
		return err
	}
	defer s.Close()

	if *list {
		for t, err := range s.Tools(ctx, nil) {
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "  %-20s %s\n", t.Name, t.Description)
		}
		return nil
	}
	if !json.Valid([]byte(*argJSON)) {
		return errors.New("--args is not valid JSON")
	}
	text, isError, err := callTool(ctx, s, *tool, json.RawMessage(*argJSON))
	if err != nil {
		return err
	}
	if isError {
		fmt.Fprintf(out, "NOT RUN / ERROR:\n%s\n", text)
		return nil
	}
	fmt.Fprintf(out, "%s\n", text)
	return nil
}

func approverClient(url, caPath, keyPath, id string) (*approverapi.Client, error) {
	pool, err := rootPool(caPath)
	if err != nil {
		return nil, err
	}
	key, err := keyfile.ReadComposite(keyPath)
	if err != nil {
		return nil, err
	}
	return &approverapi.Client{
		BaseURL: strings.TrimSuffix(url, "/"),
		HTTP: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS13, VerifyConnection: identity.CheckServer,
		}}},
		Key: key, Approver: id,
	}, nil
}

func cmdApprove(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	fs := flags("approve", out)
	url := fs.String("url", "https://127.0.0.1:8444", "Warden's approver API")
	caPath := fs.String("ca", "warden-local/pki/ca.pem", "Warden root certificate")
	keyPath := fs.String("key", "", "approver private key")
	id := fs.String("id", "", "approver identity, e.g. bob@tenant-a")
	decision := fs.Int64("decision", -1, "decision receipt number to answer (omit to list pending calls)")
	reject := fs.Bool("reject", false, "reject instead of approve")
	ttl := fs.Duration("ttl", 10*time.Minute, "how long an approval stays valid (at most 1h)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *id == "" {
		return errors.New("--key and --id are required")
	}
	c, err := approverClient(*url, *caPath, *keyPath, *id)
	if err != nil {
		return err
	}
	pending, err := c.List(ctx)
	if err != nil {
		return err
	}
	if *decision < 0 {
		if len(pending) == 0 {
			fmt.Fprintln(out, "No calls are waiting for approval.")
			return nil
		}
		for _, p := range pending {
			state := "waiting"
			if p.Approval != nil {
				state = string(p.Approval.Outcome) + " by " + p.Approval.Approver
			}
			fmt.Fprintf(out, "  #%-4d %-18s %s for %s  args %s  [%s]\n", p.DecisionSeq, p.Call.Tool, p.Actor.Agent, p.Actor.Principal, p.Args, state)
		}
		return nil
	}

	var target *approverapi.Pending
	for i := range pending {
		if pending[i].DecisionSeq == *decision {
			target = &pending[i]
		}
	}
	if target == nil {
		return fmt.Errorf("no call is waiting under decision #%d", *decision)
	}
	outcome := receipt.Approved
	if *reject {
		outcome = receipt.Rejected
	}
	fmt.Fprintf(out, "Decision #%d (%s)\n  tool:      %s\n  arguments: %s\n  agent:     %s\n  for:       %s\n  task:      %s\n  rule:      %s\n",
		target.DecisionSeq, target.DecisionTS, target.Call.Tool, target.Args, target.Actor.Agent, target.Actor.Principal, target.TaskID, target.Rule)
	if len(target.Taint) > 0 {
		fmt.Fprintf(out, "  taint:     %s\n", strings.Join(target.Taint, ", "))
	}
	fmt.Fprintln(out, "  (arguments verified against the decision receipt's commitment)")
	if !*yes {
		verb := "Approve"
		if *reject {
			verb = "Reject"
		}
		fmt.Fprintf(out, "%s this call? [y/N] ", verb)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			return errors.New("not confirmed; nothing was signed")
		}
	}
	statement, err := c.Sign(*target, outcome, *ttl)
	if err != nil {
		return err
	}
	sub, err := c.Submit(ctx, statement)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Recorded: decision #%d %s by %s, valid until %s.\n", sub.DecisionSeq, sub.Outcome, sub.Approver, sub.ExpiresTS)
	if sub.Outcome == receipt.Approved {
		fmt.Fprintf(out, "The agent can now call warden.resume with {\"decision_seq\": %d}.\n", sub.DecisionSeq)
	}
	return nil
}
