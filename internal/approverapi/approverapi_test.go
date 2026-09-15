package approverapi

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fkadusei/agent-warden/internal/broker"
	"github.com/fkadusei/agent-warden/internal/canonical"
	"github.com/fkadusei/agent-warden/internal/composite"
	"github.com/fkadusei/agent-warden/internal/gateway"
	"github.com/fkadusei/agent-warden/internal/identity"
	"github.com/fkadusei/agent-warden/internal/policy"
	"github.com/fkadusei/agent-warden/internal/receipt"
	"github.com/fkadusei/agent-warden/internal/registry"
	"github.com/fkadusei/agent-warden/internal/store"
)

const policies = `
@id("refunds_need_approval")
permit (principal, action == Action::"call", resource == Tool::"payments/refund");
`

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type tools struct{}

func (tools) Manifest(_ context.Context, server, tool string) (registry.Manifest, error) {
	return registry.Manifest{Server: server, Name: tool, Description: "Refund a payment.", InputSchema: map[string]any{"type": "object"}}, nil
}

func (tools) Call(context.Context, string, string, json.RawMessage, []broker.Credential) (*gateway.ToolResult, error) {
	return &gateway.ToolResult{Content: []byte(`{"refunded":true}`)}, nil
}

type env struct {
	gw        *gateway.Gateway
	api       *httptest.Server
	cred      []byte
	bob       *Client
	alice     *Client
	mallory   *Client
	decisions []int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	e := &env{}

	ca := must(identity.NewCA("root", must(mldsa.GenerateKey(mldsa.MLDSA65())), now.Add(-time.Hour), now.Add(time.Hour)))
	e.cred = must(ca.IssueTask(identity.TaskClaims{Agent: "agent-7", Principal: "alice@tenant-a", Task: "t1"},
		must(mldsa.GenerateKey(mldsa.MLDSA65())).PublicKey(), now.Add(-time.Minute), now.Add(10*time.Minute)))

	receiptKey := must(composite.MLDSA65Ed25519.GenerateKey())
	st := must(store.Open(filepath.Join(t.TempDir(), "r.db"), receiptKey, "k1", "chain-1"))
	t.Cleanup(func() { st.Close() })

	m, _ := tools{}.Manifest(ctx, "payments", "refund")
	reg := must(registry.Load(must(registry.PinAll([]registry.Manifest{m}))))
	keys := map[string]*composite.PrivateKey{
		"bob@tenant-a":   must(composite.MLDSA65Ed25519.GenerateKey()),
		"alice@tenant-a": must(composite.MLDSA65Ed25519.GenerateKey()),
	}
	resolve := func(k string) (*composite.PublicKey, error) {
		if key, ok := keys[k]; ok {
			return key.Public(), nil
		}
		return nil, errors.New("unknown")
	}
	e.gw = must(gateway.New(gateway.Config{
		Store: st, Registry: reg, Policy: must(policy.Load("p", []byte(policies))),
		Broker: must(broker.Load([]byte(`{"v":1,"bindings":[]}`), broker.Sources{})),
		Roots:  ca.Pool(), Approvers: resolve, Upstream: tools{},
	}))
	for _, amount := range []string{"500", "900"} {
		resp := must(e.gw.Call(ctx, e.cred, "payments", "refund", json.RawMessage(`{"amount":`+amount+`}`)))
		e.decisions = append(e.decisions, resp.DecisionSeq)
	}

	e.api = httptest.NewServer(NewServer(e.gw, st, resolve, nil).Handler())
	t.Cleanup(e.api.Close)
	client := func(id string, k *composite.PrivateKey) *Client {
		return &Client{BaseURL: e.api.URL, HTTP: e.api.Client(), Key: k, Approver: id}
	}
	e.bob = client("bob@tenant-a", keys["bob@tenant-a"])
	e.alice = client("alice@tenant-a", keys["alice@tenant-a"])
	e.mallory = client("mallory@tenant-a", must(composite.MLDSA65Ed25519.GenerateKey()))
	return e
}

func TestListAndApprove(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	list, err := e.bob.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].DecisionSeq != e.decisions[0] || string(list[1].Args) != `{"amount":900}` || list[0].Actor.Principal != "alice@tenant-a" {
		t.Fatalf("unexpected list %+v", list)
	}

	st := must(e.bob.Sign(list[0], receipt.Approved, 10*time.Minute))
	sub, err := e.bob.Submit(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if sub.DecisionSeq != e.decisions[0] || sub.Outcome != receipt.Approved || sub.Approver != "bob@tenant-a" {
		t.Fatalf("unexpected submission %+v", sub)
	}
	if _, err := e.gw.Resume(ctx, e.cred, e.decisions[0]); err != nil {
		t.Fatalf("approved call did not run: %v", err)
	}

	list = must(e.bob.List(ctx))
	if len(list) != 1 || list[0].DecisionSeq != e.decisions[1] {
		t.Fatalf("executed call still listed: %+v", list)
	}
}

func TestSubmitErrors(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	list := must(e.bob.List(ctx))

	t.Run("self-approval is forbidden", func(t *testing.T) {
		_, err := e.alice.Submit(ctx, must(e.alice.Sign(list[0], receipt.Approved, 10*time.Minute)))
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("got %v, want 403", err)
		}
	})
	t.Run("untrusted approver is refused", func(t *testing.T) {
		_, err := e.mallory.Submit(ctx, must(e.mallory.Sign(list[0], receipt.Approved, 10*time.Minute)))
		if err == nil || !strings.Contains(err.Error(), "400") {
			t.Fatalf("got %v, want 400", err)
		}
	})
	t.Run("second answer conflicts", func(t *testing.T) {
		if _, err := e.bob.Submit(ctx, must(e.bob.Sign(list[1], receipt.Rejected, 10*time.Minute))); err != nil {
			t.Fatal(err)
		}
		_, err := e.bob.Submit(ctx, must(e.bob.Sign(list[1], receipt.Approved, 10*time.Minute)))
		if err == nil || !strings.Contains(err.Error(), "409") {
			t.Fatalf("got %v, want 409", err)
		}
	})
	t.Run("unknown decision", func(t *testing.T) {
		p := list[0]
		p.DecisionSeq = 999
		_, err := e.bob.Submit(ctx, must(e.bob.Sign(p, receipt.Approved, 10*time.Minute)))
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("got %v, want 404", err)
		}
	})
	t.Run("garbage body", func(t *testing.T) {
		if _, err := e.bob.Submit(ctx, []byte("nope")); err == nil {
			t.Fatal("accepted")
		}
	})
}

// signedList builds a raw list request body with the given fields.
func signedList(t *testing.T, c *Client, kid string, req ListRequest) []byte {
	t.Helper()
	payload := must(canonical.Encode(req))
	return must(must(receipt.SignPayload(c.Key, kid, payload)).Line())
}

func postList(t *testing.T, e *env, body []byte) int {
	t.Helper()
	resp, err := e.api.Client().Post(e.api.URL+"/v1/pending", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestListAuthentication(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	good := func() ListRequest {
		return ListRequest{Domain: RequestDomain, Approver: "bob@tenant-a", Nonce: strings.Repeat("n", 30) + now.Format("150405.000")[:6], TS: now.Format(receipt.TimeFormat)}
	}

	body := signedList(t, e.bob, "bob@tenant-a", good())
	if code := postList(t, e, body); code != http.StatusOK {
		t.Fatalf("valid request: %d", code)
	}
	if code := postList(t, e, body); code != http.StatusUnauthorized {
		t.Fatalf("replayed request: %d, want 401", code)
	}

	cases := map[string][]byte{
		"stale timestamp": signedList(t, e.bob, "bob@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = strings.Repeat("a", 30)
			r.TS = now.Add(-5 * time.Minute).Format(receipt.TimeFormat)
			return r
		}()),
		"future timestamp": signedList(t, e.bob, "bob@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = strings.Repeat("b", 30)
			r.TS = now.Add(5 * time.Minute).Format(receipt.TimeFormat)
			return r
		}()),
		"approver field differs from key": signedList(t, e.bob, "bob@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = strings.Repeat("c", 30)
			r.Approver = "carol@tenant-a"
			return r
		}()),
		"untrusted approver": signedList(t, e.mallory, "mallory@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = strings.Repeat("d", 30)
			r.Approver = "mallory@tenant-a"
			return r
		}()),
		"signed by another key": signedList(t, e.mallory, "bob@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = strings.Repeat("e", 30)
			return r
		}()),
		"wrong domain": signedList(t, e.bob, "bob@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = strings.Repeat("f", 30)
			r.Domain = approvalStatementDomainForTest
			return r
		}()),
		"short nonce": signedList(t, e.bob, "bob@tenant-a", func() ListRequest {
			r := good()
			r.Nonce = "abc"
			return r
		}()),
		"not a signed request": []byte(`{"approver":"bob@tenant-a"}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if code := postList(t, e, body); code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", code)
			}
		})
	}
}

const approvalStatementDomainForTest = "agent-warden/approval-statement/v1"

// A server that shows different arguments than it committed to is caught before
// the approver signs anything.
func TestClientDetectsALyingServer(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	liar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp, err := http.Post(e.api.URL+r.URL.Path, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Write(bytes.ReplaceAll(data, []byte(`{"amount":500}`), []byte(`{"amount":5}`)))
	}))
	defer liar.Close()

	c := *e.bob
	c.BaseURL, c.HTTP = liar.URL, liar.Client()
	if _, err := c.List(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("got %v, want ErrTampered", err)
	}

	// And Sign refuses a tampered entry even if it is handed one directly.
	list := must(e.bob.List(ctx))
	p := list[0]
	p.Args = json.RawMessage(`{"amount":5}`)
	if _, err := e.bob.Sign(p, receipt.Approved, 10*time.Minute); !errors.Is(err, ErrTampered) {
		t.Fatalf("Sign on tampered entry: got %v, want ErrTampered", err)
	}
}
