# ADR-0011: MCP transport and agent authentication

- **Status:** Accepted
- **Date:** 2026-09-15
- **Related:** threats W3, W4, W7; ADR-0010 (certificate profile); design §2, §3;
  Phase 2 step 2.8

## Context

The agent reaches tools only through Warden, over MCP. Warden must know which task
credential made each call, and the agent must prove it holds that credential's
private key; a certificate sent as data could be replayed by anyone who copied it.
Warden also reaches upstream tool servers over MCP, and must inject their
credentials without the agent ever seeing them.

Checked on 2026-09-15:

- **Go 1.27 `crypto/tls`** completes a TLS 1.3 handshake with mutual authentication
  using ML-DSA-65 certificates on both sides; the server sees exactly the verified
  client certificate, and a client without one is refused.
- **MCP Go SDK v1.8.0:** `NewStreamableHTTPHandler` supports `Stateless` mode (no
  `Mcp-Session-Id`, a temporary session per request). Tool handlers receive
  `RequestExtra.Header` from the HTTP request, but not its TLS state. `getServer` is
  called several times per request. Tool names are limited to `A–Z a–z 0–9 _ - .`,
  up to 128 characters. The streamable client sends each POST with the calling
  context. `CommandTransport` leaves the process environment to the caller.

## Decision

### Agent to Warden

- **Transport:** MCP Streamable HTTP, **stateless**, over **TLS 1.3 only**.
- **Agent authentication:** mutual TLS. The client certificate is the agent's **task
  credential** (ADR-0010), so the handshake proves the agent holds its key. Requests
  without a verified client certificate are refused before MCP sees them.
- **Why stateless:** each request stands on its own TLS connection's certificate. With
  sessions, a second client that learned a session ID could act under the first
  client's identity.
- **Passing identity to tools:** a Warden middleware deletes any client-supplied
  `X-Warden-Peer-Certificate` header, then sets it to the verified peer certificate
  (base64). One shared MCP server reads it from `RequestExtra.Header` and passes it to
  the gateway, which verifies the credential again.
- **Warden's server certificate** is a third profile under Warden's arc: policy
  `…4786.3`, server-authentication key usage, DNS or IP names, at most 90 days. Agents
  check that policy, so any other certificate from the same root cannot impersonate
  the gateway.

### Tools exposed to the agent

- Each pinned tool whose current manifest matches its pin is exposed as
  **`<server>.<tool>`** with its pinned description and input schema. Server names
  must not contain `.`; tool names may, and Warden splits at the first dot.
- The server name `warden` is reserved. **`warden.resume`** takes `{"decision_seq": n}`
  and runs an approved call (gateway `Resume`).
- Outcomes map to MCP results: `ok` returns the scrubbed tool output; `denied`,
  `tool_error`, and `pending_approval` return `isError: true` with a short explanation
  that names the decision receipt. A pending call's explanation tells the agent to call
  `warden.resume` once approved.

### Warden to upstream tool servers

- **Streamable HTTP servers:** credentials of kind `header` are set per call by an HTTP
  transport that reads them from the call's context. They exist only in Warden's
  process and on that request.
- **stdio servers:** credentials of kind `env` are resolved once, from server-wide
  bindings (`tool: "*"`), and set on the process when it starts. Per-tool `env`
  bindings cannot be honored by a long-lived process and are refused at startup.
  The process receives only those variables plus a minimal `PATH`, never Warden's
  environment.
- The manifest is listed from the upstream server on every call, so a changed tool is
  caught at the next call, not the next restart.

### Approvers (step 2.8b)

- A separate HTTPS listener (server authentication only) serves pending calls and
  accepts signed approval statements. Listing pending calls requires a request signed
  with a trusted approver key, with a timestamp no more than one minute old and a
  single-use nonce; submitting an approval needs no further authentication, because
  the statement itself is signed (ADR-0009).
- `warden approve` uses that API.

## Consequences

- Agent identity is cryptographically proven on every request and bound to receipts,
  with no bearer tokens to leak.
- Stateless mode rules out server-to-client requests such as sampling or elicitation;
  Warden does not need them.
- Agents must hold a fresh task credential and key, and reconnect when it expires
  (at most every 16 minutes).
- Listing upstream tools on every call adds latency; the benchmark measures it.
- The internal header is trusted only because the middleware always overwrites it;
  tests check that a client-supplied value is ignored.

## Alternatives considered

- **Certificate in the request body or `_meta`** — no proof of key possession; a copied
  certificate could be replayed. Rejected.
- **OAuth bearer tokens** — well supported by the SDK, but a stolen token works from
  anywhere until it expires, which is the credential-theft pattern Warden exists to
  remove. Rejected for agents.
- **stdio between agent and Warden** — the agent would launch Warden, putting Warden's
  secrets and receipt key inside the agent's trust boundary (W3, W7). Rejected.
- **Stateful sessions bound to the first request's certificate** — workable with extra
  checks on every request, but stateless mode removes the problem. Rejected.
