# Pocket Proxy — Specification

## Overview

A general-purpose HTTP proxy that gives untrusted agents supervised, budget-limited, credential-isolated access to any HTTP API. The proxy is a long-running process that holds all sensitive state (API credentials, run tokens, request/response logs) in memory, ensuring agents have no way to discover or escalate their access.

## Problem

AI agents that need to call external APIs face a trust gap:

- Giving agents direct API access means they control spend, can leak credentials, and can exceed intended usage
- Having the orchestrator do all fetching kills the agent's ability to explore and make adaptive decisions
- No existing tool provides the middle ground: supervised autonomy over HTTP with hard budget enforcement

## Architecture

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│ Orchestrator │──admin──▶│  Pocket Proxy    │──proxy──▶│ Target API  │
│ (Go runner)  │  API    │                  │         │ (e.g. X)    │
└─────────────┘         │  In-memory       │         └─────────────┘
                        │  SQLite DB       │
┌─────────────┐         │                  │
│    Agent     │──agent──▶│  - Runs          │
│ (CC/OpenCode)│  API    │  - Tokens        │
└─────────────┘         │  - Request logs  │
                        │  - Response cache│
                        │  - Dedup index   │
                        └──────────────────┘
```

### Key Principles

- **Tokens never touch disk.** All run state lives in the proxy's in-memory SQLite database. Agents cannot discover tokens by reading files, env vars, or local databases.
- **Agents never see real credentials.** The proxy holds API keys/Bearer tokens and injects them into proxied requests. The agent only knows its run token and the proxy address.
- **Hard budget enforcement.** The proxy counts requests and returns a deterministic "budget exhausted" signal when the cap is reached. This is not advisory — the proxy stops proxying.
- **Transparent proxying.** The agent gets the real upstream response (headers and body) plus budget metadata. From the agent's perspective, it's making normal HTTP requests with extra context.

## Configuration

A single YAML file defines everything the proxy needs: admin auth, credentials, and service definitions. This file is written to `/tmp` at container startup, consumed by the proxy on init, and securely deleted (`srm`). After startup, all configuration exists only in proxy memory.

```yaml
admin:
  secret: "adm_Tn4xKq9Rm2pLw8nJ"
  port: 9120
  id_size: 16               # Nano ID length (default: 16)
  max_response_size: 1048576 # Max cached response body in bytes (default: 1MB)

credentials:
  x-api:
    header: "Authorization"
    value: "Bearer AAA..."
  github:
    header: "Authorization"
    value: "token ghp_xxx"
  some-custom-api:
    header: "X-API-Key"
    value: "sk-123"

services:
  x-search:
    base_url: "https://api.x.com/2"
    credential: "x-api"
    allowed_paths:
      - "/tweets/search/recent"
    max_requests: 10
    dedup_enabled: true
    store_responses: true
    expires_in_seconds: 3600
  github-repos:
    base_url: "https://api.github.com"
    credential: "github"
    allowed_paths:
      - "/search/repositories"
      - "/repos/*"
    max_requests: 20
    dedup_enabled: false
    store_responses: false
    expires_in_seconds: 1800
```

### Credentials

Each credential defines a name, the HTTP header it should be injected as, and the value. When a service references a credential by name, the proxy resolves it and injects the appropriate header into every proxied request for runs against that service.

### Services

Each service defines a target API and the constraints for runs against it. All run behaviour (budget, dedup, response storage, TTL, allowed paths) is configured here. The orchestrator only needs to reference a service by name to create a run.

## Credential Handling

In the current deployment model (ephemeral containers), the runner is the orchestrator and owns the entire lifecycle:

1. Runner generates a random admin secret
2. Runner writes the full config YAML to `/tmp` (admin secret, API credentials, service definitions)
3. Runner starts the proxy process
4. Proxy reads the file, loads everything into memory, securely deletes it (`srm`)
5. Runner holds the admin secret in its own process memory for admin API calls
6. Runner creates a run via the Admin API, receives a token
7. Runner launches the agent process with only the token and proxy URL
8. Agent runs, makes proxied requests, exhausts budget or completes
9. Runner closes the run, container is destroyed

The agent process only ever receives the run token and the proxy address. The admin secret exists only in the runner's memory. The API credentials exist only in the proxy's memory. By the time the agent starts, the config file is gone and no env vars contain sensitive values. Even if the agent discovers the proxy port, it cannot authenticate to the Admin API without the admin secret, and cannot use the Agent API without a valid run token.

**If the environment becomes persistent**, this model would need to be replaced with credential aliases backed by an external vault. That's out of scope for V1.

## Data Model (In-Memory SQLite)

### Runs

| Field | Type | Description |
|---|---|---|
| id | TEXT PK | Nano ID (16 chars default, configurable) |
| token | TEXT UNIQUE | Opaque token issued to agent (Nano ID) |
| service | TEXT | Name of the service from config |
| requests_used | INTEGER | Counter, starts at 0 |
| status | TEXT | `active`, `exhausted`, `expired`, `revoked`, `closed` |
| created_at | DATETIME | |
| expires_at | DATETIME | Derived from service `expires_in_seconds` |

### Request Log

| Field | Type | Description |
|---|---|---|
| id | TEXT PK | Nano ID (16 chars default, configurable) |
| run_id | TEXT FK | |
| method | TEXT | GET, POST, etc. |
| path | TEXT | Request path + query string |
| status_code | INTEGER | Upstream response status |
| counted | BOOLEAN | Whether this request counted against budget (true for 2xx only) |
| response_body | BLOB | Optional, only if service has `store_responses` enabled and response was 2xx |
| dedup_key | TEXT | Hash of method + path + relevant params |
| created_at | DATETIME | |

## Request Counting Policy

Only successful upstream responses (2xx status codes) count against the run budget. Failed requests — whether caused by upstream errors (5xx), rate limiting (429), or bad agent queries (4xx) — are passed through to the agent transparently but do not:

- Increment `requests_used`
- Enter the dedup index
- Get stored in the response cache

This means the budget headers on a failed response show the same values as before the request was made. The agent knows the request failed, but hasn't lost budget.

The rationale is simple: the agent got no usable data, so the request doesn't count. This keeps the rule predictable and avoids penalising agents for upstream instability or query iteration.

Upstream timeouts and connection failures follow the same rule. If the proxy cannot reach the upstream service (timeout, DNS failure, connection refused), the request is not counted and the agent receives a `502 Bad Gateway` response with unchanged budget headers.

## APIs

### Admin API

Authenticated via the `admin.secret` from the config file. Every admin request must include the secret as a Bearer token in the `Authorization` header. Without it, the proxy returns `401 Unauthorized`.

```
Authorization: Bearer adm_Tn4xKq9Rm2pLw8nJ
```

#### `POST /admin/runs`

Create a new run against a configured service.

```json
{
  "service": "x-search"
}
```

Returns:

```json
{
  "run_id": "Xk9mQ2pLw4nR7vTs",
  "token": "Bj3hY8dFe6gK1zAm",
  "proxy_url": "http://localhost:9120"
}
```

The orchestrator passes `token` and `proxy_url` to the agent (e.g. injected into the agent prompt). All budget, auth, and path constraints come from the service definition in the config.

#### `GET /admin/runs/:id`

Query run status.

```json
{
  "run_id": "Xk9mQ2pLw4nR7vTs",
  "service": "x-search",
  "status": "active",
  "requests_used": 4,
  "max_requests": 10,
  "requests": [
    {
      "method": "GET",
      "path": "/tweets/search/recent?query=...",
      "status_code": 200,
      "counted": true,
      "created_at": "2026-02-25T14:30:00Z"
    }
  ]
}
```

#### `GET /admin/runs/:id/responses`

Retrieve cached response bodies (if the service has `store_responses` enabled).

#### `POST /admin/runs/:id/close`

Close a run.

```json
{
  "mode": "purge"
}
```

Modes:
- `purge` (default) — delete all run data from memory immediately
- `flush` — write request log and responses to a specified path, then purge

Flush example:

```json
{
  "mode": "flush",
  "path": "/mnt/data/run-output.json"
}
```

#### `DELETE /admin/runs/:id`

Revoke a run immediately. Any in-flight or subsequent agent requests receive a `revoked` error.

### Agent API

Token-scoped. The agent's only interface to the proxy. No authentication other than a valid run token.

#### `* /proxy/**`

Proxied request. The agent makes a standard HTTP request to the proxy, which forwards it to the target API.

**Request:**

```
GET /proxy/tweets/search/recent?query=example&max_results=100
X-Run-Token: Bj3hY8dFe6gK1zAm
```

**Successful Response:**

The upstream response is returned as-is (status code, headers, body), with additional budget headers:

```
HTTP/1.1 200 OK
X-Budget-Used: 4
X-Budget-Remaining: 6
X-Budget-Total: 10
Content-Type: application/json

{ ...upstream response body... }
```

**Budget Exhausted Response:**

```
HTTP/1.1 429 Too Many Requests
X-Budget-Used: 10
X-Budget-Remaining: 0
X-Budget-Total: 10
Content-Type: application/json

{
  "error": "budget_exhausted",
  "message": "Run has reached its request limit (10/10).",
  "requests_used": 10,
  "max_requests": 10
}
```

**Revoked/Expired Response:**

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "run_terminated",
  "message": "This run has been revoked or has expired."
}
```

**Deduplicated Response:**

If the service has `dedup_enabled` and the same request has been made before in this run, the proxy returns the cached response without counting it against the budget:

```
HTTP/1.1 200 OK
X-Budget-Used: 4
X-Budget-Remaining: 6
X-Budget-Total: 10
X-Dedup: true
Content-Type: application/json

{ ...cached response body... }
```

Note: dedup requires `store_responses` to be enabled on the service.

**No Token / Invalid Token Response:**

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "unauthorized",
  "message": "Missing or invalid run token."
}
```

**Disallowed Path Response:**

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "path_not_allowed",
  "message": "This path is not permitted for the current run."
}
```

## Agent Prompt Integration

The orchestrator provides the agent with minimal context:

```
You have access to a web API via a proxy. To make requests:

  Endpoint: http://localhost:9120/proxy
  Token: Bj3hY8dFe6gK1zAm (pass as X-Run-Token header)

Every response includes budget headers:
  X-Budget-Used, X-Budget-Remaining, X-Budget-Total

You have a limited number of requests. Check X-Budget-Remaining after
each request and plan accordingly. When you receive a 429 response
with error "budget_exhausted", you are done making requests.

Target API base: https://api.x.com/2
Available paths: /tweets/search/recent
```

## Implementation Notes

- **Language:** Go. Single binary for the container image.
- **SQLite:** Use `:memory:` mode. No file touches disk.
- **Concurrency:** The proxy must handle concurrent agent requests safely. SQLite in WAL mode with proper locking, or serialise writes.
- **Response storage:** Configurable max size per response, default 1MB. Responses exceeding the threshold are not cached (the request still counts and the agent still receives the response, but the body is not stored).
- **Startup:** The proxy takes a single argument: the path to the config file. It reads the file, loads everything into memory, then deletes the file via `srm`. It then starts listening on the configured port.

## Future Considerations (Not for V1)

- Cost-based budgeting (not just request count) when APIs provide cost-per-request info
- Persistent mode with file-backed SQLite for run history and cost analysis
- Remote deployment (proxy on a different machine from agents)
- WebSocket/SSE support for streaming API responses
- Rate limit awareness (reading upstream rate limit headers and throttling proactively)
