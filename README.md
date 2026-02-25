# pocket-proxy

Budget-limited HTTP proxy that gives AI agents supervised, credential-isolated access to external APIs. Agents get a scoped run token and a request budget — they never see real API keys, and the proxy hard-stops them when the budget is hit.

## Why

Giving agents direct API keys means they control spend and can leak credentials. Having the orchestrator do all fetching kills agent autonomy. Pocket Proxy sits in between: agents make real HTTP requests through the proxy, which injects credentials, enforces budgets, and logs everything — all in memory.

## Install

Requires Go 1.24+.

```
go build -o pocket-proxy
```

## Usage

```
pocket-proxy <config-path>
```

The proxy reads the YAML config, loads it into memory, securely deletes the config file (`srm` > `shred` > `rm` fallback), and starts listening. After startup, no secrets exist on disk.

Handles `SIGINT`/`SIGTERM` for graceful shutdown.

## Configuration

Single YAML file defining admin auth, credentials, and services:

```yaml
admin:
  secret: "adm_Tn4xKq9Rm2pLw8nJ"   # Bearer token for admin API (required)
  port: 9120                         # Listen port (required, 1-65535)
  id_size: 16                        # Nano ID length (default: 16)
  max_response_size: 1048576         # Max cached response in bytes (default: 1MB)
  proxy_url: "http://localhost:9120" # Proxy URL returned to agents (default: derived from port)

credentials:
  x-api:
    header: "Authorization"
    value: "Bearer AAA..."
  github:
    header: "Authorization"
    value: "token ghp_xxx"

services:
  x-search:
    base_url: "https://api.x.com/2"
    credential: "x-api"               # References a credential above
    allowed_paths:
      - "/tweets/search/recent"        # Exact match
      - "/repos/*"                     # Wildcard: matches any subpath
    max_requests: 10                   # Budget cap (required, > 0)
    dedup_enabled: true                # Return cached response for duplicate requests
    store_responses: true              # Cache response bodies (required if dedup_enabled)
    expires_in_seconds: 3600           # Run TTL (required, > 0)
```

## API

### Admin API

All endpoints require `Authorization: Bearer <admin-secret>`.

**`POST /admin/runs`** — Create a run.

```json
// Request
{ "service": "x-search" }

// Response 201
{
  "run_id": "Xk9mQ2pLw4nR7vTs",
  "token": "Bj3hY8dFe6gK1zAm",
  "proxy_url": "http://localhost:9120"
}
```

**`GET /admin/runs/:id`** — Get run status and request log.

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
      "created_at": "2025-01-15T14:30:00Z"
    }
  ]
}
```

**`GET /admin/runs/:id/responses`** — Get cached response bodies (requires `store_responses`).

**`POST /admin/runs/:id/close`** — Close and clean up a run.

```json
{ "mode": "purge" }
```

Modes: `purge` (default) deletes all run data; `flush` writes data to a file path, then purges:

```json
{ "mode": "flush", "path": "/mnt/data/run-output.json" }
```

**`DELETE /admin/runs/:id`** — Revoke a run immediately.

### Agent API

Agents authenticate with `X-Run-Token: <token>` on every request.

**`* /proxy/**`** — Proxy request to the target API.

```
GET /proxy/tweets/search/recent?query=example
X-Run-Token: Bj3hY8dFe6gK1zAm
```

Every response includes budget headers:

```
X-Budget-Used: 4
X-Budget-Remaining: 6
X-Budget-Total: 10
```

| Scenario | Status | Error code |
|---|---|---|
| Budget exhausted | `429` | `budget_exhausted` |
| Run revoked/expired | `403` | `run_terminated` |
| Path not allowed | `403` | `path_not_allowed` |
| Invalid/missing token | `401` | `unauthorized` |
| Upstream unreachable | `502` | `upstream_error` |

Deduplicated responses return `X-Dedup: true` and don't count against the budget.

## Key behaviors

- **Only 2xx counts.** Non-2xx upstream responses, timeouts, and connection failures do not consume budget.
- **Deduplication.** When enabled, identical requests (same method + path + body) return the cached response for free.
- **Path matching.** Exact paths match literally; paths ending in `/*` match any subpath.
- **Credential injection.** The proxy strips `X-Run-Token` and injects the configured credential header before forwarding upstream.
- **Run lifecycle.** Runs transition through: `active` → `exhausted` | `expired` | `revoked` | `closed`.

## Security

- Config file is securely deleted on startup — no secrets on disk after boot
- All state (tokens, credentials, logs) lives in an in-memory SQLite database
- Admin secret compared with constant-time comparison
- IDs generated with cryptographically secure randomness (no modulo bias)
- Agents never see real API credentials or the admin secret
