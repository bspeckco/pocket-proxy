# Decision: Add `allow_absolute_urls` mode with extracted target resolution module
_Recorded 2026-02-27 · Project: pocket-proxy_

## Context

pocket-proxy currently only supports a `base_url + allowed_paths` model: the agent sends `GET /proxy/tweets/search/recent` and the proxy prepends `svc.BaseURL` to build the upstream URL. This works for single-API services but doesn't work for general web scraping where agents hit arbitrary URLs.

The immediate driver: crawl-space agents (`claude -p`, `opencode run`) make HTTP requests via curl/fetch, bypassing pocket-proxy entirely. Agent CLIs don't write HTTP traffic to stdout/stderr — an `io.MultiWriter` tee in crawl-space's exec.go captures nothing useful. The only way to get HTTP visibility is routing all agent requests through the proxy.

Constraints:
- `proxy.go` is already 323 lines with a single `proxyRequest()` function handling 12 steps
- `server_test.go` is 1,325 lines of integration tests
- Budget tracking, credential injection, dedup, and request logging must all work unchanged for the new mode

## Decision

Two coupled decisions:

**1. `allow_absolute_urls` service mode.** A new boolean field on `ServiceConfig`. When enabled, agents pass `X-Target-URL: https://example.com/path` as a request header. The proxy validates the URL (scheme, optional domain filter, optional path filter) and forwards directly. Budget, logging, credential injection, and dedup all work unchanged — the only difference is how the upstream URL is determined.

An optional `allowed_domains` list restricts which hosts the agent can reach. Supports exact match and wildcard subdomain (`*.github.com`). Empty list = all domains allowed.

**2. Extract target resolution into `internal/server/target.go`.** A new file containing `resolveTarget()`, `resolveAbsoluteTarget()`, `resolvePathTarget()`, `domainAllowed()`, and the `targetInfo` struct. This replaces steps 4 and 8 in `proxyRequest()` with a single 5-line call, keeping the handler focused on orchestration.

New `internal/server/target_test.go` for table-driven unit tests (no integration server needed), keeping `server_test.go` from growing further.

## Rationale

**X-Target-URL header over URL-in-path:** Encoding arbitrary URLs in the path (`/proxy/https://example.com/path?q=x`) creates ambiguity with URL encoding, query string merging, and double-encoding edge cases. A header is unambiguous — the value is the exact URL to forward to.

**Separate `target.go` over inline in `proxy.go`:** Target resolution (URL parsing, domain matching, path validation) is a distinct concern from proxy orchestration (token auth, budget reservation, upstream forwarding, response logging). Extracting it:
- Keeps `proxy.go` from growing past 323 lines (actually shrinks it to ~300)
- Makes target resolution independently testable without spinning up the full integration server
- Keeps `server_test.go` (1,325 lines) from growing excessively — pure logic tests go in `target_test.go`

**Optional domain allowlist over mandatory:** Some use cases need unrestricted web access (general scraping). Others need tight restrictions (API-only services). Making it optional serves both without configuration burden.

## Alternatives Considered

1. **Capture agent CLI output via `--verbose` flags** — rejected. `claude -p` only writes final text to stdout. `--verbose` has a known bug (output goes to stdout instead of stderr, GitHub issue #4859). `opencode run` similar. Neither CLI exposes HTTP request/response traffic to the parent process.

2. **Read agent system logs** — rejected. Log locations are agent-specific, unstable, and parsing them is fragile.

3. **URL-in-path approach** (`/proxy/https://example.com/...`) — rejected. URL encoding ambiguity, query string merging complexity, and path prefix collisions make this error-prone. Header approach is clean and unambiguous.

4. **Inline all new logic in `proxy.go`** — rejected. `proxyRequest()` is already a 323-line function with 12 steps. Adding a conditional branch for URL resolution, domain matching, and header validation would push it well past 400 lines and make the two modes harder to test independently.

## Consequences

- **Easier:** Adding web scraping capabilities to crawl-space agents — just configure a service with `allow_absolute_urls: true` and the agent gets full HTTP visibility through pocket-proxy's logging
- **Easier:** Testing target resolution logic — table-driven tests in `target_test.go` without integration server overhead
- **Easier:** Future URL routing modes — `resolveTarget()` is a clean extension point
- **Harder:** Two code paths for URL resolution (standard vs absolute) — mitigated by the shared `targetInfo` return type
- **Invariant:** `X-Target-URL` header must be stripped before forwarding upstream (alongside `X-Run-Token`)
- **Invariant:** `AllowAbsoluteURLs: true` services don't require `base_url` or `allowed_paths` in config validation
- **Follow-up:** crawl-space `internal/proxy/proxy.go` needs `ServiceMeta` and `PreambleSuffix` updates to generate absolute-URL-mode agent instructions

## Status
**accepted**
