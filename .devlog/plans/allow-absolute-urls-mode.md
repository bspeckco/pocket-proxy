# pocket-proxy: `allow_absolute_urls` mode

## Context

crawl-space agents (`claude -p`, `opencode run`) make HTTP requests directly via curl/fetch, bypassing pocket-proxy entirely. The `io.MultiWriter` tee in exec.go captures nothing useful — agent CLIs don't write their HTTP traffic to stdout/stderr. The only way to get visibility into agent HTTP activity is to route ALL requests through pocket-proxy.

Currently, pocket-proxy only supports a `base_url + allowed_paths` model. This works for single-API services but doesn't work for general web scraping where agents hit arbitrary URLs.

**Solution**: Add an `allow_absolute_urls` mode. The agent sends `X-Target-URL: https://example.com/path` and the proxy forwards to that URL directly. Budget, logging, credential injection, and dedup all work unchanged. An optional `allowed_domains` list restricts which hosts the agent can reach.

---

## Modularity approach

Current file sizes that inform the design:
- `proxy.go` — 323 lines (single `proxyRequest()` doing 12 steps)
- `server_test.go` — 1,325 lines
- `server.go` — 97 lines
- crawl-space `proxy.go` — 312 lines (process lifecycle + admin API + preamble)

**Key decisions:**
1. **Extract target resolution** into `internal/server/target.go` — keeps `proxyRequest()` from growing. Contains `resolveTarget()` (both modes), `domainAllowed()`, and the `targetInfo` struct.
2. **New test file** `internal/server/target_test.go` — unit tests for target resolution and domain matching (table-driven, no integration server needed). Keeps `server_test.go` from growing further.
3. **Absolute URL integration tests** go in `server_test.go` since they reuse `testEnv` infrastructure, but only the integration tests that need the full proxy roundtrip.
4. **Crawl-space preamble** — `PreambleSuffix` stays in `proxy.go` with a conditional branch (not worth a separate file for a single function change).

---

## Repo: `~/Development/pocket-proxy`

### 1. Config — `internal/config/config.go`

Add to `ServiceConfig`:
```go
AllowAbsoluteURLs bool     `yaml:"allow_absolute_urls"`
AllowedDomains    []string `yaml:"allowed_domains"`
```

Modify `validate()` service loop — when `AllowAbsoluteURLs` is true:
- `BaseURL` not required (skip check)
- `AllowedPaths` not required (skip check)
- If `BaseURL` is set but `AllowedPaths` is empty → error (misconfiguration)
- `Credential` still required

When `AllowAbsoluteURLs` is false: unchanged.

### 2. New file — `internal/server/target.go`

Contains all target URL resolution logic, cleanly separated from the proxy handler:

```go
package server

import (
    "fmt"
    "net/http"
    "net/url"
    "strings"

    "pocket-proxy/internal/config"
)

// targetInfo holds the resolved target URL and log path for a proxy request.
type targetInfo struct {
    URL     string // full upstream URL
    LogPath string // path or URL for request logging
}

// resolveTarget determines the upstream URL from either X-Target-URL header
// (absolute URL mode) or the request path (standard base_url mode).
// Returns targetInfo on success, or an error code + message on failure.
func resolveTarget(r *http.Request, svc *config.ServiceConfig) (*targetInfo, int, string, string) {
    if svc.AllowAbsoluteURLs {
        return resolveAbsoluteTarget(r, svc)
    }
    return resolvePathTarget(r, svc)
}

func resolveAbsoluteTarget(r *http.Request, svc *config.ServiceConfig) (*targetInfo, int, string, string) {
    raw := r.Header.Get("X-Target-URL")
    if raw == "" {
        return nil, http.StatusBadRequest, "missing_target_url",
            "X-Target-URL header is required for this service."
    }

    parsed, err := url.Parse(raw)
    if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
        return nil, http.StatusBadRequest, "invalid_target_url",
            "X-Target-URL must be a valid http/https URL."
    }

    if !domainAllowed(parsed.Host, svc.AllowedDomains) {
        return nil, http.StatusForbidden, "domain_not_allowed",
            "This domain is not permitted for the current run."
    }

    if len(svc.AllowedPaths) > 0 && !pathAllowed(parsed.Path, svc.AllowedPaths) {
        return nil, http.StatusForbidden, "path_not_allowed",
            "This path is not permitted for the current run."
    }

    return &targetInfo{URL: raw, LogPath: raw}, 0, "", ""
}

func resolvePathTarget(r *http.Request, svc *config.ServiceConfig) (*targetInfo, int, string, string) {
    targetPath := strings.TrimPrefix(r.URL.Path, "/proxy")
    if targetPath == "" {
        targetPath = "/"
    }

    if !pathAllowed(targetPath, svc.AllowedPaths) {
        return nil, http.StatusForbidden, "path_not_allowed",
            "This path is not permitted for the current run."
    }

    logPath := targetPath
    if r.URL.RawQuery != "" {
        logPath = targetPath + "?" + r.URL.RawQuery
    }

    baseURL := strings.TrimRight(svc.BaseURL, "/")
    targetURL := baseURL + targetPath
    if r.URL.RawQuery != "" {
        targetURL += "?" + r.URL.RawQuery
    }

    return &targetInfo{URL: targetURL, LogPath: logPath}, 0, "", ""
}

// domainAllowed checks whether a hostname matches the allowed domains list.
// Empty list = all domains allowed. "*." prefix matches any subdomain.
func domainAllowed(host string, allowedDomains []string) bool {
    if len(allowedDomains) == 0 {
        return true
    }
    if idx := strings.LastIndex(host, ":"); idx != -1 {
        host = host[:idx]
    }
    host = strings.ToLower(host)
    for _, pattern := range allowedDomains {
        pattern = strings.ToLower(pattern)
        if strings.HasPrefix(pattern, "*.") {
            suffix := pattern[1:] // ".github.com"
            if host == pattern[2:] || strings.HasSuffix(host, suffix) {
                return true
            }
        } else if host == pattern {
            return true
        }
    }
    return false
}
```

### 3. Proxy handler — `internal/server/proxy.go`

**Replace steps 4 + 8** with a call to `resolveTarget()`:

```go
// 4. Resolve target URL
target, errCode, errType, errMsg := resolveTarget(r, &svc)
if target == nil {
    s.log.Debug("proxy request rejected: %s for run %s", errType, run.ID)
    jsonError(w, errCode, errType, errMsg)
    return
}
```

**Step 8**: Remove the old `baseURL + targetPath` construction (lines 182-186). Use `target.URL` directly:
```go
upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.URL, bodyReader)
```

**Step 5**: Use `target.LogPath` instead of computing `logPath`:
```go
dedupKey := store.DedupKey(r.Method, target.LogPath, reqBody)
```

**Step 11**: Use `target.LogPath` in log entry:
```go
logEntry := &store.RequestEntry{
    ...
    Path: target.LogPath,
    ...
}
```

**Header forwarding** (line 216): add `X-Target-URL` to skip list:
```go
if hopByHopHeaders[key] || key == "X-Run-Token" || key == "X-Target-URL" {
```

**Net result**: `proxy.go` gets shorter (steps 4+8 replaced by 5-line call), while `target.go` is ~90 lines of focused, testable logic.

### 4. Crawl-space — `~/Development/crawl-space/internal/proxy/proxy.go`

**`ServiceMeta`** — add fields:
```go
AllowAbsoluteURLs bool
AllowedDomains    []string
```

**`pocketConfig`** services struct — add YAML fields:
```go
AllowAbsoluteURLs bool     `yaml:"allow_absolute_urls"`
AllowedDomains    []string `yaml:"allowed_domains"`
```

**`NewManager`** — extract new fields in the service loop.

**`PreambleSuffix`** — conditional branch:
- Absolute URL mode: show proxy endpoint, X-Target-URL usage, curl example, allowed domains
- Standard mode: existing base_url + allowed_paths text (unchanged)

---

## Files to modify

### pocket-proxy (`~/Development/pocket-proxy`)

| File | Action | Lines |
|------|--------|-------|
| `internal/config/config.go` | **Edit** — add fields to `ServiceConfig`, relax validation | ~134 → ~150 |
| `internal/config/config_test.go` | **Edit** — add 5 config validation tests | ~486 → ~560 |
| `internal/server/target.go` | **New** — `resolveTarget()`, `domainAllowed()`, `targetInfo` | ~90 |
| `internal/server/target_test.go` | **New** — table-driven unit tests for target resolution + domain matching | ~150 |
| `internal/server/proxy.go` | **Edit** — replace steps 4+8 with `resolveTarget()` call, strip header | ~323 → ~300 |
| `internal/server/server_test.go` | **Edit** — add test services to `setupTest`, add integration tests | ~1325 → ~1450 |

### crawl-space (`~/Development/crawl-space`)

| File | Action | Lines |
|------|--------|-------|
| `internal/proxy/proxy.go` | **Edit** — add fields, update preamble | ~312 → ~340 |

---

## Testing plan

### `internal/server/target_test.go` (new, unit tests — no server needed)

**`TestDomainAllowed`** — table-driven:
- `("api.github.com", ["api.github.com"])` → true
- `("evil.com", ["api.github.com"])` → false
- `("api.github.com", ["*.github.com"])` → true
- `("github.com", ["*.github.com"])` → true (bare domain)
- `("sub.api.github.com", ["*.github.com"])` → true
- `("evil.com", ["*.github.com"])` → false
- `("anything.com", [])` → true (empty = allow all)
- `("API.GITHUB.COM", ["api.github.com"])` → true (case insensitive)
- `("api.github.com:443", ["api.github.com"])` → true (port stripped)

**`TestResolveAbsoluteTarget`** — table-driven with `httptest.NewRequest`:
- Valid URL → returns `targetInfo` with URL and LogPath
- Missing header → error 400 `missing_target_url`
- Invalid URL → error 400 `invalid_target_url`
- FTP scheme → error 400
- Blocked domain → error 403 `domain_not_allowed`
- With allowed_paths set, blocked path → error 403

**`TestResolvePathTarget`** — table-driven:
- Valid path → returns `targetInfo` with constructed URL
- Blocked path → error 403
- Query string preserved in URL and logPath

### `internal/config/config_test.go` (pocket-proxy)

- `TestAllowAbsoluteURLsValid` — `allow_absolute_urls: true`, no base_url, no paths → passes
- `TestAllowAbsoluteURLsWithDomains` — with `allowed_domains` → passes
- `TestAllowAbsoluteURLsWithBaseURLNoPaths` — base_url set but no paths → error
- `TestStandardModeStillRequiresBaseURL` — regression check
- `TestStandardModeStillRequiresPaths` — regression check

### `internal/server/server_test.go` (integration tests)

Add `absolute-url-svc` and `domain-filtered-svc` to `setupTest`.

New integration tests (use full proxy roundtrip with `testEnv`):
- `TestAbsoluteURLProxySuccess` — 200, body forwarded, credential injected, budget counted
- `TestAbsoluteURLMissingHeader` → 400
- `TestAbsoluteURLDomainFiltering` → 200 for allowed, 403 for blocked
- `TestAbsoluteURLBudgetTracking` — exhaust budget → 429
- `TestAbsoluteURLDedup` — second identical request returns cached
- `TestAbsoluteURLHeadersNotForwarded` — X-Run-Token and X-Target-URL stripped
- `TestAbsoluteURLLogPath` — admin API shows full URL in request log

---

## Verification

```bash
# pocket-proxy
cd ~/Development/pocket-proxy
go vet ./...
go build ./...
go test ./... -race

# crawl-space
cd ~/Development/crawl-space
go vet ./...
go build ./...
go test ./... -race
```
