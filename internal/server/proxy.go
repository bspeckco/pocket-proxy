package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pocket-proxy/internal/store"
)

var proxyClient = &http.Client{
	Timeout: 30 * time.Second,
}

// hop-by-hop headers that should not be forwarded (RFC 7230)
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Transfer-Encoding":   true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Upgrade":             true,
}

// maxProxyReadSize is the maximum response body the proxy will read from upstream.
// Responses exceeding this are truncated (the agent still gets up to this much).
const maxProxyReadSize = 10 << 20 // 10MB

func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Extract and validate run token
	token := r.Header.Get("X-Run-Token")
	if token == "" {
		s.log.Debug("proxy request rejected: missing X-Run-Token")
		jsonError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid run token.")
		return
	}

	run, err := s.store.GetRunByToken(token)
	if err != nil {
		s.log.Error("failed to look up run by token: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to look up run.")
		return
	}
	if run == nil {
		s.log.Debug("proxy request rejected: unknown token")
		jsonError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid run token.")
		return
	}

	// 2. Look up service config
	svc, ok := s.cfg.Services[run.Service]
	if !ok {
		s.log.Error("service %q not found in config for run %s", run.Service, run.ID)
		jsonError(w, http.StatusInternalServerError, "internal_error", "Service configuration not found.")
		return
	}

	// 3. Check run status
	if run.Status == "exhausted" {
		s.log.Debug("proxy request rejected: run %s budget exhausted", run.ID)
		w.Header().Set("Content-Type", "application/json")
		setBudgetHeaders(w, run.RequestsUsed, svc.MaxRequests)
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "budget_exhausted",
			"message":       fmt.Sprintf("Run has reached its request limit (%d/%d).", svc.MaxRequests, svc.MaxRequests),
			"requests_used": run.RequestsUsed,
			"max_requests":  svc.MaxRequests,
		})
		return
	}
	if run.Status != "active" {
		s.log.Debug("proxy request rejected: run %s status is %s", run.ID, run.Status)
		jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		return
	}
	if time.Now().UTC().After(run.ExpiresAt) {
		s.log.Debug("proxy request rejected: run %s has expired", run.ID)
		jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		return
	}

	// 4. Extract and validate target path
	targetPath := strings.TrimPrefix(r.URL.Path, "/proxy")
	if targetPath == "" {
		targetPath = "/"
	}

	if !pathAllowed(targetPath, svc.AllowedPaths) {
		s.log.Debug("proxy request rejected: path %q not allowed for run %s", targetPath, run.ID)
		jsonError(w, http.StatusForbidden, "path_not_allowed", "This path is not permitted for the current run.")
		return
	}

	// 5. Build log path and dedup key
	logPath := targetPath
	if r.URL.RawQuery != "" {
		logPath = targetPath + "?" + r.URL.RawQuery
	}

	// Read request body for dedup and forwarding (bounded to prevent memory exhaustion)
	var reqBody []byte
	if r.Body != nil {
		reqBody, err = io.ReadAll(io.LimitReader(r.Body, maxProxyReadSize))
		if err != nil {
			s.log.Warn("failed to read request body for run %s: %v", run.ID, err)
			jsonError(w, http.StatusBadRequest, "bad_request", "Failed to read request body.")
			return
		}
	}

	dedupKey := store.DedupKey(r.Method, logPath, reqBody)

	// 6. Check for cached dedup response
	if svc.DedupEnabled && svc.StoreResponses {
		entry, err := s.store.FindDedupEntry(run.ID, dedupKey)
		if err == nil && entry != nil && entry.ResponseBody != nil {
			s.log.Debug("dedup hit for run %s: %s %s", run.ID, r.Method, logPath)
			setBudgetHeaders(w, run.RequestsUsed, svc.MaxRequests)
			w.Header().Set("X-Dedup", "true")
			ct := entry.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			w.Header().Set("Content-Type", ct)
			w.WriteHeader(entry.StatusCode)
			w.Write(entry.ResponseBody)
			return
		}
	}

	// 7. Check budget - atomic reserve
	if run.RequestsUsed >= svc.MaxRequests {
		s.log.Debug("proxy request rejected: run %s budget check failed (%d/%d)", run.ID, run.RequestsUsed, svc.MaxRequests)
		w.Header().Set("Content-Type", "application/json")
		setBudgetHeaders(w, run.RequestsUsed, svc.MaxRequests)
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "budget_exhausted",
			"message":       fmt.Sprintf("Run has reached its request limit (%d/%d).", svc.MaxRequests, svc.MaxRequests),
			"requests_used": run.RequestsUsed,
			"max_requests":  svc.MaxRequests,
		})
		return
	}

	newCount, err := s.store.ReserveRequest(run.ID, svc.MaxRequests)
	if err != nil {
		switch err {
		case store.ErrBudgetExhausted:
			s.log.Debug("proxy request rejected: run %s budget exhausted on reserve", run.ID)
			w.Header().Set("Content-Type", "application/json")
			setBudgetHeaders(w, svc.MaxRequests, svc.MaxRequests)
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":         "budget_exhausted",
				"message":       fmt.Sprintf("Run has reached its request limit (%d/%d).", svc.MaxRequests, svc.MaxRequests),
				"requests_used": svc.MaxRequests,
				"max_requests":  svc.MaxRequests,
			})
		case store.ErrRunNotActive:
			s.log.Debug("proxy request rejected: run %s not active on reserve", run.ID)
			jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		case store.ErrRunExpired:
			s.log.Debug("proxy request rejected: run %s expired on reserve", run.ID)
			jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		default:
			s.log.Error("failed to reserve request for run %s: %v", run.ID, err)
			jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to process request.")
		}
		return
	}

	// 8. Build and send upstream request
	baseURL := strings.TrimRight(svc.BaseURL, "/")
	targetURL := baseURL + targetPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	s.log.Info("proxy %s %s -> %s (run=%s, budget=%d/%d)", r.Method, logPath, run.Service, run.ID, newCount, svc.MaxRequests)
	s.log.Debug("upstream url: %s", targetURL)

	// Log inbound request headers
	for key, values := range r.Header {
		for _, v := range values {
			s.log.Trace("inbound header: %s: %s", key, v)
		}
	}

	var bodyReader io.Reader
	if len(reqBody) > 0 {
		bodyReader = bytes.NewReader(reqBody)
		s.log.Debug("request body: %d bytes", len(reqBody))
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bodyReader)
	if err != nil {
		s.log.Error("failed to create upstream request for run %s: %v", run.ID, err)
		if _, releaseErr := s.store.ReleaseRequest(run.ID); releaseErr != nil {
			s.log.Error("failed to release request for run %s: %v", run.ID, releaseErr)
		}
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to create upstream request.")
		return
	}

	// Forward request headers (except hop-by-hop and token)
	for key, values := range r.Header {
		if hopByHopHeaders[key] || key == "X-Run-Token" {
			s.log.Trace("skipping inbound header: %s", key)
			continue
		}
		for _, v := range values {
			upstreamReq.Header.Add(key, v)
		}
	}

	// Inject credential
	cred := s.cfg.Credentials[svc.Credential]
	upstreamReq.Header.Set(cred.Header, cred.Value)

	// Log all outbound headers (includes injected credential)
	for key, values := range upstreamReq.Header {
		for _, v := range values {
			s.log.Trace("upstream header: %s: %s", key, v)
		}
	}

	resp, err := proxyClient.Do(upstreamReq)
	if err != nil {
		s.log.Warn("upstream error for run %s: %v", run.ID, err)
		if _, releaseErr := s.store.ReleaseRequest(run.ID); releaseErr != nil {
			s.log.Error("failed to release request for run %s: %v", run.ID, releaseErr)
		}
		jsonError(w, http.StatusBadGateway, "upstream_error", "Failed to reach upstream service.")
		return
	}
	defer resp.Body.Close()

	// 9. Read response body (bounded)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyReadSize))
	if err != nil {
		s.log.Warn("failed to read upstream response for run %s: %v", run.ID, err)
		if _, releaseErr := s.store.ReleaseRequest(run.ID); releaseErr != nil {
			s.log.Error("failed to release request for run %s: %v", run.ID, releaseErr)
		}
		jsonError(w, http.StatusBadGateway, "upstream_error", "Failed to read upstream response.")
		return
	}

	s.log.Debug("upstream response: %d, %d bytes", resp.StatusCode, len(body))
	for key, values := range resp.Header {
		for _, v := range values {
			s.log.Trace("response header: %s: %s", key, v)
		}
	}

	// 10. Determine if this counts against budget
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	counted := is2xx

	if !is2xx {
		// Non-2xx: release the reservation and use the actual DB count
		s.log.Debug("non-2xx response (%d), releasing budget reservation for run %s", resp.StatusCode, run.ID)
		releasedCount, releaseErr := s.store.ReleaseRequest(run.ID)
		if releaseErr != nil {
			s.log.Error("failed to release request for run %s: %v", run.ID, releaseErr)
		} else {
			newCount = releasedCount
		}
	}

	// 11. Log the request
	contentType := resp.Header.Get("Content-Type")
	logEntry := &store.RequestEntry{
		RunID:       run.ID,
		Method:      r.Method,
		Path:        logPath,
		StatusCode:  resp.StatusCode,
		Counted:     counted,
		DedupKey:    dedupKey,
		ContentType: contentType,
	}

	// Store response body if applicable
	if counted && svc.StoreResponses && len(body) <= s.store.MaxRespSize() {
		logEntry.ResponseBody = body
	}

	if logErr := s.store.LogRequest(logEntry); logErr != nil {
		s.log.Error("failed to log request for run %s: %v", run.ID, logErr)
	}

	// 12. Forward upstream response to agent
	for key, values := range resp.Header {
		if hopByHopHeaders[key] || key == "Content-Length" {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// Set accurate Content-Length from the buffered body
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))

	setBudgetHeaders(w, newCount, svc.MaxRequests)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func setBudgetHeaders(w http.ResponseWriter, used, total int) {
	w.Header().Set("X-Budget-Used", strconv.Itoa(used))
	w.Header().Set("X-Budget-Remaining", strconv.Itoa(total-used))
	w.Header().Set("X-Budget-Total", strconv.Itoa(total))
}
