package server

import (
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

// hop-by-hop headers that should not be forwarded
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Transfer-Encoding":   true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Upgrade":             true,
}

func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Extract and validate run token
	token := r.Header.Get("X-Run-Token")
	if token == "" {
		jsonError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid run token.")
		return
	}

	run, err := s.store.GetRunByToken(token)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to look up run.")
		return
	}
	if run == nil {
		jsonError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid run token.")
		return
	}

	// 2. Look up service config
	svc, ok := s.cfg.Services[run.Service]
	if !ok {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Service configuration not found.")
		return
	}

	// 3. Check run status
	if run.Status != "active" {
		jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		return
	}
	if time.Now().UTC().After(run.ExpiresAt) {
		jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		return
	}

	// 4. Extract and validate target path
	targetPath := strings.TrimPrefix(r.URL.Path, "/proxy")
	if targetPath == "" {
		targetPath = "/"
	}

	if !pathAllowed(targetPath, svc.AllowedPaths) {
		jsonError(w, http.StatusForbidden, "path_not_allowed", "This path is not permitted for the current run.")
		return
	}

	// 5. Build dedup key and check for cached response
	logPath := targetPath
	if r.URL.RawQuery != "" {
		logPath = targetPath + "?" + r.URL.RawQuery
	}
	dedupKey := store.DedupKey(r.Method, logPath)

	if svc.DedupEnabled && svc.StoreResponses {
		entry, err := s.store.FindDedupEntry(run.ID, dedupKey)
		if err == nil && entry != nil && entry.ResponseBody != nil {
			setBudgetHeaders(w, run.RequestsUsed, svc.MaxRequests)
			w.Header().Set("X-Dedup", "true")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(entry.StatusCode)
			w.Write(entry.ResponseBody)
			return
		}
	}

	// 6. Check budget - atomic reserve
	if run.RequestsUsed >= svc.MaxRequests {
		w.Header().Set("Content-Type", "application/json")
		setBudgetHeaders(w, run.RequestsUsed, svc.MaxRequests)
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":          "budget_exhausted",
			"message":        fmt.Sprintf("Run has reached its request limit (%d/%d).", svc.MaxRequests, svc.MaxRequests),
			"requests_used":  run.RequestsUsed,
			"max_requests":   svc.MaxRequests,
		})
		return
	}

	newCount, err := s.store.ReserveRequest(run.ID, svc.MaxRequests)
	if err != nil {
		switch err {
		case store.ErrBudgetExhausted:
			w.Header().Set("Content-Type", "application/json")
			setBudgetHeaders(w, svc.MaxRequests, svc.MaxRequests)
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":          "budget_exhausted",
				"message":        fmt.Sprintf("Run has reached its request limit (%d/%d).", svc.MaxRequests, svc.MaxRequests),
				"requests_used":  svc.MaxRequests,
				"max_requests":   svc.MaxRequests,
			})
		case store.ErrRunNotActive:
			jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		case store.ErrRunExpired:
			jsonError(w, http.StatusForbidden, "run_terminated", "This run has been revoked or has expired.")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to process request.")
		}
		return
	}

	// 7. Build and send upstream request
	baseURL := strings.TrimRight(svc.BaseURL, "/")
	targetURL := baseURL + targetPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		s.store.ReleaseRequest(run.ID)
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to create upstream request.")
		return
	}

	// Forward request headers (except hop-by-hop and token)
	for key, values := range r.Header {
		if hopByHopHeaders[key] || key == "X-Run-Token" {
			continue
		}
		for _, v := range values {
			upstreamReq.Header.Add(key, v)
		}
	}

	// Inject credential
	cred := s.cfg.Credentials[svc.Credential]
	upstreamReq.Header.Set(cred.Header, cred.Value)

	resp, err := proxyClient.Do(upstreamReq)
	if err != nil {
		s.store.ReleaseRequest(run.ID)
		jsonError(w, http.StatusBadGateway, "upstream_error", "Failed to reach upstream service.")
		return
	}
	defer resp.Body.Close()

	// 8. Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.store.ReleaseRequest(run.ID)
		jsonError(w, http.StatusBadGateway, "upstream_error", "Failed to read upstream response.")
		return
	}

	// 9. Determine if this counts against budget
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	counted := is2xx

	if !is2xx {
		// Non-2xx: release the reservation
		s.store.ReleaseRequest(run.ID)
		newCount = newCount - 1
	}

	// 10. Log the request
	logEntry := &store.RequestEntry{
		RunID:      run.ID,
		Method:     r.Method,
		Path:       logPath,
		StatusCode: resp.StatusCode,
		Counted:    counted,
		DedupKey:   dedupKey,
	}

	// Store response body if applicable
	if counted && svc.StoreResponses && len(body) <= store.MaxResponseStoreSize {
		logEntry.ResponseBody = body
	}

	s.store.LogRequest(logEntry)

	// 11. Forward upstream response to agent
	for key, values := range resp.Header {
		if hopByHopHeaders[key] || key == "Content-Length" {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	setBudgetHeaders(w, newCount, svc.MaxRequests)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func setBudgetHeaders(w http.ResponseWriter, used, total int) {
	w.Header().Set("X-Budget-Used", strconv.Itoa(used))
	w.Header().Set("X-Budget-Remaining", strconv.Itoa(total-used))
	w.Header().Set("X-Budget-Total", strconv.Itoa(total))
}
