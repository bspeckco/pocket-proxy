package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pocket-proxy/internal/config"
	"pocket-proxy/internal/store"
)

type testEnv struct {
	server          *Server
	proxy           *httptest.Server
	upstream        *httptest.Server
	store           *store.Store
	cfg             *config.Config
	upstreamHandler func(w http.ResponseWriter, r *http.Request)
}

func setupTest(t *testing.T) *testEnv {
	t.Helper()

	env := &testEnv{}

	// Default upstream handler: return 200 with JSON
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}

	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.upstreamHandler(w, r)
	}))

	env.cfg = &config.Config{
		Admin: config.AdminConfig{
			Secret: "test-admin-secret",
			Port:   9999,
		},
		Credentials: map[string]config.CredentialConfig{
			"test-cred": {
				Header: "Authorization",
				Value:  "Bearer upstream-api-key",
			},
		},
		Services: map[string]config.ServiceConfig{
			"test-svc": {
				BaseURL:          env.upstream.URL,
				Credential:       "test-cred",
				AllowedPaths:     []string{"/test", "/wildcard/*"},
				MaxRequests:      5,
				DedupEnabled:     true,
				StoreResponses:   true,
				ExpiresInSeconds: 3600,
			},
			"no-dedup-svc": {
				BaseURL:          env.upstream.URL,
				Credential:       "test-cred",
				AllowedPaths:     []string{"/test"},
				MaxRequests:      10,
				DedupEnabled:     false,
				StoreResponses:   false,
				ExpiresInSeconds: 3600,
			},
			"short-lived-svc": {
				BaseURL:          env.upstream.URL,
				Credential:       "test-cred",
				AllowedPaths:     []string{"/test"},
				MaxRequests:      10,
				DedupEnabled:     false,
				StoreResponses:   false,
				ExpiresInSeconds: 1,
			},
		},
	}

	var err error
	env.store, err = store.New()
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	env.server = New(env.cfg, env.store)
	env.proxy = httptest.NewServer(env.server)

	t.Cleanup(func() {
		env.upstream.Close()
		env.proxy.Close()
		env.store.Close()
	})

	return env
}

func adminReq(env *testEnv, method, path string, body string) *http.Response {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, env.proxy.URL+path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+env.cfg.Admin.Secret)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func proxyReq(env *testEnv, method, path, token string) *http.Response {
	req, _ := http.NewRequest(method, env.proxy.URL+"/proxy"+path, nil)
	if token != "" {
		req.Header.Set("X-Run-Token", token)
	}
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func proxyReqWithBody(env *testEnv, method, path, token, body string) *http.Response {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, env.proxy.URL+"/proxy"+path, bodyReader)
	if token != "" {
		req.Header.Set("X-Run-Token", token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func createRun(t *testing.T, env *testEnv, service string) (runID, token string) {
	t.Helper()
	resp := adminReq(env, "POST", "/admin/runs", fmt.Sprintf(`{"service":"%s"}`, service))
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, body)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return result["run_id"].(string), result["token"].(string)
}

func readJSON(resp *http.Response) map[string]interface{} {
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return result
}

// --- Admin API Tests ---

func TestAdminAuthRequired(t *testing.T) {
	env := setupTest(t)

	// No auth header
	req, _ := http.NewRequest("POST", env.proxy.URL+"/admin/runs", strings.NewReader(`{"service":"test-svc"}`))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong secret
	req, _ = http.NewRequest("POST", env.proxy.URL+"/admin/runs", strings.NewReader(`{"service":"test-svc"}`))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// No Bearer prefix
	req, _ = http.NewRequest("POST", env.proxy.URL+"/admin/runs", strings.NewReader(`{"service":"test-svc"}`))
	req.Header.Set("Authorization", env.cfg.Admin.Secret)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCreateRun(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "POST", "/admin/runs", `{"service":"test-svc"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	result := readJSON(resp)

	if result["run_id"] == nil || result["run_id"].(string) == "" {
		t.Error("expected non-empty run_id")
	}
	if result["token"] == nil || result["token"].(string) == "" {
		t.Error("expected non-empty token")
	}
	if result["proxy_url"] == nil {
		t.Error("expected proxy_url")
	}
}

func TestCreateRunUnknownService(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "POST", "/admin/runs", `{"service":"nonexistent"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCreateRunInvalidJSON(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "POST", "/admin/runs", `{bad json}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGetRun(t *testing.T) {
	env := setupTest(t)

	runID, _ := createRun(t, env, "test-svc")

	resp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	result := readJSON(resp)

	if result["run_id"].(string) != runID {
		t.Errorf("expected run_id %q, got %q", runID, result["run_id"])
	}
	if result["service"].(string) != "test-svc" {
		t.Errorf("expected service 'test-svc', got %q", result["service"])
	}
	if result["status"].(string) != "active" {
		t.Errorf("expected status 'active', got %q", result["status"])
	}
	if int(result["requests_used"].(float64)) != 0 {
		t.Errorf("expected requests_used 0, got %v", result["requests_used"])
	}
	if int(result["max_requests"].(float64)) != 5 {
		t.Errorf("expected max_requests 5, got %v", result["max_requests"])
	}
	requests := result["requests"].([]interface{})
	if len(requests) != 0 {
		t.Errorf("expected 0 requests, got %d", len(requests))
	}
}

func TestGetRunNotFound(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "GET", "/admin/runs/nonexistent", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGetResponses(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":"test-response"}`))
	}

	runID, token := createRun(t, env, "test-svc")

	// Make a proxy request to store a response
	proxyReq(env, "GET", "/test", token)

	resp := adminReq(env, "GET", "/admin/runs/"+runID+"/responses", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	result := readJSON(resp)

	responses := result["responses"].([]interface{})
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	respEntry := responses[0].(map[string]interface{})
	if respEntry["response_body"].(string) != `{"data":"test-response"}` {
		t.Errorf("unexpected response body: %s", respEntry["response_body"])
	}
}

func TestGetResponsesNotFound(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "GET", "/admin/runs/nonexistent/responses", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCloseRunPurge(t *testing.T) {
	env := setupTest(t)

	runID, token := createRun(t, env, "test-svc")

	// Make a request first
	proxyReq(env, "GET", "/test", token)

	// Close with purge (default)
	resp := adminReq(env, "POST", "/admin/runs/"+runID+"/close", `{}`)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	result := readJSON(resp)
	if result["status"].(string) != "closed" {
		t.Errorf("expected status 'closed', got %q", result["status"])
	}

	// Run should be gone
	getResp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 after purge, got %d", getResp.StatusCode)
	}
	getResp.Body.Close()
}

func TestCloseRunFlush(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"flushed":"data"}`))
	}

	runID, token := createRun(t, env, "test-svc")

	// Make a request
	proxyReq(env, "GET", "/test", token)

	// Close with flush
	dir := t.TempDir()
	flushPath := filepath.Join(dir, "output.json")
	resp := adminReq(env, "POST", "/admin/runs/"+runID+"/close",
		fmt.Sprintf(`{"mode":"flush","path":"%s"}`, flushPath))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Check the flushed file exists and contains data
	data, err := os.ReadFile(flushPath)
	if err != nil {
		t.Fatalf("failed to read flush file: %v", err)
	}

	var flushed map[string]interface{}
	if err := json.Unmarshal(data, &flushed); err != nil {
		t.Fatalf("failed to parse flush file: %v", err)
	}
	if flushed["run_id"].(string) != runID {
		t.Errorf("expected run_id %q in flush, got %q", runID, flushed["run_id"])
	}

	requests := flushed["requests"].([]interface{})
	if len(requests) != 1 {
		t.Errorf("expected 1 request in flush, got %d", len(requests))
	}

	// Run should be gone
	getResp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 after flush, got %d", getResp.StatusCode)
	}
	getResp.Body.Close()
}

func TestCloseRunFlushMissingPath(t *testing.T) {
	env := setupTest(t)

	runID, _ := createRun(t, env, "test-svc")

	resp := adminReq(env, "POST", "/admin/runs/"+runID+"/close", `{"mode":"flush"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for flush without path, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCloseRunNotFound(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "POST", "/admin/runs/nonexistent/close", `{}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRevokeRun(t *testing.T) {
	env := setupTest(t)

	runID, _ := createRun(t, env, "test-svc")

	resp := adminReq(env, "DELETE", "/admin/runs/"+runID, "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	result := readJSON(resp)
	if result["status"].(string) != "revoked" {
		t.Errorf("expected status 'revoked', got %q", result["status"])
	}

	// Verify run status is revoked
	getResp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	getResult := readJSON(getResp)
	if getResult["status"].(string) != "revoked" {
		t.Errorf("expected revoked status, got %q", getResult["status"])
	}
}

func TestRevokeRunNotFound(t *testing.T) {
	env := setupTest(t)

	resp := adminReq(env, "DELETE", "/admin/runs/nonexistent", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- Proxy API Tests ---

func TestProxyNoToken(t *testing.T) {
	env := setupTest(t)

	resp := proxyReq(env, "GET", "/test", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	result := readJSON(resp)
	if result["error"].(string) != "unauthorized" {
		t.Errorf("expected 'unauthorized' error, got %q", result["error"])
	}
}

func TestProxyInvalidToken(t *testing.T) {
	env := setupTest(t)

	resp := proxyReq(env, "GET", "/test", "invalid-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestProxyDisallowedPath(t *testing.T) {
	env := setupTest(t)

	_, token := createRun(t, env, "test-svc")

	resp := proxyReq(env, "GET", "/not-allowed", token)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	result := readJSON(resp)
	if result["error"].(string) != "path_not_allowed" {
		t.Errorf("expected 'path_not_allowed' error, got %q", result["error"])
	}
}

func TestProxySuccess(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Write([]byte(`{"result":"success"}`))
	}

	_, token := createRun(t, env, "test-svc")

	resp := proxyReq(env, "GET", "/test?q=hello", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Check response body
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"result":"success"}` {
		t.Errorf("unexpected body: %s", body)
	}

	// Check custom header is forwarded
	if resp.Header.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("expected X-Custom-Header, got %q", resp.Header.Get("X-Custom-Header"))
	}

	// Check budget headers
	if resp.Header.Get("X-Budget-Used") != "1" {
		t.Errorf("expected X-Budget-Used=1, got %q", resp.Header.Get("X-Budget-Used"))
	}
	if resp.Header.Get("X-Budget-Remaining") != "4" {
		t.Errorf("expected X-Budget-Remaining=4, got %q", resp.Header.Get("X-Budget-Remaining"))
	}
	if resp.Header.Get("X-Budget-Total") != "5" {
		t.Errorf("expected X-Budget-Total=5, got %q", resp.Header.Get("X-Budget-Total"))
	}
}

func TestProxyCredentialInjection(t *testing.T) {
	env := setupTest(t)

	var receivedAuth string
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}

	_, token := createRun(t, env, "test-svc")
	resp := proxyReq(env, "GET", "/test", token)
	resp.Body.Close()

	if receivedAuth != "Bearer upstream-api-key" {
		t.Errorf("expected credential injection, got Authorization: %q", receivedAuth)
	}
}

func TestProxyTokenNotForwarded(t *testing.T) {
	env := setupTest(t)

	var receivedToken string
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Run-Token")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}

	_, token := createRun(t, env, "test-svc")
	resp := proxyReq(env, "GET", "/test", token)
	resp.Body.Close()

	if receivedToken != "" {
		t.Errorf("X-Run-Token should not be forwarded to upstream, got %q", receivedToken)
	}
}

func TestProxyBudgetExhausted(t *testing.T) {
	env := setupTest(t)

	_, token := createRun(t, env, "test-svc") // max_requests = 5

	// Use all 5 requests (unique queries to avoid dedup)
	for i := 0; i < 5; i++ {
		resp := proxyReq(env, "GET", fmt.Sprintf("/test?i=%d", i), token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// 6th should be rejected
	resp := proxyReq(env, "GET", "/test?i=6", token)
	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 429, got %d; body: %s", resp.StatusCode, body)
	}
	result := readJSON(resp)
	if result["error"].(string) != "budget_exhausted" {
		t.Errorf("expected 'budget_exhausted' error, got %q", result["error"])
	}
	if int(result["requests_used"].(float64)) != 5 {
		t.Errorf("expected requests_used=5, got %v", result["requests_used"])
	}

	// Check budget headers on 429
	if resp.Header.Get("X-Budget-Used") != "5" {
		t.Errorf("expected X-Budget-Used=5, got %q", resp.Header.Get("X-Budget-Used"))
	}
	if resp.Header.Get("X-Budget-Remaining") != "0" {
		t.Errorf("expected X-Budget-Remaining=0, got %q", resp.Header.Get("X-Budget-Remaining"))
	}
}

func TestProxyNon2xxDoesNotCount(t *testing.T) {
	env := setupTest(t)

	callCount := 0
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"upstream error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}

	runID, token := createRun(t, env, "test-svc")

	// Make 3 failing requests
	for i := 0; i < 3; i++ {
		resp := proxyReq(env, "GET", "/test", token)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("request %d: expected 500, got %d", i+1, resp.StatusCode)
		}
		// Budget should still be 0 used
		if resp.Header.Get("X-Budget-Used") != "0" {
			t.Errorf("request %d: expected X-Budget-Used=0, got %q", i+1, resp.Header.Get("X-Budget-Used"))
		}
		resp.Body.Close()
	}

	// 4th request succeeds
	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Budget-Used") != "1" {
		t.Errorf("expected X-Budget-Used=1 after first success, got %q", resp.Header.Get("X-Budget-Used"))
	}
	resp.Body.Close()

	// Verify via admin API
	adminResp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	result := readJSON(adminResp)
	if int(result["requests_used"].(float64)) != 1 {
		t.Errorf("expected 1 requests_used, got %v", result["requests_used"])
	}

	// All 4 requests should be logged
	requests := result["requests"].([]interface{})
	if len(requests) != 4 {
		t.Errorf("expected 4 logged requests, got %d", len(requests))
	}

	// First 3 should not be counted
	for i := 0; i < 3; i++ {
		req := requests[i].(map[string]interface{})
		if req["counted"].(bool) != false {
			t.Errorf("request %d should not be counted", i+1)
		}
	}
	// 4th should be counted
	req := requests[3].(map[string]interface{})
	if req["counted"].(bool) != true {
		t.Error("4th request should be counted")
	}
}

func TestProxy4xxDoesNotCount(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}

	_, token := createRun(t, env, "test-svc")

	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Budget-Used") != "0" {
		t.Errorf("expected X-Budget-Used=0, got %q", resp.Header.Get("X-Budget-Used"))
	}
	resp.Body.Close()
}

func TestProxy429UpstreamDoesNotCount(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"rate limited"}`))
	}

	_, token := createRun(t, env, "test-svc")

	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Budget-Used") != "0" {
		t.Errorf("expected X-Budget-Used=0, got %q", resp.Header.Get("X-Budget-Used"))
	}
	resp.Body.Close()
}

func TestProxyDedup(t *testing.T) {
	env := setupTest(t)

	callCount := 0
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"call":%d}`, callCount)))
	}

	_, token := createRun(t, env, "test-svc") // dedup_enabled=true, store_responses=true

	// First request
	resp1 := proxyReq(env, "GET", "/test?q=hello", token)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp1.StatusCode)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if resp1.Header.Get("X-Budget-Used") != "1" {
		t.Errorf("expected X-Budget-Used=1, got %q", resp1.Header.Get("X-Budget-Used"))
	}
	if resp1.Header.Get("X-Dedup") != "" {
		t.Error("first request should not have X-Dedup header")
	}

	// Same request again - should be deduped
	resp2 := proxyReq(env, "GET", "/test?q=hello", token)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.Header.Get("X-Budget-Used") != "1" {
		t.Errorf("dedup: expected X-Budget-Used=1 (unchanged), got %q", resp2.Header.Get("X-Budget-Used"))
	}
	if resp2.Header.Get("X-Dedup") != "true" {
		t.Error("dedup: expected X-Dedup=true header")
	}

	// Body should be the cached response (from first call)
	if string(body2) != string(body1) {
		t.Errorf("dedup: expected same body. got %s vs %s", body1, body2)
	}

	// Upstream should only have been called once
	if callCount != 1 {
		t.Errorf("expected 1 upstream call, got %d", callCount)
	}

	// Different query should not be deduped
	resp3 := proxyReq(env, "GET", "/test?q=world", token)
	resp3.Body.Close()
	if callCount != 2 {
		t.Errorf("expected 2 upstream calls, got %d", callCount)
	}
	if resp3.Header.Get("X-Dedup") != "" {
		t.Error("different query should not be deduped")
	}
}

func TestProxyDedupDifferentMethod(t *testing.T) {
	env := setupTest(t)

	callCount := 0
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}

	_, token := createRun(t, env, "test-svc")

	// GET request
	resp1 := proxyReq(env, "GET", "/test", token)
	resp1.Body.Close()

	// POST to same path - should NOT be deduped (different method)
	resp2 := proxyReqWithBody(env, "POST", "/test", token, `{"data":"x"}`)
	resp2.Body.Close()

	if callCount != 2 {
		t.Errorf("expected 2 upstream calls (different methods), got %d", callCount)
	}
}

func TestProxyRunRevoked(t *testing.T) {
	env := setupTest(t)

	runID, token := createRun(t, env, "test-svc")

	// Revoke
	resp := adminReq(env, "DELETE", "/admin/runs/"+runID, "")
	resp.Body.Close()

	// Try proxy request
	proxyResp := proxyReq(env, "GET", "/test", token)
	if proxyResp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", proxyResp.StatusCode)
	}
	result := readJSON(proxyResp)
	if result["error"].(string) != "run_terminated" {
		t.Errorf("expected 'run_terminated' error, got %q", result["error"])
	}
}

func TestProxyRunExpired(t *testing.T) {
	env := setupTest(t)

	_, token := createRun(t, env, "short-lived-svc") // expires_in_seconds=1

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for expired run, got %d", resp.StatusCode)
	}
	result := readJSON(resp)
	if result["error"].(string) != "run_terminated" {
		t.Errorf("expected 'run_terminated' error, got %q", result["error"])
	}
}

func TestProxyWildcardPath(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"path":"%s"}`, r.URL.Path)))
	}

	_, token := createRun(t, env, "test-svc") // allowed: /test, /wildcard/*

	// Exact match
	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("exact match: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Wildcard match
	resp = proxyReq(env, "GET", "/wildcard/foo", token)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("wildcard /wildcard/foo: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Deep wildcard match
	resp = proxyReq(env, "GET", "/wildcard/foo/bar/baz", token)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("wildcard /wildcard/foo/bar/baz: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Should NOT match /test/extra
	resp = proxyReq(env, "GET", "/test/extra", token)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("/test/extra: expected 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestProxyLargeResponseNotStored(t *testing.T) {
	env := setupTest(t)

	// Generate a response larger than the default max response store size (1MB)
	maxSize := env.store.MaxRespSize()
	largeBody := strings.Repeat("x", maxSize+1)
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(largeBody))
	}

	runID, token := createRun(t, env, "test-svc")

	// Request succeeds and agent gets the full body
	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) != maxSize+1 {
		t.Errorf("expected full body to be returned, got %d bytes", len(body))
	}

	// But response should NOT be stored
	getResp := adminReq(env, "GET", "/admin/runs/"+runID+"/responses", "")
	result := readJSON(getResp)
	responses := result["responses"].([]interface{})
	if len(responses) != 0 {
		t.Errorf("expected 0 stored responses for large body, got %d", len(responses))
	}
}

func TestProxyRequestWithBody(t *testing.T) {
	env := setupTest(t)

	var receivedBody string
	var receivedMethod string
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"received":true}`))
	}

	_, token := createRun(t, env, "test-svc")

	resp := proxyReqWithBody(env, "POST", "/test", token, `{"key":"value"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if receivedMethod != "POST" {
		t.Errorf("expected POST, got %s", receivedMethod)
	}
	if receivedBody != `{"key":"value"}` {
		t.Errorf("expected body forwarded, got %q", receivedBody)
	}
}

func TestProxyUpstreamTargetURL(t *testing.T) {
	env := setupTest(t)

	var receivedPath string
	var receivedQuery string
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}

	_, token := createRun(t, env, "test-svc")

	resp := proxyReq(env, "GET", "/test?q=hello&limit=10", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if receivedPath != "/test" {
		t.Errorf("expected upstream path '/test', got %q", receivedPath)
	}
	if receivedQuery != "q=hello&limit=10" {
		t.Errorf("expected upstream query 'q=hello&limit=10', got %q", receivedQuery)
	}
}

func TestProxyNoDedup(t *testing.T) {
	env := setupTest(t)

	callCount := 0
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}

	_, token := createRun(t, env, "no-dedup-svc") // dedup_enabled=false

	// Same request twice
	resp1 := proxyReq(env, "GET", "/test", token)
	resp1.Body.Close()
	resp2 := proxyReq(env, "GET", "/test", token)
	resp2.Body.Close()

	// Both should hit upstream
	if callCount != 2 {
		t.Errorf("expected 2 upstream calls (no dedup), got %d", callCount)
	}
	if resp2.Header.Get("X-Dedup") != "" {
		t.Error("no-dedup service should not have X-Dedup header")
	}
}

func TestProxyBudgetHeadersOnEveryResponse(t *testing.T) {
	env := setupTest(t)

	_, token := createRun(t, env, "test-svc")

	for i := 0; i < 3; i++ {
		resp := proxyReq(env, "GET", fmt.Sprintf("/test?i=%d", i), token)
		used := resp.Header.Get("X-Budget-Used")
		remaining := resp.Header.Get("X-Budget-Remaining")
		total := resp.Header.Get("X-Budget-Total")
		resp.Body.Close()

		expectedUsed := fmt.Sprintf("%d", i+1)
		expectedRemaining := fmt.Sprintf("%d", 5-(i+1))

		if used != expectedUsed {
			t.Errorf("request %d: expected X-Budget-Used=%s, got %s", i+1, expectedUsed, used)
		}
		if remaining != expectedRemaining {
			t.Errorf("request %d: expected X-Budget-Remaining=%s, got %s", i+1, expectedRemaining, remaining)
		}
		if total != "5" {
			t.Errorf("request %d: expected X-Budget-Total=5, got %s", i+1, total)
		}
	}
}

func TestProxyRunClosedMidSession(t *testing.T) {
	env := setupTest(t)

	runID, token := createRun(t, env, "test-svc")

	// First request works
	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Close the run
	closeResp := adminReq(env, "POST", "/admin/runs/"+runID+"/close", `{}`)
	closeResp.Body.Close()

	// Next proxy request should fail (run data is gone)
	resp = proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 after close (token gone), got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGetRunShowsExpiredStatus(t *testing.T) {
	env := setupTest(t)

	runID, _ := createRun(t, env, "short-lived-svc")

	time.Sleep(1100 * time.Millisecond)

	resp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	result := readJSON(resp)
	if result["status"].(string) != "expired" {
		t.Errorf("expected expired status, got %q", result["status"])
	}
}

func TestGetRunWithRequestLog(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}

	runID, token := createRun(t, env, "test-svc")

	// Make some requests
	proxyReq(env, "GET", "/test?q=1", token).Body.Close()
	proxyReq(env, "GET", "/test?q=2", token).Body.Close()

	// Get run details
	resp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	result := readJSON(resp)

	if int(result["requests_used"].(float64)) != 2 {
		t.Errorf("expected requests_used=2, got %v", result["requests_used"])
	}

	requests := result["requests"].([]interface{})
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests in log, got %d", len(requests))
	}

	req1 := requests[0].(map[string]interface{})
	if req1["method"].(string) != "GET" {
		t.Errorf("expected method GET, got %q", req1["method"])
	}
	if req1["path"].(string) != "/test?q=1" {
		t.Errorf("expected path '/test?q=1', got %q", req1["path"])
	}
	if int(req1["status_code"].(float64)) != 200 {
		t.Errorf("expected status_code 200, got %v", req1["status_code"])
	}
	if req1["counted"].(bool) != true {
		t.Error("expected counted=true")
	}
}

func TestProxyUpstreamConnectionFailure(t *testing.T) {
	env := setupTest(t)

	// Close upstream to simulate connection failure
	env.upstream.Close()

	runID, token := createRun(t, env, "test-svc")

	resp := proxyReq(env, "GET", "/test", token)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", resp.StatusCode)
	}
	result := readJSON(resp)
	if result["error"].(string) != "upstream_error" {
		t.Errorf("expected 'upstream_error', got %q", result["error"])
	}

	// Budget should not have been consumed (reservation was released)
	getResp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	getResult := readJSON(getResp)
	if int(getResult["requests_used"].(float64)) != 0 {
		t.Errorf("expected 0 requests_used after upstream failure, got %v", getResult["requests_used"])
	}
}

func TestProxyDedupPreservesContentType(t *testing.T) {
	env := setupTest(t)

	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("plain text response"))
	}

	_, token := createRun(t, env, "test-svc")

	// First request
	resp1 := proxyReq(env, "GET", "/test", token)
	ct1 := resp1.Header.Get("Content-Type")
	resp1.Body.Close()

	// Second request (dedup)
	resp2 := proxyReq(env, "GET", "/test", token)
	ct2 := resp2.Header.Get("Content-Type")
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.Header.Get("X-Dedup") != "true" {
		t.Error("expected X-Dedup=true on second request")
	}
	if ct2 != ct1 {
		t.Errorf("dedup Content-Type mismatch: original %q, dedup %q", ct1, ct2)
	}
	if string(body2) != "plain text response" {
		t.Errorf("unexpected dedup body: %s", body2)
	}
}

func TestProxyPostDedupIncludesBody(t *testing.T) {
	env := setupTest(t)

	callCount := 0
	env.upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"call":%d}`, callCount)))
	}

	_, token := createRun(t, env, "test-svc")

	// POST with body A
	resp1 := proxyReqWithBody(env, "POST", "/test", token, `{"query":"A"}`)
	resp1.Body.Close()

	// POST with body B (different body, should NOT be deduped)
	resp2 := proxyReqWithBody(env, "POST", "/test", token, `{"query":"B"}`)
	resp2.Body.Close()

	if callCount != 2 {
		t.Errorf("expected 2 upstream calls (different POST bodies), got %d", callCount)
	}

	// POST with body A again (same body, should be deduped)
	resp3 := proxyReqWithBody(env, "POST", "/test", token, `{"query":"A"}`)
	resp3.Body.Close()

	if callCount != 2 {
		t.Errorf("expected 2 upstream calls (same POST body deduped), got %d", callCount)
	}
	if resp3.Header.Get("X-Dedup") != "true" {
		t.Error("expected X-Dedup=true for repeated POST with same body")
	}
}

func TestProxyExhaustedStatusViaAdmin(t *testing.T) {
	env := setupTest(t)

	runID, token := createRun(t, env, "test-svc") // max=5

	// Exhaust budget
	for i := 0; i < 5; i++ {
		resp := proxyReq(env, "GET", fmt.Sprintf("/test?i=%d", i), token)
		resp.Body.Close()
	}

	// Admin API should report exhausted status
	resp := adminReq(env, "GET", "/admin/runs/"+runID, "")
	result := readJSON(resp)
	if result["status"].(string) != "exhausted" {
		t.Errorf("expected exhausted status, got %q", result["status"])
	}
}

func TestCloseRunFlushIncludesRunMetrics(t *testing.T) {
	env := setupTest(t)

	runID, token := createRun(t, env, "test-svc")

	// Make a request
	proxyReq(env, "GET", "/test", token).Body.Close()

	// Flush
	dir := t.TempDir()
	flushPath := dir + "/out.json"
	resp := adminReq(env, "POST", "/admin/runs/"+runID+"/close",
		fmt.Sprintf(`{"mode":"flush","path":"%s"}`, flushPath))
	resp.Body.Close()

	data, _ := os.ReadFile(flushPath)
	var flushed map[string]interface{}
	json.Unmarshal(data, &flushed)

	if _, ok := flushed["requests_used"]; !ok {
		t.Error("flush data should include requests_used")
	}
	if _, ok := flushed["max_requests"]; !ok {
		t.Error("flush data should include max_requests")
	}
}

// --- Path Matching Unit Tests ---

func TestPathAllowed(t *testing.T) {
	tests := []struct {
		path    string
		allowed []string
		want    bool
	}{
		{"/test", []string{"/test"}, true},
		{"/test", []string{"/other"}, false},
		{"/repos/owner/repo", []string{"/repos/*"}, true},
		{"/repos/owner/repo/issues", []string{"/repos/*"}, true},
		{"/repos/", []string{"/repos/*"}, true},
		{"/test", []string{"/test", "/other"}, true},
		{"/other", []string{"/test", "/other"}, true},
		{"/nope", []string{"/test", "/other"}, false},
		{"/test/extra", []string{"/test"}, false},
		{"/tweets/search/recent", []string{"/tweets/search/recent"}, true},
		{"/tweets/search/all", []string{"/tweets/search/recent"}, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_in_%v", tt.path, tt.allowed), func(t *testing.T) {
			got := pathAllowed(tt.path, tt.allowed)
			if got != tt.want {
				t.Errorf("pathAllowed(%q, %v) = %v, want %v", tt.path, tt.allowed, got, tt.want)
			}
		})
	}
}
