package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body.")
		return
	}

	svc, ok := s.cfg.Services[req.Service]
	if !ok {
		jsonError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("Unknown service: %s", req.Service))
		return
	}

	expiresAt := time.Now().UTC().Add(time.Duration(svc.ExpiresInSeconds) * time.Second)
	run, err := s.store.CreateRun(req.Service, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to create run.")
		return
	}

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"run_id":    run.ID,
		"token":     run.Token,
		"proxy_url": s.cfg.Admin.ProxyURL,
	})
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	run, err := s.store.GetRun(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to get run.")
		return
	}
	if run == nil {
		jsonError(w, http.StatusNotFound, "not_found", "Run not found.")
		return
	}

	svc := s.cfg.Services[run.Service]

	logs, err := s.store.GetRequestLogs(run.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to get request logs.")
		return
	}

	requests := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		requests = append(requests, map[string]interface{}{
			"method":      l.Method,
			"path":        l.Path,
			"status_code": l.StatusCode,
			"counted":     l.Counted,
			"created_at":  l.CreatedAt.Format(time.RFC3339),
		})
	}

	status := run.Status
	if status == "active" && time.Now().UTC().After(run.ExpiresAt) {
		status = "expired"
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"run_id":        run.ID,
		"service":       run.Service,
		"status":        status,
		"requests_used": run.RequestsUsed,
		"max_requests":  svc.MaxRequests,
		"requests":      requests,
	})
}

func (s *Server) getResponses(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	run, err := s.store.GetRun(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to get run.")
		return
	}
	if run == nil {
		jsonError(w, http.StatusNotFound, "not_found", "Run not found.")
		return
	}

	responses, err := s.store.GetResponses(run.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to get responses.")
		return
	}

	result := make([]map[string]interface{}, 0, len(responses))
	for _, resp := range responses {
		result = append(result, map[string]interface{}{
			"id":            resp.ID,
			"method":        resp.Method,
			"path":          resp.Path,
			"status_code":   resp.StatusCode,
			"response_body": string(resp.ResponseBody),
			"created_at":    resp.CreatedAt.Format(time.RFC3339),
		})
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"run_id":    run.ID,
		"responses": result,
	})
}

func (s *Server) closeRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		Mode string `json:"mode"`
		Path string `json:"path"`
	}
	// Decode body but don't fail on empty body
	json.NewDecoder(r.Body).Decode(&req)

	if req.Mode == "" {
		req.Mode = "purge"
	}

	run, err := s.store.GetRun(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to get run.")
		return
	}
	if run == nil {
		jsonError(w, http.StatusNotFound, "not_found", "Run not found.")
		return
	}

	// Validate flush parameters before changing any state
	if req.Mode == "flush" && req.Path == "" {
		jsonError(w, http.StatusBadRequest, "bad_request", "Flush mode requires a 'path' field.")
		return
	}

	// Set status to closed before purging to block in-flight proxy requests
	if err := s.store.UpdateRunStatus(id, "closed"); err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to close run.")
		return
	}

	if req.Mode == "flush" {
		svc := s.cfg.Services[run.Service]

		logs, _ := s.store.GetRequestLogs(id)
		responses, _ := s.store.GetResponses(id)

		requestData := make([]map[string]interface{}, 0, len(logs))
		for _, l := range logs {
			entry := map[string]interface{}{
				"id":          l.ID,
				"method":      l.Method,
				"path":        l.Path,
				"status_code": l.StatusCode,
				"counted":     l.Counted,
				"created_at":  l.CreatedAt.Format(time.RFC3339),
			}
			requestData = append(requestData, entry)
		}

		responseData := make([]map[string]interface{}, 0, len(responses))
		for _, resp := range responses {
			responseData = append(responseData, map[string]interface{}{
				"id":            resp.ID,
				"method":        resp.Method,
				"path":          resp.Path,
				"status_code":   resp.StatusCode,
				"response_body": string(resp.ResponseBody),
				"created_at":    resp.CreatedAt.Format(time.RFC3339),
			})
		}

		data := map[string]interface{}{
			"run_id":        run.ID,
			"service":       run.Service,
			"status":        run.Status,
			"requests_used": run.RequestsUsed,
			"max_requests":  svc.MaxRequests,
			"requests":      requestData,
			"responses":     responseData,
		}

		fileData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to marshal flush data.")
			return
		}
		if err := os.WriteFile(req.Path, fileData, 0644); err != nil {
			jsonError(w, http.StatusInternalServerError, "internal_error", fmt.Sprintf("Failed to write flush data: %v", err))
			return
		}
	}

	// Purge all run data
	s.store.DeleteRunData(id)

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": "closed",
	})
}

func (s *Server) revokeRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	run, err := s.store.GetRun(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to get run.")
		return
	}
	if run == nil {
		jsonError(w, http.StatusNotFound, "not_found", "Run not found.")
		return
	}

	if err := s.store.UpdateRunStatus(id, "revoked"); err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke run.")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": "revoked",
	})
}
