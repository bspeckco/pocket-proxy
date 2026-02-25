package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"pocket-proxy/internal/config"
	"pocket-proxy/internal/store"
)

type Server struct {
	cfg   *config.Config
	store *store.Store
	mux   *http.ServeMux
}

func New(cfg *config.Config, st *store.Store) *Server {
	s := &Server{
		cfg:   cfg,
		store: st,
		mux:   http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Admin API
	s.mux.HandleFunc("POST /admin/runs", s.adminAuth(s.createRun))
	s.mux.HandleFunc("GET /admin/runs/{id}", s.adminAuth(s.getRun))
	s.mux.HandleFunc("GET /admin/runs/{id}/responses", s.adminAuth(s.getResponses))
	s.mux.HandleFunc("POST /admin/runs/{id}/close", s.adminAuth(s.closeRun))
	s.mux.HandleFunc("DELETE /admin/runs/{id}", s.adminAuth(s.revokeRun))

	// Agent API
	s.mux.HandleFunc("/proxy/", s.proxyRequest)
}

func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing admin secret.")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Admin.Secret)) != 1 {
			jsonError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing admin secret.")
			return
		}
		next(w, r)
	}
}

func jsonError(w http.ResponseWriter, status int, errCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   errCode,
		"message": message,
	})
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// pathAllowed checks whether requestPath matches any of the allowed path
// patterns. requestPath must be the URL path only (no query string) — this
// is guaranteed when derived from r.URL.Path.
// Patterns ending in "*" match any path sharing that prefix; otherwise exact match.
func pathAllowed(requestPath string, allowedPaths []string) bool {
	for _, pattern := range allowedPaths {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(requestPath, prefix) {
				return true
			}
		} else if requestPath == pattern {
			return true
		}
	}
	return false
}
