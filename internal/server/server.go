package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"pocket-proxy/internal/config"
	"pocket-proxy/internal/logger"
	"pocket-proxy/internal/store"
)

type Server struct {
	cfg   *config.Config
	store *store.Store
	log   *logger.Logger
	mux   *http.ServeMux
}

func New(cfg *config.Config, st *store.Store, log *logger.Logger) *Server {
	s := &Server{
		cfg:   cfg,
		store: st,
		log:   log,
		mux:   http.NewServeMux(),
	}
	for name, svc := range cfg.Services {
		if svc.AllowAbsoluteURLs && len(svc.AllowedDomains) == 0 {
			log.Warn("service %q: allow_absolute_urls is enabled with no allowed_domains — proxy will forward to any host", name)
		}
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
			s.log.Debug("admin auth failed: missing Bearer prefix")
			jsonError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing admin secret.")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Admin.Secret)) != 1 {
			s.log.Debug("admin auth failed: invalid secret")
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
