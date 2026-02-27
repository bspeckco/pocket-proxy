package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"pocket-proxy/internal/config"
)

func TestDomainAllowed(t *testing.T) {
	tests := []struct {
		host    string
		allowed []string
		want    bool
	}{
		{"api.github.com", []string{"api.github.com"}, true},
		{"evil.com", []string{"api.github.com"}, false},
		{"api.github.com", []string{"*.github.com"}, true},
		{"github.com", []string{"*.github.com"}, true},
		{"sub.api.github.com", []string{"*.github.com"}, true},
		{"evil.com", []string{"*.github.com"}, false},
		{"anything.com", []string{}, true},
		{"API.GITHUB.COM", []string{"api.github.com"}, true},
		{"api.github.com:443", []string{"api.github.com"}, true},
		{"api.github.com", []string{"API.GITHUB.COM"}, true},
		{"sub.example.com:8080", []string{"*.example.com"}, true},
		{"notgithub.com", []string{"*.github.com"}, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_in_%v", tt.host, tt.allowed), func(t *testing.T) {
			got := domainAllowed(tt.host, tt.allowed)
			if got != tt.want {
				t.Errorf("domainAllowed(%q, %v) = %v, want %v", tt.host, tt.allowed, got, tt.want)
			}
		})
	}
}

func TestResolveAbsoluteTarget(t *testing.T) {
	tests := []struct {
		name           string
		targetURL      string
		allowedDomains []string
		allowedPaths   []string
		wantURL        string
		wantLogPath    string
		wantCode       int
		wantErrType    string
	}{
		{
			name:      "valid URL",
			targetURL: "https://api.github.com/repos/owner/repo",
			wantURL:   "https://api.github.com/repos/owner/repo",
			wantLogPath: "https://api.github.com/repos/owner/repo",
		},
		{
			name:        "missing header",
			targetURL:   "",
			wantCode:    http.StatusBadRequest,
			wantErrType: "missing_target_url",
		},
		{
			name:        "invalid URL",
			targetURL:   "://bad",
			wantCode:    http.StatusBadRequest,
			wantErrType: "invalid_target_url",
		},
		{
			name:        "ftp scheme",
			targetURL:   "ftp://files.example.com/data",
			wantCode:    http.StatusBadRequest,
			wantErrType: "invalid_target_url",
		},
		{
			name:           "blocked domain",
			targetURL:      "https://evil.com/api",
			allowedDomains: []string{"api.github.com"},
			wantCode:       http.StatusForbidden,
			wantErrType:    "domain_not_allowed",
		},
		{
			name:           "allowed domain",
			targetURL:      "https://api.github.com/repos",
			allowedDomains: []string{"api.github.com"},
			wantURL:        "https://api.github.com/repos",
			wantLogPath:    "https://api.github.com/repos",
		},
		{
			name:           "wildcard domain allowed",
			targetURL:      "https://sub.example.com/api",
			allowedDomains: []string{"*.example.com"},
			wantURL:        "https://sub.example.com/api",
			wantLogPath:    "https://sub.example.com/api",
		},
		{
			name:         "with allowed_paths, blocked path",
			targetURL:    "https://api.github.com/admin/delete",
			allowedPaths: []string{"/repos/*"},
			wantCode:     http.StatusForbidden,
			wantErrType:  "path_not_allowed",
		},
		{
			name:         "with allowed_paths, allowed path",
			targetURL:    "https://api.github.com/repos/owner/repo",
			allowedPaths: []string{"/repos/*"},
			wantURL:      "https://api.github.com/repos/owner/repo",
			wantLogPath:  "https://api.github.com/repos/owner/repo",
		},
		{
			name:      "http scheme allowed",
			targetURL: "http://example.com/api",
			wantURL:   "http://example.com/api",
			wantLogPath: "http://example.com/api",
		},
		{
			name:        "no scheme",
			targetURL:   "example.com/api",
			wantCode:    http.StatusBadRequest,
			wantErrType: "invalid_target_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/proxy/", nil)
			if tt.targetURL != "" {
				req.Header.Set("X-Target-URL", tt.targetURL)
			}

			svc := &config.ServiceConfig{
				AllowAbsoluteURLs: true,
				AllowedDomains:    tt.allowedDomains,
				AllowedPaths:      tt.allowedPaths,
			}

			target, code, errType, _ := resolveAbsoluteTarget(req, svc)

			if tt.wantCode != 0 {
				if target != nil {
					t.Errorf("expected nil target, got %+v", target)
				}
				if code != tt.wantCode {
					t.Errorf("expected code %d, got %d", tt.wantCode, code)
				}
				if errType != tt.wantErrType {
					t.Errorf("expected errType %q, got %q", tt.wantErrType, errType)
				}
			} else {
				if target == nil {
					t.Fatalf("expected target, got nil (code=%d, errType=%q)", code, errType)
				}
				if target.URL != tt.wantURL {
					t.Errorf("expected URL %q, got %q", tt.wantURL, target.URL)
				}
				if target.LogPath != tt.wantLogPath {
					t.Errorf("expected LogPath %q, got %q", tt.wantLogPath, target.LogPath)
				}
			}
		})
	}
}

func TestResolvePathTarget(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		query       string
		baseURL     string
		allowed     []string
		wantURL     string
		wantLogPath string
		wantCode    int
		wantErrType string
	}{
		{
			name:        "valid path",
			path:        "/proxy/test",
			baseURL:     "https://api.example.com",
			allowed:     []string{"/test"},
			wantURL:     "https://api.example.com/test",
			wantLogPath: "/test",
		},
		{
			name:        "blocked path",
			path:        "/proxy/admin",
			baseURL:     "https://api.example.com",
			allowed:     []string{"/test"},
			wantCode:    http.StatusForbidden,
			wantErrType: "path_not_allowed",
		},
		{
			name:        "query string preserved",
			path:        "/proxy/test",
			query:       "q=hello&limit=10",
			baseURL:     "https://api.example.com",
			allowed:     []string{"/test"},
			wantURL:     "https://api.example.com/test?q=hello&limit=10",
			wantLogPath: "/test?q=hello&limit=10",
		},
		{
			name:        "trailing slash on base URL",
			path:        "/proxy/test",
			baseURL:     "https://api.example.com/",
			allowed:     []string{"/test"},
			wantURL:     "https://api.example.com/test",
			wantLogPath: "/test",
		},
		{
			name:        "root path",
			path:        "/proxy",
			baseURL:     "https://api.example.com",
			allowed:     []string{"/"},
			wantURL:     "https://api.example.com/",
			wantLogPath: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest("GET", url, nil)

			svc := &config.ServiceConfig{
				BaseURL:      tt.baseURL,
				AllowedPaths: tt.allowed,
			}

			target, code, errType, _ := resolvePathTarget(req, svc)

			if tt.wantCode != 0 {
				if target != nil {
					t.Errorf("expected nil target, got %+v", target)
				}
				if code != tt.wantCode {
					t.Errorf("expected code %d, got %d", tt.wantCode, code)
				}
				if errType != tt.wantErrType {
					t.Errorf("expected errType %q, got %q", tt.wantErrType, errType)
				}
			} else {
				if target == nil {
					t.Fatalf("expected target, got nil (code=%d, errType=%q)", code, errType)
				}
				if target.URL != tt.wantURL {
					t.Errorf("expected URL %q, got %q", tt.wantURL, target.URL)
				}
				if target.LogPath != tt.wantLogPath {
					t.Errorf("expected LogPath %q, got %q", tt.wantLogPath, target.LogPath)
				}
			}
		})
	}
}

func TestResolveTargetDispatch(t *testing.T) {
	// Verify resolveTarget dispatches to the right function
	req := httptest.NewRequest("GET", "/proxy/test", nil)
	req.Header.Set("X-Target-URL", "https://api.example.com/test")

	// Absolute URL mode
	svc := &config.ServiceConfig{AllowAbsoluteURLs: true}
	target, _, _, _ := resolveTarget(req, svc)
	if target == nil {
		t.Fatal("expected target for absolute URL mode")
	}
	if target.URL != "https://api.example.com/test" {
		t.Errorf("expected absolute URL, got %q", target.URL)
	}

	// Standard mode
	svc = &config.ServiceConfig{
		BaseURL:      "https://base.example.com",
		AllowedPaths: []string{"/test"},
	}
	target, _, _, _ = resolveTarget(req, svc)
	if target == nil {
		t.Fatal("expected target for path mode")
	}
	if target.URL != "https://base.example.com/test" {
		t.Errorf("expected path-based URL, got %q", target.URL)
	}
}
