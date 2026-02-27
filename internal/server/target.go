package server

import (
	"net"
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

	if parsed.User != nil {
		return nil, http.StatusBadRequest, "invalid_target_url",
			"X-Target-URL must not contain userinfo (user:password@host)."
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
	// Strip port if present. net.SplitHostPort handles IPv6 brackets correctly.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Strip brackets from bare IPv6 addresses (e.g., "[::1]" without port).
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
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
