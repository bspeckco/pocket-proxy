package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `
admin:
  secret: "test-secret"
  port: 9120

credentials:
  test-cred:
    header: "Authorization"
    value: "Bearer test-key"

services:
  test-svc:
    base_url: "https://api.example.com"
    credential: "test-cred"
    allowed_paths:
      - "/test"
    max_requests: 10
    dedup_enabled: false
    store_responses: false
    expires_in_seconds: 3600
`

func TestParseValidConfig(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.Secret != "test-secret" {
		t.Errorf("expected secret 'test-secret', got %q", cfg.Admin.Secret)
	}
	if cfg.Admin.Port != 9120 {
		t.Errorf("expected port 9120, got %d", cfg.Admin.Port)
	}
	if len(cfg.Credentials) != 1 {
		t.Errorf("expected 1 credential, got %d", len(cfg.Credentials))
	}
	cred := cfg.Credentials["test-cred"]
	if cred.Header != "Authorization" {
		t.Errorf("expected header 'Authorization', got %q", cred.Header)
	}
	if len(cfg.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(cfg.Services))
	}
	svc := cfg.Services["test-svc"]
	if svc.BaseURL != "https://api.example.com" {
		t.Errorf("expected base_url 'https://api.example.com', got %q", svc.BaseURL)
	}
	if svc.MaxRequests != 10 {
		t.Errorf("expected max_requests 10, got %d", svc.MaxRequests)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.Secret != "test-secret" {
		t.Errorf("expected secret 'test-secret', got %q", cfg.Admin.Secret)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestMissingAdminSecret(t *testing.T) {
	yaml := `
admin:
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing admin secret")
	}
}

func TestMissingAdminPort(t *testing.T) {
	yaml := `
admin:
  secret: "s"
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing admin port")
	}
}

func TestInvalidPortRange(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 99999
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestNoServices(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for no services")
	}
}

func TestUnknownCredentialReference(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "nonexistent"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown credential reference")
	}
}

func TestDedupWithoutStoreResponses(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    dedup_enabled: true
    store_responses: false
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for dedup without store_responses")
	}
}

func TestMissingServiceBaseURL(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing base_url")
	}
}

func TestMissingServiceCredential(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing credential")
	}
}

func TestInvalidMaxRequests(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 0
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid max_requests")
	}
}

func TestInvalidExpiresInSeconds(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 0
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid expires_in_seconds")
	}
}

func TestNoAllowedPaths(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for no allowed_paths")
	}
}

func TestCredentialMissingHeader(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for credential missing header")
	}
}

func TestCredentialMissingValue(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  c:
    header: "H"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for credential missing value")
	}
}

func TestInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("{{not yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLogLevelDefault(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.LogLevel != "info" {
		t.Errorf("expected default log_level 'info', got %q", cfg.Admin.LogLevel)
	}
}

func TestLogLevelValid(t *testing.T) {
	for _, level := range []string{"trace", "debug", "info", "warn", "error", "TRACE", "DEBUG", "Info", "WARN"} {
		yaml := fmt.Sprintf(`
admin:
  secret: "s"
  port: 9120
  log_level: "%s"
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`, level)
		_, err := Parse([]byte(yaml))
		if err != nil {
			t.Errorf("expected log_level %q to be valid, got error: %v", level, err)
		}
	}
}

func TestLogLevelInvalid(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
  log_level: "verbose"
credentials:
  c:
    header: "H"
    value: "V"
services:
  s:
    base_url: "http://x"
    credential: "c"
    allowed_paths: ["/"]
    max_requests: 1
    expires_in_seconds: 60
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid log_level")
	}
}

func TestMultipleServicesAndCredentials(t *testing.T) {
	yaml := `
admin:
  secret: "s"
  port: 9120
credentials:
  cred-a:
    header: "Authorization"
    value: "Bearer aaa"
  cred-b:
    header: "X-API-Key"
    value: "bbb"
services:
  svc-a:
    base_url: "http://a.com"
    credential: "cred-a"
    allowed_paths: ["/a"]
    max_requests: 5
    expires_in_seconds: 100
  svc-b:
    base_url: "http://b.com"
    credential: "cred-b"
    allowed_paths: ["/b", "/c/*"]
    max_requests: 20
    dedup_enabled: true
    store_responses: true
    expires_in_seconds: 200
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Credentials) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(cfg.Credentials))
	}
	if len(cfg.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(cfg.Services))
	}
	svcB := cfg.Services["svc-b"]
	if !svcB.DedupEnabled {
		t.Error("expected svc-b dedup_enabled to be true")
	}
	if !svcB.StoreResponses {
		t.Error("expected svc-b store_responses to be true")
	}
	if len(svcB.AllowedPaths) != 2 {
		t.Errorf("expected 2 allowed paths for svc-b, got %d", len(svcB.AllowedPaths))
	}
}
