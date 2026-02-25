package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

type Config struct {
	Admin       AdminConfig                `yaml:"admin"`
	Credentials map[string]CredentialConfig `yaml:"credentials"`
	Services    map[string]ServiceConfig    `yaml:"services"`
}

type AdminConfig struct {
	Secret      string `yaml:"secret"`
	Port        int    `yaml:"port"`
	IDSize      int    `yaml:"id_size"`
	MaxRespSize int    `yaml:"max_response_size"`
	ProxyURL    string `yaml:"proxy_url"`
	LogLevel    string `yaml:"log_level"`
	LogFile     string `yaml:"log_file"`
}

type CredentialConfig struct {
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
}

type ServiceConfig struct {
	BaseURL          string   `yaml:"base_url"`
	Credential       string   `yaml:"credential"`
	AllowedPaths     []string `yaml:"allowed_paths"`
	MaxRequests      int      `yaml:"max_requests"`
	DedupEnabled     bool     `yaml:"dedup_enabled"`
	StoreResponses   bool     `yaml:"store_responses"`
	ExpiresInSeconds int      `yaml:"expires_in_seconds"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	return validate(&cfg)
}

func validate(cfg *Config) (*Config, error) {
	if cfg.Admin.Secret == "" {
		return nil, errors.New("admin.secret is required")
	}
	if cfg.Admin.Port == 0 {
		return nil, errors.New("admin.port is required")
	}
	if cfg.Admin.Port < 1 || cfg.Admin.Port > 65535 {
		return nil, fmt.Errorf("admin.port must be between 1 and 65535, got %d", cfg.Admin.Port)
	}

	if cfg.Admin.IDSize == 0 {
		cfg.Admin.IDSize = 16
	}
	if cfg.Admin.MaxRespSize == 0 {
		cfg.Admin.MaxRespSize = 1 << 20 // 1MB
	}
	if cfg.Admin.ProxyURL == "" {
		cfg.Admin.ProxyURL = fmt.Sprintf("http://localhost:%d", cfg.Admin.Port)
	}
	if cfg.Admin.LogLevel == "" {
		cfg.Admin.LogLevel = "info"
	} else {
		cfg.Admin.LogLevel = strings.ToLower(cfg.Admin.LogLevel)
		if !validLogLevels[cfg.Admin.LogLevel] {
			return nil, fmt.Errorf("admin.log_level must be one of debug, info, warn, error; got %q", cfg.Admin.LogLevel)
		}
	}

	if len(cfg.Services) == 0 {
		return nil, errors.New("at least one service must be defined")
	}

	for name, cred := range cfg.Credentials {
		if cred.Header == "" {
			return nil, fmt.Errorf("credential %q: header is required", name)
		}
		if cred.Value == "" {
			return nil, fmt.Errorf("credential %q: value is required", name)
		}
	}

	for name, svc := range cfg.Services {
		if svc.BaseURL == "" {
			return nil, fmt.Errorf("service %q: base_url is required", name)
		}
		if svc.Credential == "" {
			return nil, fmt.Errorf("service %q: credential is required", name)
		}
		if _, ok := cfg.Credentials[svc.Credential]; !ok {
			return nil, fmt.Errorf("service %q references unknown credential %q", name, svc.Credential)
		}
		if svc.MaxRequests <= 0 {
			return nil, fmt.Errorf("service %q: max_requests must be positive", name)
		}
		if svc.ExpiresInSeconds <= 0 {
			return nil, fmt.Errorf("service %q: expires_in_seconds must be positive", name)
		}
		if len(svc.AllowedPaths) == 0 {
			return nil, fmt.Errorf("service %q: at least one allowed_path is required", name)
		}
		if svc.DedupEnabled && !svc.StoreResponses {
			return nil, fmt.Errorf("service %q: dedup_enabled requires store_responses to be enabled", name)
		}
	}

	return cfg, nil
}
