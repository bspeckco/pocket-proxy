package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"pocket-proxy/internal/config"
	"pocket-proxy/internal/logger"
	"pocket-proxy/internal/server"
	"pocket-proxy/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: pocket-proxy <config-path>\n")
		os.Exit(1)
	}

	configPath := os.Args[1]

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger from config
	level, _ := logger.ParseLevel(cfg.Admin.LogLevel) // already validated
	log, err := logger.New(logger.Options{
		Level:   level,
		LogFile: cfg.Admin.LogFile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	// Securely delete config file (secureDelete already falls back to os.Remove)
	if err := secureDelete(configPath); err != nil {
		log.Warn("failed to delete config file: %v", err)
	}

	st, err := store.New(store.StoreOptions{
		IDSize:      cfg.Admin.IDSize,
		MaxRespSize: cfg.Admin.MaxRespSize,
	})
	if err != nil {
		log.Fatal("failed to initialize store: %v", err)
	}
	defer st.Close()

	srv := server.New(cfg, st, log)

	addr := fmt.Sprintf(":%d", cfg.Admin.Port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Info("shutting down...")
		httpServer.Close()
	}()

	log.Info("pocket-proxy listening on %s (log_level=%s)", addr, cfg.Admin.LogLevel)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal("server error: %v", err)
	}
}

func secureDelete(path string) error {
	// Try srm first
	if _, err := exec.LookPath("srm"); err == nil {
		return exec.Command("srm", path).Run()
	}
	// Try shred as fallback
	if _, err := exec.LookPath("shred"); err == nil {
		return exec.Command("shred", "-u", path).Run()
	}
	// Regular delete as last resort
	return os.Remove(path)
}
