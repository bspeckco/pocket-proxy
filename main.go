package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"pocket-proxy/internal/config"
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
		log.Fatalf("failed to load config: %v", err)
	}

	// Securely delete config file
	if err := secureDelete(configPath); err != nil {
		log.Printf("warning: secure delete failed, falling back to regular delete: %v", err)
		if err := os.Remove(configPath); err != nil {
			log.Printf("warning: failed to delete config file: %v", err)
		}
	}

	st, err := store.New()
	if err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}
	defer st.Close()

	srv := server.New(cfg, st)

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
		log.Println("shutting down...")
		httpServer.Close()
	}()

	log.Printf("pocket-proxy listening on %s", addr)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
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
