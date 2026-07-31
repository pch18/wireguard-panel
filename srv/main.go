package main

import (
	"context"
	"embed"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"wireguard-panel/internal/config"
	"wireguard-panel/internal/httpapi"
	"wireguard-panel/internal/service"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"
)

//go:embed web
var webFiles embed.FS

const wireGuardDirectory = "/etc/wireguard"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	authService, err := service.NewAuthService(cfg.Username, cfg.Password)
	if err != nil {
		log.Fatal(err)
	}
	configStore, err := wgconfig.NewStore(wireGuardDirectory)
	if err != nil {
		log.Fatal(err)
	}
	shutdownSignal, stopSignals := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stopSignals()
	statusCollector := wgstatus.NewCollector(
		wgstatus.ExecRunner{Binary: "wg"},
		2*time.Second,
		3*time.Minute,
	)
	statusCollector.Start(shutdownSignal)
	router, err := httpapi.NewRouter(httpapi.Dependencies{
		Auth:     authService,
		Configs:  configStore,
		Status:   statusCollector,
		WebFiles: webFiles,
	})
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       75 * time.Second,
	}
	serverErrors := make(chan error, 1)

	log.Printf("server listening on http://localhost:%s", cfg.Port)
	log.Printf("WireGuard configurations at %s", wireGuardDirectory)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-shutdownSignal.Done():
		log.Print("shutdown signal received")
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server stopped unexpectedly: %v", err)
		}
		return
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		_ = server.Close()
		return
	}
	log.Print("server stopped")
}
