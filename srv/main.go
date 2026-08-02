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
	"wireguard-panel/internal/mtuprobe"
	"wireguard-panel/internal/service"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"
)

//go:embed web
var webFiles embed.FS

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	credentialStore, err := service.NewFileCredentialStore(cfg.AuthenticationFile)
	if err != nil {
		log.Fatal(err)
	}
	authService, err := service.NewPersistentAuthService(credentialStore)
	if err != nil {
		log.Fatal(err)
	}
	configStore, err := wgconfig.NewStore(cfg.WireGuardDirectory)
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
		3*time.Minute,
	)
	execTunnelController := wgconfig.ExecTunnelController{
		ConfigDirectory: cfg.WireGuardDirectory,
	}
	var tunnelController wgconfig.TunnelController = execTunnelController
	if cfg.TunnelMode == config.TunnelModeFileOnly {
		tunnelController = wgconfig.FileOnlyTunnelController{}
		statusCollector = nil
		log.Print("file-only tunnel mode enabled; WireGuard commands will not be executed")
	} else {
		if err := execTunnelController.ValidateEnvironment(); err != nil {
			log.Fatal(err)
		}
		go statusCollector.Run(shutdownSignal)
	}
	router, err := httpapi.NewRouter(httpapi.Dependencies{
		Auth:               authService,
		Configs:            configStore,
		Status:             statusCollector,
		MTUProbe:           mtuprobe.NewDetector(),
		Tunnels:            tunnelController,
		WebFiles:           webFiles,
		ApplicationContext: shutdownSignal,
	})
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       75 * time.Second,
	}
	serverErrors := make(chan error, 1)

	log.Printf("server listening on http://localhost:%s", cfg.Port)
	log.Printf("WireGuard configurations at %s", cfg.WireGuardDirectory)
	log.Printf("authentication configuration at %s", cfg.AuthenticationFile)
	log.Printf("tunnel mode: %s", cfg.TunnelMode)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-shutdownSignal.Done():
		log.Print("shutdown signal received")
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server stopped unexpectedly: %v", err)
		}
		return
	}

	// A cancelled WireGuard command can need the two-minute recovery path in
	// the applied store. Keep the process alive until that rollback finishes.
	shutdownContext, cancel := context.WithTimeout(context.Background(), 135*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		_ = server.Close()
		return
	}
	log.Print("server stopped")
}
