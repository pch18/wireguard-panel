package config

import (
	"fmt"
	"os"
	"strings"
)

const (
	defaultPort               = "8080"
	defaultWireGuardDirectory = "/etc/wireguard"
	defaultAuthenticationFile = "/etc/wireguard-panel/auth.json"
	TunnelModeSystem          = "system"
	TunnelModeFileOnly        = "file-only"
)

type Config struct {
	Port               string
	TunnelMode         string
	WireGuardDirectory string
	AuthenticationFile string
}

func Load() (Config, error) {
	cfg := Config{
		Port:               valueOrDefault("APP_PORT", defaultPort),
		TunnelMode:         strings.ToLower(strings.TrimSpace(valueOrDefault("APP_TUNNEL_MODE", TunnelModeSystem))),
		WireGuardDirectory: valueOrDefault("APP_WIREGUARD_DIRECTORY", defaultWireGuardDirectory),
		AuthenticationFile: valueOrDefault("APP_AUTHENTICATION_FILE", defaultAuthenticationFile),
	}
	switch cfg.TunnelMode {
	case TunnelModeSystem, TunnelModeFileOnly:
	default:
		return Config{}, fmt.Errorf(
			"APP_TUNNEL_MODE must be %q or %q",
			TunnelModeSystem,
			TunnelModeFileOnly,
		)
	}
	return cfg, nil
}

func valueOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
