package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultPort        = "8080"
	defaultUsername    = "admin"
	defaultPassword    = "admin"
	defaultWGDirectory = "/etc/wireguard"
)

type Config struct {
	Port               string
	Username           string
	Password           string
	WireGuardDirectory string
	CookieSecure       bool
}

func Load() (Config, error) {
	cfg := Config{
		Port:     valueOrDefault("APP_PORT", defaultPort),
		Username: valueOrDefault("APP_USERNAME", defaultUsername),
		Password: valueOrDefault("APP_PASSWORD", defaultPassword),
		WireGuardDirectory: valueOrDefault(
			"WG_CONFIG_DIR",
			defaultWGDirectory,
		),
	}

	cfg.Username = strings.TrimSpace(cfg.Username)
	if cfg.Username == "" || cfg.Password == "" {
		return Config{}, fmt.Errorf("APP_USERNAME and APP_PASSWORD cannot be empty")
	}
	if !filepath.IsAbs(cfg.WireGuardDirectory) {
		return Config{}, fmt.Errorf("WG_CONFIG_DIR must be an absolute path")
	}
	if raw := os.Getenv("APP_COOKIE_SECURE"); raw != "" {
		secure, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("APP_COOKIE_SECURE must be true or false: %w", err)
		}
		cfg.CookieSecure = secure
	}
	return cfg, nil
}

func valueOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
