package config

import (
	"fmt"
	"os"
	"strings"
)

const (
	defaultPort     = "8080"
	defaultUsername = "admin"
	defaultPassword = "admin5555"
)

type Config struct {
	Port     string
	Username string
	Password string
}

func Load() (Config, error) {
	cfg := Config{
		Port:     valueOrDefault("APP_PORT", defaultPort),
		Username: valueOrDefault("APP_USERNAME", defaultUsername),
		Password: valueOrDefault("APP_PASSWORD", defaultPassword),
	}

	cfg.Username = strings.TrimSpace(cfg.Username)
	if cfg.Username == "" || cfg.Password == "" {
		return Config{}, fmt.Errorf("APP_USERNAME and APP_PASSWORD cannot be empty")
	}
	return cfg, nil
}

func valueOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
