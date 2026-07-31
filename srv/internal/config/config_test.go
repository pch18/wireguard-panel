package config

import "testing"

func TestLoadDefaultsToAdmin(t *testing.T) {
	t.Setenv("APP_PORT", "")
	t.Setenv("APP_USERNAME", "")
	t.Setenv("APP_PASSWORD", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" || cfg.Username != "admin" || cfg.Password != "admin5555" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestLoadEnvironmentCredentials(t *testing.T) {
	t.Setenv("APP_USERNAME", "operator")
	t.Setenv("APP_PASSWORD", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "operator" ||
		cfg.Password != "secret" {
		t.Fatalf("environment configuration not applied: %#v", cfg)
	}
}
