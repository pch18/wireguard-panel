package config

import "testing"

func TestLoadDefaultsToAdmin(t *testing.T) {
	t.Setenv("APP_PORT", "")
	t.Setenv("APP_USERNAME", "")
	t.Setenv("APP_PASSWORD", "")
	t.Setenv("APP_COOKIE_SECURE", "")
	t.Setenv("WG_CONFIG_DIR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" || cfg.Username != "admin" || cfg.Password != "admin" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if cfg.CookieSecure {
		t.Fatal("local cookie unexpectedly secure by default")
	}
	if cfg.WireGuardDirectory != "/etc/wireguard" {
		t.Fatalf("unexpected WireGuard directory: %q", cfg.WireGuardDirectory)
	}
}

func TestLoadEnvironmentCredentials(t *testing.T) {
	t.Setenv("APP_USERNAME", "operator")
	t.Setenv("APP_PASSWORD", "secret")
	t.Setenv("APP_COOKIE_SECURE", "true")
	t.Setenv("WG_CONFIG_DIR", "/var/lib/test-wireguard")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "operator" ||
		cfg.Password != "secret" ||
		!cfg.CookieSecure ||
		cfg.WireGuardDirectory != "/var/lib/test-wireguard" {
		t.Fatalf("environment configuration not applied: %#v", cfg)
	}
}

func TestLoadRejectsRelativeWireGuardDirectory(t *testing.T) {
	t.Setenv("WG_CONFIG_DIR", "wireguard")

	if _, err := Load(); err == nil {
		t.Fatal("relative WG_CONFIG_DIR was accepted")
	}
}
