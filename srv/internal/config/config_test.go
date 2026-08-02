package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("APP_PORT", "")
	t.Setenv("APP_TUNNEL_MODE", "")
	t.Setenv("APP_WIREGUARD_DIRECTORY", "")
	t.Setenv("APP_AUTHENTICATION_FILE", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "5555" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if cfg.TunnelMode != TunnelModeSystem {
		t.Fatalf("unexpected tunnel mode default: %#v", cfg)
	}
	if cfg.WireGuardDirectory != "/etc/wireguard" ||
		cfg.AuthenticationFile != "/etc/wireguard-panel/auth.json" {
		t.Fatalf("unexpected path defaults: %#v", cfg)
	}
}

func TestLoadEnvironmentPort(t *testing.T) {
	t.Setenv("APP_PORT", "9090")
	t.Setenv("APP_TUNNEL_MODE", " FILE-ONLY ")
	t.Setenv("APP_WIREGUARD_DIRECTORY", "/tmp/wireguard-panel-test/wireguard")
	t.Setenv("APP_AUTHENTICATION_FILE", "/tmp/wireguard-panel-test/auth.json")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "9090" {
		t.Fatalf("environment configuration not applied: %#v", cfg)
	}
	if cfg.TunnelMode != TunnelModeFileOnly {
		t.Fatalf("environment tunnel mode not applied: %#v", cfg)
	}
	if cfg.WireGuardDirectory != "/tmp/wireguard-panel-test/wireguard" ||
		cfg.AuthenticationFile != "/tmp/wireguard-panel-test/auth.json" {
		t.Fatalf("environment paths not applied: %#v", cfg)
	}
}

func TestLoadRejectsUnknownTunnelMode(t *testing.T) {
	t.Setenv("APP_TUNNEL_MODE", "disabled")

	if _, err := Load(); err == nil {
		t.Fatal("unknown tunnel mode was accepted")
	}
}
