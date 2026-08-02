package wgconfig

import (
	"path/filepath"
	"reflect"
	"testing"

	"wireguard-panel/internal/model"
)

func TestExecTunnelControllerUsesManagedConfigurationDirectory(t *testing.T) {
	controller := ExecTunnelController{ConfigDirectory: "/srv/wireguard"}
	if got, want := controller.configTarget("wg0"), filepath.Join("/srv/wireguard", "wg0.conf"); got != want {
		t.Fatalf("config target = %q, want %q", got, want)
	}
	if got := (ExecTunnelController{}).configTarget("wg0"); got != "wg0" {
		t.Fatalf("default config target = %q", got)
	}
}

func TestExecTunnelControllerValidatesDependenciesAndDirectory(t *testing.T) {
	controller := ExecTunnelController{
		WGBinary: "sh", WGQuickBinary: "sh", IPBinary: "sh",
		ConfigDirectory: t.TempDir(),
	}
	if err := controller.ValidateEnvironment(); err != nil {
		t.Fatalf("available environment was rejected: %v", err)
	}
	controller.ConfigDirectory = "relative"
	if err := controller.ValidateEnvironment(); err == nil {
		t.Fatal("relative configuration directory was accepted")
	}
	controller.ConfigDirectory = t.TempDir()
	controller.WGBinary = "wireguard-panel-command-that-does-not-exist"
	if err := controller.ValidateEnvironment(); err == nil {
		t.Fatal("missing WireGuard command was accepted")
	}
}

func TestRuntimeConfigMatchesSemanticallyEquivalentWireGuardOutput(t *testing.T) {
	desired := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.9/24, fd00::9/64
Endpoint = 192.0.2.8:51820
PersistentKeepalive = 25
`)
	actual := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ListenPort = 50123
FwMark = 0xca6c

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 192.0.2.8:51820
AllowedIPs = fd00::/64, 10.0.0.0/24
PersistentKeepalive = 25
`)
	match, err := runtimeConfigMatches(desired, actual)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("semantically equivalent configurations did not match")
	}
}

func TestRuntimeConfigRejectsMissingOrUnexpectedPeer(t *testing.T) {
	desired := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.2/32
`)
	actual := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`)
	match, err := runtimeConfigMatches(desired, actual)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Fatal("configuration with a missing running Peer matched")
	}
}

func TestRuntimeConfigIgnoresRoamingPeerEndpoint(t *testing.T) {
	desired := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.2/32
Endpoint = 192.0.2.8:51820
`)
	actual := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.2/32
Endpoint = 198.51.100.9:49152
`)
	match, err := runtimeConfigMatches(desired, actual)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("an authenticated roaming Endpoint was treated as configuration drift")
	}

	desired = []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.2/32
`)
	match, err = runtimeConfigMatches(desired, actual)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("a learned Endpoint was treated as an unexpected configured field")
	}
}

func TestKeepalivesToDisableSupportsOlderSyncconf(t *testing.T) {
	enabled := uint16(25)
	disabled := uint16(0)
	before := model.Interface{Peers: []model.Peer{
		{PublicKey: "keep", PersistentKeepalive: &enabled},
		{PublicKey: "disable-nil", PersistentKeepalive: &enabled},
		{PublicKey: "disable-zero", PersistentKeepalive: &enabled},
		{PublicKey: "removed", PersistentKeepalive: &enabled},
	}}
	after := model.Interface{Peers: []model.Peer{
		{PublicKey: "keep", PersistentKeepalive: &enabled},
		{PublicKey: "disable-nil"},
		{PublicKey: "disable-zero", PersistentKeepalive: &disabled},
	}}
	want := []string{"disable-nil", "disable-zero"}
	if got := keepalivesToDisable(before, after); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected Peer keepalives to clear: %#v", got)
	}
}
