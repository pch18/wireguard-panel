package wgconfig

import (
	"encoding/base64"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wireguard-panel/internal/model"
)

func TestRuntimeConfigPrivateKeyClamping(t *testing.T) {
	canonical, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}
	// 穷举 X25519 会规范化的五个位；其他位不变时必须仍是同一身份。
	for bits := 0; bits < 32; bits++ {
		variant := append([]byte(nil), raw...)
		variant[0] = (variant[0] & 248) | byte(bits&7)
		variant[31] = (variant[31] & 63) | byte((bits>>3)<<6)
		encoded := base64.StdEncoding.EncodeToString(variant)
		match, err := runtimeConfigMatches(
			[]byte("[Interface]\nPrivateKey = "+encoded+"\nListenPort = 60000\n"),
			[]byte("[Interface]\nListenPort = 60000\nPrivateKey = "+canonical+"\n"),
		)
		if err != nil || !match {
			t.Fatalf("equivalent private key variant %d rejected: %v", bits, err)
		}
		if encoded != canonical && runtimeValueMatches("presharedkey", encoded, canonical) {
			t.Fatal("PresharedKey must not use X25519 normalization")
		}
	}
	other, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{other, "invalid", "", wireGuardZeroKey} {
		if runtimeValueMatches("privatekey", candidate, canonical) {
			t.Fatal("different, invalid or unset private key matched")
		}
	}
	// 全零值表示清除身份，不能当作常规 X25519 标量参与等价比较。
	zeroScalar := make([]byte, 32)
	zeroScalar[31] = 64
	if runtimeValueMatches("privatekey", wireGuardZeroKey, base64.StdEncoding.EncodeToString(zeroScalar)) {
		t.Fatal("unset key matched a clamped zero scalar")
	}
}

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

func TestRuntimeConfigAcceptsShowconfNumericAndOmittedDefaults(t *testing.T) {
	desired := []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
FwMark = 51820

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 0
`)
	actual := []byte(`[Interface]
FwMark = 0xca6c

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.2/32
`)
	match, err := runtimeConfigMatches(desired, actual)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("wg showconf normalization was treated as configuration drift")
	}

	differentFwMark := []byte(strings.Replace(
		string(actual), "FwMark = 0xca6c", "FwMark = 0xca6d", 1,
	))
	match, err = runtimeConfigMatches(desired, differentFwMark)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Fatal("a genuinely different FwMark matched")
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
