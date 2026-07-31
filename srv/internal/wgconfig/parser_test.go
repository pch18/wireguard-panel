package wgconfig

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"wireguard-panel/internal/model"
)

func TestParseAndSerializeAllOfficialFields(t *testing.T) {
	privateKey, _ := testKeyPair(t)
	_, peerPublicKey := testKeyPair(t)
	presharedKey, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`# Name = Tokyo Gateway
[Interface]
PrivateKey = %s
Address = 10.20.0.1/24, fd20::1/64
ListenPort = 51820
FwMark = 0xca6c
DNS = 1.1.1.1, resolver.example.com
MTU = 1420
Table = 100
PreUp = echo pre-up
PreUp = echo second-pre-up
PostUp = iptables -A FORWARD -i %%i -j ACCEPT
PreDown = echo pre-down
PostDown = echo post-down
SaveConfig = true

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 10.20.0.2/32, fd20::2/128
Endpoint = peer.example.com:51820
PersistentKeepalive = 25
`, privateKey, peerPublicKey, presharedKey)

	config, err := Parse(7, "wg7.conf", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if config.ID != 7 ||
		config.Filename != "wg7.conf" ||
		config.Name != "Tokyo Gateway" ||
		config.ListenPort == nil ||
		*config.ListenPort != 51820 ||
		config.MTU == nil ||
		*config.MTU != 1420 ||
		!config.SaveConfig {
		t.Fatalf("unexpected interface metadata: %#v", config)
	}
	if !reflect.DeepEqual(config.Address, []string{"10.20.0.1/24", "fd20::1/64"}) ||
		!reflect.DeepEqual(config.DNS, []string{"1.1.1.1", "resolver.example.com"}) ||
		!reflect.DeepEqual(config.PreUp, []string{"echo pre-up", "echo second-pre-up"}) {
		t.Fatalf("repeated interface values were not parsed: %#v", config)
	}
	if len(config.Peers) != 1 ||
		config.Peers[0].ID != PeerID(config.Peers[0].PublicKey) ||
		config.Peers[0].PersistentKeepalive == nil ||
		*config.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("unexpected peer: %#v", config.Peers)
	}

	serialized, err := Serialize(config)
	if err != nil {
		t.Fatal(err)
	}
	requiredLines := []string{
		"# Name = Tokyo Gateway",
		"[Interface]",
		"PrivateKey = ",
		"Address = 10.20.0.1/24, fd20::1/64",
		"ListenPort = 51820",
		"FwMark = 0xca6c",
		"DNS = 1.1.1.1, resolver.example.com",
		"MTU = 1420",
		"Table = 100",
		"PreUp = echo pre-up",
		"PostUp = iptables -A FORWARD -i %i -j ACCEPT",
		"PreDown = echo pre-down",
		"PostDown = echo post-down",
		"SaveConfig = true",
		"[Peer]",
		"PublicKey = ",
		"PresharedKey = ",
		"AllowedIPs = 10.20.0.2/32, fd20::2/128",
		"Endpoint = peer.example.com:51820",
		"PersistentKeepalive = 25",
	}
	for _, line := range requiredLines {
		if !bytes.Contains(serialized, []byte(line)) {
			t.Errorf("serialized config is missing %q:\n%s", line, serialized)
		}
	}
	roundTripped, err := Parse(7, "wg7.conf", serialized)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.Revision == config.Revision {
		t.Fatal("revision did not change after canonical serialization")
	}
	config.Revision = roundTripped.Revision
	if !reflect.DeepEqual(config, roundTripped) {
		t.Fatalf("round trip changed config:\nwant %#v\ngot  %#v", config, roundTripped)
	}
}

func TestParseFallsBackToFilenameAndRejectsUnknownFields(t *testing.T) {
	valid := fmt.Sprintf(`[Interface]
PrivateKey = %s
Table = main
`, testPrivateKey(t))
	config, err := Parse(2, "wg2.conf", []byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "wg2" {
		t.Fatalf("unexpected fallback name %q", config.Name)
	}
	if config.Table != "main" {
		t.Fatalf("named routing table was not accepted: %q", config.Table)
	}

	_, err = Parse(2, "wg2.conf", []byte(valid+"MadeUp = value\n"))
	if err == nil || !errors.Is(err, ErrInvalidFile) || !strings.Contains(err.Error(), "MadeUp") {
		t.Fatalf("unknown field returned unexpected error: %v", err)
	}
}

func TestSerializeRejectsDuplicatePeerKeys(t *testing.T) {
	publicKey := testPublicKey(t)
	config := model.Interface{
		Name:       "Duplicate",
		PrivateKey: testPrivateKey(t),
		Peers: []model.Peer{
			{PublicKey: publicKey},
			{PublicKey: publicKey},
		},
	}

	if _, err := Serialize(config); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate peer keys returned %v", err)
	}
}
