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

func TestParseAndSerializeSupportedInterfaceFields(t *testing.T) {
	privateKey, _ := testKeyPair(t)
	_, peerPublicKey := testKeyPair(t)
	presharedKey, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`# Name = Tokyo Gateway
# ClientDNS = 1.1.1.1
# ClientAllowedIPs = 0.0.0.0/0, ::/0
# ClientPersistentKeepalive = 15
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

	config, err := Parse("wg7", "wg7.conf", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if config.ID != "wg7" ||
		config.Filename != "wg7.conf" ||
		config.ListenPort == nil ||
		*config.ListenPort != 51820 ||
		config.MTU == nil ||
		*config.MTU != 1420 {
		t.Fatalf("unexpected interface metadata: %#v", config)
	}
	if !reflect.DeepEqual(config.Address, []string{"10.20.0.1/24", "fd20::1/64"}) ||
		!reflect.DeepEqual(config.DNS, []string{"1.1.1.1", "resolver.example.com"}) ||
		!reflect.DeepEqual(config.ClientAllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("repeated interface values were not parsed: %#v", config)
	}
	if len(config.Peers) != 1 ||
		config.Peers[0].PersistentKeepalive == nil ||
		*config.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("unexpected peer: %#v", config.Peers)
	}

	serialized, err := Serialize(config)
	if err != nil {
		t.Fatal(err)
	}
	requiredLines := []string{
		"# ClientAllowedIPs = 0.0.0.0/0, ::/0",
		"[Interface]",
		"PrivateKey = ",
		"Address = 10.20.0.1/24, fd20::1/64",
		"ListenPort = 51820",
		"DNS = 1.1.1.1, resolver.example.com",
		"MTU = 1420",
		"FwMark = 0xca6c",
		"Table = 100",
		"PreUp = echo pre-up",
		"PreUp = echo second-pre-up",
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
	for _, obsolete := range []string{
		"# ID =",
		"# Name = Tokyo Gateway",
		"ClientDNS",
		"ClientPersistentKeepalive",
	} {
		if bytes.Contains(serialized, []byte(obsolete)) {
			t.Fatalf("obsolete Interface metadata %s was written back:\n%s", obsolete, serialized)
		}
	}
	roundTripped, err := Parse("wg7", "wg7.conf", serialized)
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

func TestSerializeSeparatesPanelMetadataFromInterfaceSection(t *testing.T) {
	config := model.Interface{
		PrivateKey:       testPrivateKey(t),
		Address:          []string{"10.0.0.1/24"},
		ClientAllowedIPs: []string{"10.0.0.0/8"},
	}
	withMetadata, err := Serialize(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(
		withMetadata,
		[]byte("# ClientAllowedIPs = 10.0.0.0/8\n\n[Interface]\n"),
	) {
		t.Fatalf("panel metadata is not separated from [Interface]:\n%s", withMetadata)
	}

	config.ClientAllowedIPs = nil
	withoutMetadata, err := Serialize(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(withoutMetadata, []byte("[Interface]\n")) {
		t.Fatalf("metadata-free config has a leading blank line:\n%s", withoutMetadata)
	}
}

func TestParseUsesFilenameIdentityAndReportsUnknownFields(t *testing.T) {
	valid := fmt.Sprintf(`[Interface]
PrivateKey = %s
Table = main
`, testPrivateKey(t))
	config, err := Parse("wg2", "wg2.conf", []byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := Serialize(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(serialized, []byte("Table = main")) {
		t.Fatalf("unmanaged routing table was not preserved:\n%s", serialized)
	}

	invalid, err := Parse("wg2", "wg2.conf", []byte(valid+"MadeUp = value\n"))
	if err != nil {
		t.Fatalf("unknown field prevented inventory parsing: %v", err)
	}
	if len(invalid.ValidationErrors) == 0 ||
		!strings.Contains(strings.Join(invalid.ValidationErrors, "\n"), "MadeUp") {
		t.Fatalf("unknown field was not reported: %#v", invalid.ValidationErrors)
	}
}

func TestParseOnlyRejectsFilesWithoutInterfaceSection(t *testing.T) {
	invalidValues := `[Interface]
PrivateKey = not-a-key
ListenPort = not-a-port
MadeUp = value

[Peer]
PublicKey = also-not-a-key
AllowedIPs = not-a-cidr
`
	config, err := Parse("wg9", "wg9.conf", []byte(invalidValues))
	if err != nil {
		t.Fatalf("repairable configuration was rejected: %v", err)
	}
	if len(config.ValidationErrors) < 3 {
		t.Fatalf("repairable problems were not retained: %#v", config.ValidationErrors)
	}
	if config.PrivateKey != "not-a-key" || config.Peers[0].AllowedIPs[0] != "not-a-cidr" {
		t.Fatalf("invalid values were not preserved for editing: %#v", config)
	}

	if _, err := Parse("wg9", "wg9.conf", []byte("[Peer]\nPublicKey = value\n")); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("file without Interface returned %v", err)
	}
}

func TestParseKeepsPeerOutsideAdvisoryRouteRange(t *testing.T) {
	data := fmt.Sprintf(`# ClientAllowedIPs = 10.20.0.0/24
[Interface]
PrivateKey = %s
Address = 10.20.0.1/24

[Peer]
# Name = legacy
PublicKey = %s
AllowedIPs = 192.0.2.7/32
`, testPrivateKey(t), testPublicKey(t))
	config, err := Parse("wg0", "wg0.conf", []byte(data))
	if err != nil {
		t.Fatalf("Peer route conflict made Interface unreadable: %v", err)
	}
	if len(config.Peers) != 1 || config.Peers[0].AllowedIPs[0] != "192.0.2.7/32" {
		t.Fatalf("conflicting Peer was not preserved: %#v", config.Peers)
	}
	if len(config.ValidationErrors) != 0 {
		t.Fatalf("advisory route range produced validation errors: %#v", config.ValidationErrors)
	}
}

func TestSerializeRejectsDuplicatePeerKeys(t *testing.T) {
	publicKey := testPublicKey(t)
	config := model.Interface{
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

func TestParseAndSerializeSinglePeer(t *testing.T) {
	privateKey, publicKey := testKeyPair(t)
	presharedKey, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`# Name = Imported laptop
# PrivateKey = %s
# SystemGenerated = true
# ClientAddress = 10.20.0.2/24
# ClientPersistentKeepalive = 15
[Peer]
# ID = 12416d97-1b8c-4c36-bd4d-06dc4e458e4f
PublicKey = %s
PresharedKey = %s
AllowedIPs = 10.20.0.2/32
PersistentKeepalive = 25
`, privateKey, publicKey, presharedKey)

	peer, err := ParsePeer([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if peer.Name != "Imported laptop" ||
		peer.PrivateKey != privateKey ||
		peer.PublicKey != publicKey ||
		peer.PersistentKeepalive == nil ||
		*peer.PersistentKeepalive != 25 {
		t.Fatalf("unexpected parsed Peer: %#v", peer)
	}
	serialized, err := SerializePeer(peer)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"[Peer]",
		"# Name = Imported laptop",
		"# PrivateKey = " + privateKey,
		"PublicKey = " + publicKey,
		"AllowedIPs = 10.20.0.2/32",
	} {
		if !bytes.Contains(serialized, []byte(line)) {
			t.Errorf("serialized Peer is missing %q:\n%s", line, serialized)
		}
	}
	for _, obsolete := range []string{
		"# ID =",
		"SystemGenerated",
		"ClientAddress",
		"ClientPersistentKeepalive",
	} {
		if bytes.Contains(serialized, []byte(obsolete)) {
			t.Fatalf("obsolete %s metadata was written back:\n%s", obsolete, serialized)
		}
	}
	roundTripped, err := ParsePeer(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(peer, roundTripped) {
		t.Fatalf("Peer round trip changed value:\nwant %#v\ngot  %#v", peer, roundTripped)
	}
}

func TestParseMultiplePeersKeepsMetadataWithEachSection(t *testing.T) {
	firstPublicKey := testPublicKey(t)
	secondPublicKey := testPublicKey(t)
	source := fmt.Sprintf(`# Name = Laptop
[Peer]
PublicKey = %s
AllowedIPs = 10.20.0.2/32

# Name = Phone
[Peer]
PublicKey = %s
AllowedIPs = 10.20.0.3/32
`, firstPublicKey, secondPublicKey)

	peers, err := ParsePeers([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 ||
		peers[0].Name != "Laptop" ||
		peers[0].PublicKey != firstPublicKey ||
		peers[1].Name != "Phone" ||
		peers[1].PublicKey != secondPublicKey {
		t.Fatalf("unexpected parsed Peers: %#v", peers)
	}
	if _, err := ParsePeer([]byte(source)); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("single Peer parser accepted a batch: %v", err)
	}
}

func TestParseSinglePeerRejectsWrongSectionsAndUnknownFields(t *testing.T) {
	wrongSection := fmt.Sprintf("[Interface]\nPrivateKey = %s\n", testPrivateKey(t))
	if _, err := ParsePeer([]byte(wrongSection)); err == nil || !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("wrong section returned %v", err)
	}
	unknownField := fmt.Sprintf("[Peer]\nPublicKey = %s\nMadeUp = value\n", testPublicKey(t))
	if _, err := ParsePeer([]byte(unknownField)); err == nil || !errors.Is(err, ErrInvalidFile) || !strings.Contains(err.Error(), "MadeUp") {
		t.Fatalf("unknown Peer field returned %v", err)
	}
}
