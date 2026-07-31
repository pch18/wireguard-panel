package wgconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wireguard-panel/internal/model"
)

func TestGeneratedPeerMetadataClientConfigAndRevisionConflict(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	config, err := store.Create(model.InterfaceInput{
		Name:             "Office",
		PrivateKey:       testPrivateKey(t),
		Address:          []string{"10.60.0.1/24"},
		ClientEndpoint:   "vpn.example.com:51820",
		ClientDNS:        []string{"1.1.1.1"},
		ClientAllowedIPs: []string{"10.60.0.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	originalRevision := config.Revision
	config, err = store.AddPeer(0, config.Revision, model.PeerInput{
		Name:                      "Alice Laptop",
		GenerateKeyPair:           true,
		GeneratePresharedKey:      true,
		ClientAddress:             []string{"10.60.0.2/24"},
		AllowedIPs:                []string{"10.60.0.2/32"},
		ClientPersistentKeepalive: uint16Value(25),
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Revision == originalRevision {
		t.Fatal("revision did not change after peer creation")
	}
	if len(config.Peers) != 1 {
		t.Fatalf("unexpected peers: %#v", config.Peers)
	}
	peer := config.Peers[0]
	if peer.ID == "" ||
		peer.PrivateKey == "" ||
		peer.PublicKey == "" ||
		peer.PresharedKey == "" ||
		!peer.SystemGenerated {
		t.Fatalf("generated peer is incomplete: %#v", peer)
	}
	derived, err := PublicKeyFromPrivate(peer.PrivateKey)
	if err != nil || derived != peer.PublicKey {
		t.Fatalf("stored key pair does not match: derived=%q err=%v", derived, err)
	}

	native, err := os.ReadFile(filepath.Join(directory, "wg0.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"# ClientEndpoint = vpn.example.com:51820",
		"# ID = " + peer.ID,
		"# Name = Alice Laptop",
		"# PrivateKey = " + peer.PrivateKey,
		"# SystemGenerated = true",
		"# ClientAddress = 10.60.0.2/24",
		"PublicKey = " + peer.PublicKey,
	} {
		if !strings.Contains(string(native), expected) {
			t.Errorf("native configuration is missing %q:\n%s", expected, native)
		}
	}

	filename, client, err := store.ClientConfig(0, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if filename != "wg0-Alice-Laptop.conf" {
		t.Fatalf("unexpected client filename %q", filename)
	}
	for _, expected := range []string{
		"[Interface]",
		"PrivateKey = " + peer.PrivateKey,
		"Address = 10.60.0.2/24",
		"DNS = 1.1.1.1",
		"[Peer]",
		"PresharedKey = " + peer.PresharedKey,
		"AllowedIPs = 10.60.0.0/24",
		"Endpoint = vpn.example.com:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(string(client), expected) {
			t.Errorf("client configuration is missing %q:\n%s", expected, client)
		}
	}

	_, err = store.Update(0, originalRevision, interfaceInput(config))
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision returned %v", err)
	}
}

func TestIPPlanAndConflictingPeerAssignments(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config, err := store.Create(model.InterfaceInput{
		Name:       "Plan",
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.70.0.1/29", "fd70::1/64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := store.IPPlan(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Networks) != 2 ||
		plan.Networks[0].SuggestedAddress != "10.70.0.2/29" ||
		plan.Networks[0].SuggestedAllowedIP != "10.70.0.2/32" {
		t.Fatalf("unexpected initial IP plan: %#v", plan)
	}

	config, err = store.AddPeer(0, config.Revision, model.PeerInput{
		Name:          "Peer A",
		PublicKey:     testPublicKey(t),
		ClientAddress: []string{"10.70.0.2/29"},
		AllowedIPs:    []string{"10.70.0.2/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err = store.IPPlan(0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Networks[0].SuggestedAddress != "10.70.0.3/29" {
		t.Fatalf("allocated address was not skipped: %#v", plan.Networks[0])
	}

	_, err = store.AddPeer(0, config.Revision, model.PeerInput{
		Name:          "Peer B",
		PublicKey:     testPublicKey(t),
		ClientAddress: []string{"10.70.0.2/29"},
		AllowedIPs:    []string{"10.70.0.2/32"},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting IP assignment returned %v", err)
	}
}

func TestGenerateKeyPairProducesMatchingWireGuardKeys(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if derived != publicKey {
		t.Fatalf("derived public key %q does not match %q", derived, publicKey)
	}
	_, err = NormalizePeer(model.PeerInput{
		PrivateKey: privateKey,
		PublicKey:  testPublicKey(t),
	})
	if err == nil {
		t.Fatal("mismatched key pair was accepted")
	}
}
