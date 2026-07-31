package wgconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wireguard-panel/internal/model"
)

func TestStoreCRUDUsesOnlyNativeWireGuardFiles(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	interfaceInput := model.InterfaceInput{
		Name:       "Tokyo",
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.50.0.1/24"},
		ListenPort: uint16Value(51820),
	}
	config, err := store.Create(interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if config.ID != 0 || config.Filename != "wg0.conf" {
		t.Fatalf("unexpected first interface: %#v", config)
	}
	path := filepath.Join(directory, "wg0.conf")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("configuration mode is %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# Name = Tokyo\n[Interface]") {
		t.Fatalf("name is not stored as an in-file comment:\n%s", data)
	}

	interfaceInput.Name = "Tokyo primary"
	interfaceInput.DNS = []string{"1.1.1.1"}
	updated, err := store.Update(0, config.Revision, interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Tokyo primary" {
		t.Fatalf("interface was not updated: %#v", updated)
	}

	peerInput := model.PeerInput{
		PublicKey:           testPublicKey(t),
		AllowedIPs:          []string{"10.50.0.2/32"},
		Endpoint:            "peer.example.com:51820",
		PersistentKeepalive: uint16Value(25),
	}
	updated, err = store.AddPeer(0, updated.Revision, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Peers) != 1 {
		t.Fatalf("peer was not added: %#v", updated.Peers)
	}
	peer := updated.Peers[0]
	if peer.ID == "" || peer.ID == PeerID(peer.PublicKey) {
		t.Fatalf("unexpected peer id: %#v", peer)
	}

	replacementKey := testPublicKey(t)
	peerInput.PublicKey = replacementKey
	peerInput.AllowedIPs = []string{"10.50.0.3/32"}
	updated, err = store.UpdatePeer(0, peer.ID, updated.Revision, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	replaced := updated.Peers[0]
	if replaced.ID != peer.ID || replaced.PublicKey != replacementKey {
		t.Fatalf("peer update did not preserve the stable id: %#v", replaced)
	}

	fetched, err := store.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched.Peers) != 1 ||
		!reflect.DeepEqual(fetched.Peers[0].AllowedIPs, []string{"10.50.0.3/32"}) {
		t.Fatalf("peer was not persisted: %#v", fetched.Peers)
	}
	updated, err = store.DeletePeer(0, replaced.ID, updated.Revision)
	if err != nil {
		t.Fatal(err)
	}

	second, err := store.Create(interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != 1 || second.Filename != "wg1.conf" {
		t.Fatalf("unexpected second interface: %#v", second)
	}
	if err := store.Delete(0, updated.Revision); err != nil {
		t.Fatal(err)
	}
	third, err := store.Create(interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if third.ID != 2 || third.Filename != "wg2.conf" {
		t.Fatalf("deleted IDs should not be reused while higher IDs exist: %#v", third)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 ||
		entries[0].Name() != "wg1.conf" ||
		entries[1].Name() != "wg2.conf" {
		t.Fatalf("store created non-native files: %#v", entries)
	}
}

func TestImportedPeerWithoutIDCanBeLocatedAndMigratedWhileChangingKey(
	t *testing.T,
) {
	directory := t.TempDir()
	path := filepath.Join(directory, "wg0.conf")
	originalKey := testPublicKey(t)
	native := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.90.0.1/24

[Peer]
PublicKey = %s
AllowedIPs = 10.90.0.2/32
`, testPrivateKey(t), originalKey)
	if err := os.WriteFile(path, []byte(native), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := store.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Peers) != 1 {
		t.Fatalf("imported peers: %#v", imported.Peers)
	}
	legacyID := LegacyPeerID(originalKey)
	if imported.Peers[0].ID != legacyID {
		t.Fatalf(
			"peer without metadata ID got %q, want %q",
			imported.Peers[0].ID,
			legacyID,
		)
	}

	replacementKey := testPublicKey(t)
	input := peerInput(imported.Peers[0])
	input.PublicKey = replacementKey
	updated, err := store.UpdatePeer(
		0,
		legacyID,
		imported.Revision,
		input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Peers[0].ID != legacyID ||
		updated.Peers[0].PublicKey != replacementKey {
		t.Fatalf("legacy identity was not preserved: %#v", updated.Peers[0])
	}
	if updated.Peers[0].ID == LegacyPeerID(replacementKey) {
		t.Fatal("stable ID changed together with PublicKey")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), "# ID = "+legacyID+"\n") {
		t.Fatalf("legacy ID was not written into the native file:\n%s", persisted)
	}
}

func uint16Value(value uint16) *uint16 {
	return &value
}
