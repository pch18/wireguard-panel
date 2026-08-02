package wgconfig

import (
	"errors"
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
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("configuration directory mode is %o, want 700", directoryInfo.Mode().Perm())
	}
	interfaceInput := model.InterfaceInput{
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.50.0.1/24"},
		ListenPort: uint16Value(51820),
	}
	config, err := store.Create("Tokyo", interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if config.ID != "Tokyo" || config.Filename != "Tokyo.conf" {
		t.Fatalf("unexpected first interface: %#v", config)
	}
	path := filepath.Join(directory, "Tokyo.conf")
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
	if strings.Contains(string(data), "# Name =") {
		t.Fatalf("Interface name must come only from the filename:\n%s", data)
	}
	if strings.Contains(string(data), "PublicKey =") {
		t.Fatalf("Interface PublicKey must be derived instead of stored:\n%s", data)
	}

	interfaceInput.DNS = []string{"1.1.1.1"}
	updated, err := store.Update(config.ID, config.Revision, interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != "Tokyo" {
		t.Fatalf("interface was not updated: %#v", updated)
	}

	peerInput := model.PeerInput{
		PublicKey:           testPublicKey(t),
		AllowedIPs:          []string{"10.50.0.2/32"},
		Endpoint:            "peer.example.com:51820",
		PersistentKeepalive: uint16Value(25),
	}
	updated, err = store.AddPeer(config.ID, updated.Revision, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Peers) != 1 {
		t.Fatalf("peer was not added: %#v", updated.Peers)
	}
	peer := updated.Peers[0]
	if peer.PublicKey != peerInput.PublicKey {
		t.Fatalf("unexpected peer: %#v", peer)
	}

	replacementKey := testPublicKey(t)
	peerInput.PublicKey = replacementKey
	peerInput.AllowedIPs = []string{"10.50.0.3/32"}
	updated, err = store.UpdatePeer(config.ID, peer.PublicKey, updated.Revision, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	replaced := updated.Peers[0]
	if replaced.PublicKey != replacementKey {
		t.Fatalf("peer public key was not updated: %#v", replaced)
	}

	fetched, err := store.Get(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched.Peers) != 1 ||
		!reflect.DeepEqual(fetched.Peers[0].AllowedIPs, []string{"10.50.0.3/32"}) {
		t.Fatalf("peer was not persisted: %#v", fetched.Peers)
	}
	updated, err = store.DeletePeer(config.ID, replaced.PublicKey, updated.Revision)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create("Osaka_2", interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != "Osaka_2" || second.Filename != "Osaka_2.conf" {
		t.Fatalf("unexpected second interface: %#v", second)
	}
	if err := store.Delete(config.ID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	third, err := store.Create("Tokyo", interfaceInput)
	if err != nil {
		t.Fatal(err)
	}
	if third.ID != "Tokyo" || third.Filename != "Tokyo.conf" {
		t.Fatalf("a deleted Interface name should be reusable: %#v", third)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 ||
		entries[0].Name() != "Osaka_2.conf" ||
		entries[1].Name() != "Tokyo.conf" {
		t.Fatalf("store created non-native files: %#v", entries)
	}
}

func TestInventoryIncludesConfigurationsThatCannotBeParsed(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "wg0.conf"),
		[]byte("this is not a WireGuard configuration"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "wg1.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "not-managed.txt"),
		[]byte("ignored"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	configs, names, problems, err := store.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 0 {
		t.Fatalf("parsed configs = %#v", configs)
	}
	if !reflect.DeepEqual(names, []string{"wg0", "wg1"}) {
		t.Fatalf("occupied names = %#v", names)
	}
	if len(problems) != 2 || problems[0].ID != "wg0" || problems[1].ID != "wg1" {
		t.Fatalf("inventory problems = %#v", problems)
	}
}

func TestExistingPeerCanBeLocatedByOriginalPublicKeyWhileChangingKey(
	t *testing.T,
) {
	directory := t.TempDir()
	path := filepath.Join(directory, "wg0.conf")
	originalKey := testPublicKey(t)
	native := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.90.0.1/24

[Peer]
# ID = old-panel-id
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
	imported, err := store.Get("wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Peers) != 1 {
		t.Fatalf("imported peers: %#v", imported.Peers)
	}
	if imported.Peers[0].PublicKey != originalKey {
		t.Fatalf("unexpected imported peer: %#v", imported.Peers[0])
	}

	replacementKey := testPublicKey(t)
	input := peerInput(imported.Peers[0])
	input.PublicKey = replacementKey
	updated, err := store.UpdatePeer(
		"wg0",
		originalKey,
		imported.Revision,
		input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Peers[0].PublicKey != replacementKey {
		t.Fatalf("Peer key was not replaced: %#v", updated.Peers[0])
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "# ID =") ||
		!strings.Contains(string(persisted), "PublicKey = "+replacementKey) {
		t.Fatalf("legacy ID was not removed during save:\n%s", persisted)
	}
}

func TestPeerPublicKeyCannotBeDuplicatedOrOverwriteAnotherPeer(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config, err := store.Create("Duplicate_keys", model.InterfaceInput{
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.95.0.1/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	keyA := testPublicKey(t)
	keyB := testPublicKey(t)
	config, err = store.AddPeer(config.ID, config.Revision, model.PeerInput{
		Name: "Peer A", PublicKey: keyA, AllowedIPs: []string{"10.95.0.2/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err = store.AddPeer(config.ID, config.Revision, model.PeerInput{
		Name: "Peer B", PublicKey: keyB, AllowedIPs: []string{"10.95.0.3/32"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.AddPeer(config.ID, config.Revision, model.PeerInput{
		Name: "Duplicate A", PublicKey: keyA, AllowedIPs: []string{"10.95.0.4/32"},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate add returned %v", err)
	}
	peerSource := fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = 10.95.0.4/32\n", keyA)
	if _, err := store.ImportPeer(config.ID, config.Revision, []byte(peerSource)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate import returned %v", err)
	}
	input := peerInput(config.Peers[0])
	input.PublicKey = keyB
	if _, err := store.UpdatePeer(config.ID, keyA, config.Revision, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate update returned %v", err)
	}
	after, err := store.Get(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 2 ||
		after.Peers[0].PublicKey != keyA ||
		after.Peers[1].PublicKey != keyB {
		t.Fatalf("rejected update changed peers: %#v", after.Peers)
	}
}

func TestStoreImportsAndExportsInterfaceAndPeerConfiguration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	interfaceSource := fmt.Sprintf(`# Name = Imported gateway
[Interface]
PrivateKey = %s
Address = 10.91.0.1/24
`, testPrivateKey(t))
	config, err := store.Import([]byte(interfaceSource))
	if err != nil {
		t.Fatal(err)
	}
	if config.ID != "wg0" || config.Filename != "wg0.conf" {
		t.Fatalf("unexpected imported Interface: %#v", config)
	}
	exported, err := store.Config(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), "# Name =") {
		t.Fatalf("unexpected Interface export:\n%s", exported)
	}

	_, peerPublicKey := testKeyPair(t)
	peerSource := fmt.Sprintf(`# ID = 12416d97-1b8c-4c36-bd4d-06dc4e458e4f
# Name = Imported peer
[Peer]
PublicKey = %s
AllowedIPs = 10.91.0.2/32
`, peerPublicKey)
	withPeer, err := store.ImportPeer(config.ID, config.Revision, []byte(peerSource))
	if err != nil {
		t.Fatal(err)
	}
	if len(withPeer.Peers) != 1 ||
		withPeer.Peers[0].Name != "Imported peer" {
		t.Fatalf("Peer was not imported: %#v", withPeer.Peers)
	}
	peerExport, err := store.PeerConfig(config.ID, withPeer.Peers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(peerExport), "# ID =") ||
		!strings.Contains(string(peerExport), "PublicKey = "+peerPublicKey) {
		t.Fatalf("unexpected Peer export:\n%s", peerExport)
	}

	replacement := fmt.Sprintf(`# Name = Replaced gateway
[Interface]
PrivateKey = %s
Address = 10.92.0.1/24
`, testPrivateKey(t))
	replaced, err := store.ImportOver(config.ID, withPeer.Revision, []byte(replacement))
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID != "wg0" || len(replaced.Peers) != 0 {
		t.Fatalf("unexpected replaced Interface: %#v", replaced)
	}
	if _, err := store.ImportOver(config.ID, withPeer.Revision, []byte(replacement)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale import returned %v", err)
	}
}

func TestStoreBatchPeerImportIsAtomic(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config, err := store.Create("wg0", model.InterfaceInput{
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.94.0.1/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstKey := testPublicKey(t)
	secondKey := testPublicKey(t)
	batch := fmt.Sprintf(`[Peer]
PublicKey = %s
AllowedIPs = 10.94.0.2/32

[Peer]
PublicKey = %s
AllowedIPs = 10.94.0.3/32
`, firstKey, secondKey)
	imported, err := store.ImportPeer(config.ID, config.Revision, []byte(batch))
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Peers) != 2 {
		t.Fatalf("batch import added %d Peers, want 2", len(imported.Peers))
	}

	thirdKey := testPublicKey(t)
	conflictingBatch := fmt.Sprintf(`[Peer]
PublicKey = %s
AllowedIPs = 10.94.0.4/32

[Peer]
PublicKey = %s
AllowedIPs = 10.94.0.5/32
`, thirdKey, firstKey)
	if _, err := store.ImportPeer(
		config.ID,
		imported.Revision,
		[]byte(conflictingBatch),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting batch returned %v", err)
	}
	after, err := store.Get(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 2 || after.Revision != imported.Revision {
		t.Fatalf("rejected batch changed configuration: %#v", after.Peers)
	}
}

func TestStructuredUpdatePreservesUnmanagedWGQuickFieldsVerbatim(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.96.0.1/24
  Table   =   123
PreUp = echo first
PreUp = echo second
PostUp = nft add rule inet filter forward iifname %%i accept # keep this comment
SaveConfig = false
`, testPrivateKey(t))
	path := filepath.Join(directory, "wg0.conf")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := store.Get("wg0")
	if err != nil {
		t.Fatal(err)
	}
	input := interfaceInput(config)
	input.DNS = []string{"1.1.1.1"}
	if _, err := store.Update(config.ID, config.Revision, input); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, exactLine := range []string{
		"  Table   =   123",
		"PreUp = echo first",
		"PreUp = echo second",
		"PostUp = nft add rule inet filter forward iifname %i accept # keep this comment",
		"SaveConfig = false",
	} {
		if !strings.Contains(string(updated), exactLine+"\n") {
			t.Errorf("unmanaged line changed or disappeared: %q\n%s", exactLine, updated)
		}
	}
	if !strings.Contains(string(updated), "DNS = 1.1.1.1\n") {
		t.Fatalf("managed field was not updated:\n%s", updated)
	}
}

func TestNewStoreRemovesObsoleteRuntimeSnapshot(t *testing.T) {
	directory := t.TempDir()
	legacyPath := filepath.Join(directory, legacyRuntimeStateFilename)
	if err := os.WriteFile(legacyPath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("obsolete runtime snapshot still exists: %v", err)
	}
}

func uint16Value(value uint16) *uint16 {
	return &value
}
