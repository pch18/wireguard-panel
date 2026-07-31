package wgconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"wireguard-panel/internal/model"
)

var managedFilename = regexp.MustCompile(`^wg([0-9]+)\.conf$`)

type Store struct {
	directory string
	mu        sync.RWMutex
}

func NewStore(directory string) (*Store, error) {
	if !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("WireGuard configuration directory must be absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create WireGuard configuration directory: %w", err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat WireGuard configuration directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("WireGuard configuration path is not a directory")
	}
	return &Store{directory: directory}, nil
}

func (store *Store) Directory() string {
	return store.directory
}

func (store *Store) List() ([]model.Interface, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.listLocked()
}

func (store *Store) Get(id int) (model.Interface, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.readLocked(id)
}

func (store *Store) Create(input model.InterfaceInput) (model.Interface, error) {
	input, err := NormalizeInterface(input)
	if err != nil {
		return model.Interface{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	configs, err := store.listLocked()
	if err != nil {
		return model.Interface{}, err
	}
	nextID := 0
	for _, config := range configs {
		if config.ID >= nextID {
			nextID = config.ID + 1
		}
	}
	config := model.Interface{
		ID:       nextID,
		Filename: filenameForID(nextID),
		Peers:    make([]model.Peer, 0),
	}
	applyInterfaceInput(&config, input)
	if err := store.writeLocked(config); err != nil {
		return model.Interface{}, err
	}
	return store.readLocked(nextID)
}

func (store *Store) Update(
	id int,
	expectedRevision string,
	input model.InterfaceInput,
) (model.Interface, error) {
	input, err := NormalizeInterface(input)
	if err != nil {
		return model.Interface{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	config, err := store.readLocked(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	applyInterfaceInput(&config, input)
	if err := store.writeLocked(config); err != nil {
		return model.Interface{}, err
	}
	return store.readLocked(id)
}

func (store *Store) Delete(id int, expectedRevision string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	config, err := store.readLocked(id)
	if err != nil {
		return err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return err
	}
	path := store.pathForID(id)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("delete WireGuard configuration: %w", err)
	}
	return nil
}

func (store *Store) AddPeer(
	id int,
	expectedRevision string,
	input model.PeerInput,
) (model.Interface, error) {
	input, systemGenerated, err := preparePeerInput(input)
	if err != nil {
		return model.Interface{}, err
	}
	peerID, err := newPeerID()
	if err != nil {
		return model.Interface{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	config, err := store.readLocked(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	peer := peerFromInput(input, peerID, systemGenerated)
	config.Peers = append(config.Peers, peer)
	if err := store.writeLocked(config); err != nil {
		return model.Interface{}, err
	}
	return store.readLocked(id)
}

func (store *Store) UpdatePeer(
	interfaceID int,
	peerID string,
	expectedRevision string,
	input model.PeerInput,
) (model.Interface, error) {
	input, systemGenerated, err := preparePeerInput(input)
	if err != nil {
		return model.Interface{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	config, err := store.readLocked(interfaceID)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	index := peerIndex(config.Peers, peerID)
	if index < 0 {
		return model.Interface{}, ErrPeerNotFound
	}
	existing := config.Peers[index]
	if !systemGenerated &&
		existing.SystemGenerated &&
		input.PrivateKey == existing.PrivateKey &&
		input.PublicKey == existing.PublicKey {
		systemGenerated = true
	}
	peer := peerFromInput(input, existing.ID, systemGenerated)
	config.Peers[index] = peer
	if err := store.writeLocked(config); err != nil {
		return model.Interface{}, err
	}
	return store.readLocked(interfaceID)
}

func (store *Store) DeletePeer(
	interfaceID int,
	peerID string,
	expectedRevision string,
) (model.Interface, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	config, err := store.readLocked(interfaceID)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	index := peerIndex(config.Peers, peerID)
	if index < 0 {
		return model.Interface{}, ErrPeerNotFound
	}
	config.Peers = append(config.Peers[:index], config.Peers[index+1:]...)
	if err := store.writeLocked(config); err != nil {
		return model.Interface{}, err
	}
	return store.readLocked(interfaceID)
}

func (store *Store) IPPlan(id int) (model.IPPlan, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	config, err := store.readLocked(id)
	if err != nil {
		return model.IPPlan{}, err
	}
	return BuildIPPlan(config), nil
}

func (store *Store) listLocked() ([]model.Interface, error) {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard configuration directory: %w", err)
	}
	configs := make([]model.Interface, 0)
	for _, entry := range entries {
		matches := managedFilename.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue
		}
		id, err := strconv.Atoi(matches[1])
		if err != nil || filenameForID(id) != entry.Name() {
			return nil, fmt.Errorf("%w: invalid managed filename %s", ErrInvalidFile, entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: symbolic links are not allowed: %s", ErrInvalidFile, entry.Name())
		}
		config, err := store.readLocked(id)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	sort.Slice(configs, func(left int, right int) bool {
		return configs[left].ID < configs[right].ID
	})
	return configs, nil
}

func (store *Store) readLocked(id int) (model.Interface, error) {
	if id < 0 {
		return model.Interface{}, ErrNotFound
	}
	path := store.pathForID(id)
	if _, err := safeConfigInfo(path); err != nil {
		if os.IsNotExist(err) {
			return model.Interface{}, ErrNotFound
		}
		return model.Interface{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return model.Interface{}, ErrNotFound
		}
		return model.Interface{}, fmt.Errorf("read WireGuard configuration: %w", err)
	}
	config, err := Parse(id, filenameForID(id), data)
	if err != nil {
		return model.Interface{}, fmt.Errorf("%s: %w", filenameForID(id), err)
	}
	return config, nil
}

func (store *Store) writeLocked(config model.Interface) error {
	data, err := Serialize(config)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.directory, ".wg-panel-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary WireGuard configuration: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary WireGuard configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary WireGuard configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary WireGuard configuration: %w", err)
	}
	if err := os.Rename(temporaryPath, store.pathForID(config.ID)); err != nil {
		return fmt.Errorf("replace WireGuard configuration: %w", err)
	}
	committed = true
	if directory, err := os.Open(store.directory); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (store *Store) pathForID(id int) string {
	return filepath.Join(store.directory, filenameForID(id))
}

func filenameForID(id int) string {
	return fmt.Sprintf("wg%d.conf", id)
}

func safeConfigInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: symbolic links are not allowed", ErrInvalidFile)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: configuration is not a regular file", ErrInvalidFile)
	}
	return info, nil
}

func peerIndex(peers []model.Peer, id string) int {
	for index, peer := range peers {
		if peer.ID == id {
			return index
		}
	}
	return -1
}

func checkRevision(config model.Interface, expected string) error {
	if expected == "" {
		return ErrRevisionRequired
	}
	if config.Revision != expected {
		return fmt.Errorf(
			"%w: 配置已被其他客户端或进程修改，请刷新后重试",
			ErrRevisionConflict,
		)
	}
	return nil
}

func preparePeerInput(input model.PeerInput) (model.PeerInput, bool, error) {
	systemGenerated := input.GenerateKeyPair
	if input.GenerateKeyPair {
		if input.PrivateKey != "" || input.PublicKey != "" {
			return model.PeerInput{}, false, invalid(
				"生成密钥对时不能同时提交 PrivateKey 或 PublicKey",
			)
		}
		privateKey, publicKey, err := GenerateKeyPair()
		if err != nil {
			return model.PeerInput{}, false, err
		}
		input.PrivateKey = privateKey
		input.PublicKey = publicKey
	} else if input.PrivateKey != "" && input.PublicKey == "" {
		publicKey, err := PublicKeyFromPrivate(input.PrivateKey)
		if err != nil {
			return model.PeerInput{}, false, err
		}
		input.PublicKey = publicKey
	}
	if input.GeneratePresharedKey {
		if input.PresharedKey != "" {
			return model.PeerInput{}, false, invalid(
				"生成 PresharedKey 时不能同时提交已有值",
			)
		}
		presharedKey, err := GeneratePresharedKey()
		if err != nil {
			return model.PeerInput{}, false, err
		}
		input.PresharedKey = presharedKey
	}
	normalized, err := NormalizePeer(input)
	return normalized, systemGenerated, err
}
