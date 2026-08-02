package wgconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"wireguard-panel/internal/model"
)

var managedFilename = regexp.MustCompile(`^([A-Za-z0-9_-]{1,15})\.conf$`)

const legacyRuntimeStateFilename = ".wireguard-panel-pending-restarts.json"

type Store struct {
	directory      string
	mu             sync.RWMutex
	namespaceMu    sync.Mutex
	operationMu    sync.Mutex
	operationLocks map[string]*operationLock
}

type operationLock struct {
	mu   sync.Mutex
	refs int
}

func NewStore(directory string) (*Store, error) {
	if !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("WireGuard configuration directory must be absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create WireGuard configuration directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat WireGuard configuration directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("WireGuard configuration directory must not be a symbolic link")
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("WireGuard configuration path is not a directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect WireGuard configuration directory: %w", err)
	}
	// Older builds persisted a second copy of applied configurations here.
	// The file is panel-owned and obsolete now that the native .conf file is
	// the only durable source of truth.
	if err := os.Remove(filepath.Join(directory, legacyRuntimeStateFilename)); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove obsolete WireGuard runtime state: %w", err)
	}
	return &Store{
		directory:      directory,
		operationLocks: make(map[string]*operationLock),
	}, nil
}

// lockInterfaceOperations serializes runtime-changing operations per native
// Interface without blocking read-only file access or unrelated Interfaces.
// Sorting also makes multi-Interface operations such as rename deadlock-free.
func (store *Store) lockInterfaceOperations(ids ...string) func() {
	unique := make(map[string]bool, len(ids))
	ordered := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !unique[id] {
			unique[id] = true
			ordered = append(ordered, id)
		}
	}
	sort.Strings(ordered)
	locks := make([]*operationLock, 0, len(ordered))
	store.operationMu.Lock()
	for _, id := range ordered {
		lock := store.operationLocks[id]
		if lock == nil {
			lock = &operationLock{}
			store.operationLocks[id] = lock
		}
		lock.refs++
		locks = append(locks, lock)
	}
	store.operationMu.Unlock()
	for _, lock := range locks {
		lock.mu.Lock()
	}
	return func() {
		for index := len(locks) - 1; index >= 0; index-- {
			locks[index].mu.Unlock()
		}
		store.operationMu.Lock()
		for index, id := range ordered {
			lock := locks[index]
			lock.refs--
			if lock.refs == 0 && store.operationLocks[id] == lock {
				delete(store.operationLocks, id)
			}
		}
		store.operationMu.Unlock()
	}
}

func (store *Store) List() ([]model.Interface, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.listLocked()
}

type InterfaceProblem struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Message  string `json:"message"`
}

// Inventory scans the directory once and reports every occupied native name,
// successfully parsed Interface, and per-file parse problem. Invalid files,
// directories, and symlinks still occupy their names.
func (store *Store) Inventory() (
	[]model.Interface,
	[]string,
	[]InterfaceProblem,
	error,
) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read WireGuard configuration directory: %w", err)
	}
	configs := make([]model.Interface, 0, len(entries))
	names := make([]string, 0, len(entries))
	problems := make([]InterfaceProblem, 0)
	for _, entry := range entries {
		matches := managedFilename.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue
		}
		id := matches[1]
		names = append(names, id)
		config, err := store.readLocked(id)
		if err != nil {
			problems = append(problems, InterfaceProblem{
				ID:       id,
				Filename: entry.Name(),
				Message:  err.Error(),
			})
			continue
		}
		configs = append(configs, config)
	}
	sort.Slice(configs, func(left int, right int) bool {
		return configs[left].ID < configs[right].ID
	})
	sort.Strings(names)
	return configs, names, problems, nil
}

// InventorySettled waits for every currently addressable Interface operation
// before taking the inventory snapshot. This prevents a client reconciling
// after a lost mutation response from observing a file that is still inside a
// write/runtime transaction and may yet be rolled back.
func (store *Store) InventorySettled() (
	[]model.Interface,
	[]string,
	[]InterfaceProblem,
	error,
) {
	store.namespaceMu.Lock()
	defer store.namespaceMu.Unlock()
	ids, err := store.occupiedInterfaceIDs()
	if err != nil {
		return nil, nil, nil, err
	}
	unlock := store.lockInterfaceOperations(ids...)
	defer unlock()
	return store.Inventory()
}

func (store *Store) Get(id string) (model.Interface, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.readLocked(id)
}

// GetSettled returns only a transaction boundary state. Internal mutation
// code intentionally uses Get while already holding the operation lock.
func (store *Store) GetSettled(id string) (model.Interface, error) {
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	return store.Get(id)
}

// InspectSettled keeps the transaction boundary stable while a caller checks
// related external state, such as whether the native Interface is running.
func (store *Store) InspectSettled(
	id string,
	inspect func(model.Interface) error,
) (model.Interface, error) {
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	config, err := store.Get(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := inspect(config); err != nil {
		return model.Interface{}, err
	}
	return config, nil
}

func (store *Store) Config(id string) ([]byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	config, err := store.readLocked(id)
	if err != nil {
		return nil, err
	}
	serialized, err := Serialize(config)
	if err == nil {
		return serialized, nil
	}
	data, readErr := os.ReadFile(store.pathForID(id))
	if readErr != nil {
		return nil, fmt.Errorf("read invalid WireGuard configuration for export: %w", readErr)
	}
	return data, nil
}

func (store *Store) ConfigSettled(id string) ([]byte, error) {
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	return store.Config(id)
}

// RawConfig returns the file exactly as stored so syntax or fields that the
// structured editor cannot represent can still be repaired without data loss.
func (store *Store) RawConfig(id string) ([]byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if ValidateInterfaceName(id) != nil {
		return nil, ErrNotFound
	}
	path := store.pathForID(id)
	if _, err := safeConfigInfo(path); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("read raw WireGuard configuration: %w", err)
	}
	return data, nil
}

func (store *Store) RawConfigSettled(id string) ([]byte, error) {
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	return store.RawConfig(id)
}

func (store *Store) PeerConfig(interfaceID string, publicKey string) ([]byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	config, err := store.readLocked(interfaceID)
	if err != nil {
		return nil, err
	}
	index := peerIndexByPublicKey(config.Peers, publicKey)
	if index < 0 {
		return nil, ErrPeerNotFound
	}
	return SerializePeer(config.Peers[index])
}

func (store *Store) PeerConfigSettled(interfaceID string, publicKey string) ([]byte, error) {
	unlock := store.lockInterfaceOperations(interfaceID)
	defer unlock()
	return store.PeerConfig(interfaceID, publicKey)
}

func (store *Store) IPPlan(id string) (model.IPPlan, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	config, err := store.readLocked(id)
	if err != nil {
		return model.IPPlan{}, err
	}
	return BuildIPPlan(config), nil
}

func (store *Store) IPPlanSettled(id string) (model.IPPlan, error) {
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	return store.IPPlan(id)
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
		id := matches[1]
		if filenameForID(id) != entry.Name() {
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

func (store *Store) readLocked(id string) (model.Interface, error) {
	if ValidateInterfaceName(id) != nil {
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
	return store.writeRawLocked(config.ID, data)
}

func (store *Store) write(config model.Interface) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.writeLocked(config)
}

func (store *Store) writeRaw(id string, data []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.writeRawLocked(id, data)
}

func (store *Store) configExists(id string) (bool, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if _, err := os.Lstat(store.pathForID(id)); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (store *Store) occupiedInterfaceIDs() ([]string, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard configuration directory: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if matches := managedFilename.FindStringSubmatch(entry.Name()); matches != nil {
			ids = append(ids, matches[1])
		}
	}
	return ids, nil
}

func (store *Store) remove(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := os.Remove(store.pathForID(id)); err != nil {
		return err
	}
	store.syncDirectoryLocked()
	return nil
}

func (store *Store) rename(oldID string, newID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := os.Rename(store.pathForID(oldID), store.pathForID(newID)); err != nil {
		return err
	}
	store.syncDirectoryLocked()
	return nil
}

func (store *Store) writeRawLocked(id string, data []byte) error {
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
	if err := os.Rename(temporaryPath, store.pathForID(id)); err != nil {
		return fmt.Errorf("replace WireGuard configuration: %w", err)
	}
	committed = true
	store.syncDirectoryLocked()
	return nil
}

func (store *Store) syncDirectoryLocked() {
	if directory, err := os.Open(store.directory); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
}

func (store *Store) pathForID(id string) string {
	return filepath.Join(store.directory, filenameForID(id))
}

func filenameForID(id string) string {
	return id + ".conf"
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

func peerIndexByPublicKey(peers []model.Peer, publicKey string) int {
	for index, peer := range peers {
		if peer.PublicKey == publicKey {
			return index
		}
	}
	return -1
}

func duplicatePeerPublicKey() error {
	return fmt.Errorf("%w: Peer PublicKey 不能重复", ErrConflict)
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

func preparePeerInput(input model.PeerInput) (model.PeerInput, error) {
	return NormalizePeer(input)
}
