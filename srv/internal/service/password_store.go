package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const credentialFileVersion = 1

var ErrCredentialsNotConfigured = errors.New("credentials are not configured")

type StoredCredentials struct {
	Username     string
	PasswordHash []byte
}

type CredentialStore interface {
	Load() (StoredCredentials, error)
	Save(credentials StoredCredentials) error
}

type FileCredentialStore struct {
	path string
}

type credentialFile struct {
	Version      int    `json:"version"`
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

func NewFileCredentialStore(path string) (*FileCredentialStore, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("authentication file path must be absolute")
	}
	return &FileCredentialStore{path: path}, nil
}

func (store *FileCredentialStore) Load() (StoredCredentials, error) {
	info, err := os.Lstat(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return StoredCredentials{}, ErrCredentialsNotConfigured
		}
		return StoredCredentials{}, fmt.Errorf("inspect authentication file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return StoredCredentials{}, fmt.Errorf("authentication file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return StoredCredentials{}, fmt.Errorf("authentication file is not a regular file")
	}
	if err := os.Chmod(store.path, 0o600); err != nil {
		return StoredCredentials{}, fmt.Errorf("protect authentication file: %w", err)
	}

	data, err := os.ReadFile(store.path)
	if err != nil {
		return StoredCredentials{}, fmt.Errorf("read authentication file: %w", err)
	}
	var file credentialFile
	if err := json.Unmarshal(data, &file); err != nil {
		return StoredCredentials{}, fmt.Errorf("parse authentication file: %w", err)
	}
	if file.Version != credentialFileVersion || file.PasswordHash == "" {
		return StoredCredentials{}, fmt.Errorf("authentication file has an unsupported format")
	}
	return StoredCredentials{
		Username:     file.Username,
		PasswordHash: []byte(file.PasswordHash),
	}, nil
}

func (store *FileCredentialStore) Save(credentials StoredCredentials) error {
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create authentication directory: %w", err)
	}
	if err := rejectSymlink(store.path); err != nil {
		return err
	}

	data, err := json.MarshalIndent(credentialFile{
		Version:      credentialFileVersion,
		Username:     credentials.Username,
		PasswordHash: string(credentials.PasswordHash),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode authentication file: %w", err)
	}
	data = append(data, '\n')

	temporary, err := os.CreateTemp(directory, ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary authentication file: %w", err)
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
		return fmt.Errorf("protect temporary authentication file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary authentication file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary authentication file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary authentication file: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("replace authentication file: %w", err)
	}
	committed = true

	// Rename is the commit point. Directory fsync improves crash durability where
	// supported, but must not report failure after the new credentials are visible.
	directoryHandle, err := os.Open(directory)
	if err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect authentication file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("authentication file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("authentication file is not a regular file")
	}
	return nil
}
