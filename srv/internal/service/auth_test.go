package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvironmentAuthenticationAndSession(t *testing.T) {
	service, err := NewAuthService("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, authenticated, err := service.Login("admin", "wrong"); err != nil {
		t.Fatal(err)
	} else if authenticated {
		t.Fatal("wrong password authenticated")
	}

	token, user, authenticated, err := service.Login("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !authenticated || user.Username != "admin" || token == "" {
		t.Fatalf("unexpected login result: authenticated=%v user=%#v", authenticated, user)
	}
	if sessionUser, valid := service.Session(token); !valid || sessionUser != user {
		t.Fatalf("session user = %#v, valid=%v", sessionUser, valid)
	}
	service.Logout(token)
	if _, valid := service.Session(token); valid {
		t.Fatal("logged out session remained valid")
	}
}

func TestPersistentCredentialsSurviveRestart(t *testing.T) {
	authDirectory := filepath.Join(t.TempDir(), "auth")
	path := filepath.Join(authDirectory, "auth.json")
	store, err := NewFileCredentialStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPersistentAuthService(store)
	if err != nil {
		t.Fatal(err)
	}
	currentToken, _, authenticated, err := service.Login("admin", "admin5555")
	if err != nil || !authenticated {
		t.Fatalf("initial password did not authenticate: authenticated=%v err=%v", authenticated, err)
	}
	otherToken, _, authenticated, err := service.Login("admin", "admin5555")
	if err != nil || !authenticated {
		t.Fatalf("second login failed: authenticated=%v err=%v", authenticated, err)
	}
	if err := service.ChangePassword("admin5555", "NewPassword888", currentToken); err != nil {
		t.Fatal(err)
	}
	if _, valid := service.Session(currentToken); !valid {
		t.Fatal("current session was invalidated")
	}
	if _, valid := service.Session(otherToken); valid {
		t.Fatal("other session remained valid")
	}
	if _, _, authenticated, err := service.Login("admin", "admin5555"); err != nil {
		t.Fatal(err)
	} else if authenticated {
		t.Fatal("old password remained valid")
	}

	stored, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	stored.Username = "operator"
	if err := store.Save(stored); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPersistentAuthService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, authenticated, err := restarted.Login("operator", "NewPassword888"); err != nil {
		t.Fatal(err)
	} else if !authenticated {
		t.Fatal("persisted credentials did not survive restart")
	}
	if _, _, authenticated, err := restarted.Login("admin", "NewPassword888"); err != nil {
		t.Fatal(err)
	} else if authenticated {
		t.Fatal("old username remained valid")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("authentication file mode = %o", info.Mode().Perm())
	}
	directoryInfo, err := os.Stat(authDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("authentication directory mode = %o", directoryInfo.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "NewPassword888") ||
		strings.Contains(string(data), "admin5555") {
		t.Fatalf("authentication file contains plaintext password: %s", data)
	}
	var file credentialFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != credentialFileVersion ||
		file.Username != "operator" ||
		file.PasswordHash == "" {
		t.Fatalf("unexpected authentication file: %#v", file)
	}
}

func TestPersistentCredentialsMigrateMissingUsername(t *testing.T) {
	store, err := NewFileCredentialStore(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := NewAuthService("admin", "ExistingPassword888")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(StoredCredentials{PasswordHash: legacy.passwordHash}); err != nil {
		t.Fatal(err)
	}
	persistent, err := NewPersistentAuthService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, authenticated, err := persistent.Login("admin", "ExistingPassword888"); err != nil || !authenticated {
		t.Fatalf("migrated credentials did not authenticate: authenticated=%v err=%v", authenticated, err)
	}
	stored, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Username != "admin" {
		t.Fatalf("migrated username = %q", stored.Username)
	}
}

func TestChangePasswordValidation(t *testing.T) {
	service, err := NewAuthService("admin", "admin5555")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword("wrong", "NewPassword888", ""); !errors.Is(err, ErrCurrentPasswordMismatch) {
		t.Fatalf("wrong current password returned %v", err)
	}
	if err := service.ChangePassword("admin5555", "short", ""); !errors.Is(err, ErrInvalidNewPassword) {
		t.Fatalf("short password returned %v", err)
	}
	if err := service.ChangePassword("admin5555", "admin5555", ""); !errors.Is(err, ErrPasswordUnchanged) {
		t.Fatalf("unchanged password returned %v", err)
	}
}
