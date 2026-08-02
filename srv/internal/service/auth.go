package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"wireguard-panel/internal/model"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionLifetime        = 7 * 24 * time.Hour
	sessionCleanupInterval = 15 * time.Minute
	minimumPasswordLength  = 8
	maximumPasswordBytes   = 72
	defaultInitialUsername = "admin"
	defaultInitialPassword = "admin5555"
)

var (
	ErrCurrentPasswordMismatch = errors.New("当前密码错误")
	ErrPasswordUnchanged       = errors.New("新密码不能与当前密码相同")
	ErrInvalidNewPassword      = errors.New("新密码必须至少包含 8 个字符且不能超过 72 字节")
)

type session struct {
	ExpiresAt time.Time
}

// AuthService 使用单一管理员账号认证，并在内存中保存会话。
// 密码仅以 bcrypt 哈希形式持久化，浏览器 Token 原文不会写入磁盘。
type AuthService struct {
	user         model.User
	usernameHash [sha256.Size]byte
	passwordHash []byte
	credentials  CredentialStore
	credentialMu sync.RWMutex
	sessionMu    sync.Mutex

	sessions      map[[sha256.Size]byte]session
	nextCleanupAt time.Time
	now           func() time.Time
}

func NewAuthService(username string, password string) (*AuthService, error) {
	username, err := normalizedUsername(username)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return newAuthService(username, passwordHash, nil), nil
}

func NewPersistentAuthService(
	credentials CredentialStore,
) (*AuthService, error) {
	if credentials == nil {
		return nil, fmt.Errorf("credential store is required")
	}

	stored, err := credentials.Load()
	switch {
	case err == nil:
		migrateUsername := strings.TrimSpace(stored.Username) == ""
		if migrateUsername {
			stored.Username = defaultInitialUsername
		}
		stored.Username, err = normalizedUsername(stored.Username)
		if err != nil {
			return nil, fmt.Errorf("stored username is invalid: %w", err)
		}
		if _, err := bcrypt.Cost(stored.PasswordHash); err != nil {
			return nil, fmt.Errorf("stored password hash is invalid: %w", err)
		}
		if migrateUsername {
			if err := credentials.Save(stored); err != nil {
				return nil, fmt.Errorf("migrate stored username: %w", err)
			}
		}
	case errors.Is(err, ErrCredentialsNotConfigured):
		stored.Username = defaultInitialUsername
		stored.PasswordHash, err = bcrypt.GenerateFromPassword(
			[]byte(defaultInitialPassword),
			bcrypt.DefaultCost,
		)
		if err != nil {
			return nil, fmt.Errorf("hash initial password: %w", err)
		}
		if err := credentials.Save(stored); err != nil {
			return nil, fmt.Errorf("save initial credentials: %w", err)
		}
	default:
		return nil, err
	}
	return newAuthService(stored.Username, stored.PasswordHash, credentials), nil
}

func newAuthService(
	username string,
	passwordHash []byte,
	credentials CredentialStore,
) *AuthService {
	return &AuthService{
		user: model.User{
			Username: username,
			Name:     username,
			Role:     model.UserRoleAdmin,
		},
		usernameHash: sha256.Sum256([]byte(username)),
		passwordHash: append([]byte(nil), passwordHash...),
		credentials:  credentials,
		sessions:     make(map[[sha256.Size]byte]session),
		now:          time.Now,
	}
}

func (service *AuthService) Login(
	username string,
	password string,
) (string, model.User, bool, error) {
	usernameHash := sha256.Sum256([]byte(strings.TrimSpace(username)))
	usernameMatches := subtle.ConstantTimeCompare(
		usernameHash[:],
		service.usernameHash[:],
	)

	service.credentialMu.RLock()
	defer service.credentialMu.RUnlock()
	passwordMatches := bcrypt.CompareHashAndPassword(
		service.passwordHash,
		[]byte(password),
	) == nil
	if usernameMatches != 1 || !passwordMatches {
		return "", model.User{}, false, nil
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", model.User{}, false, fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	now := service.now()
	service.sessionMu.Lock()
	service.cleanupExpiredLocked(now)
	service.sessions[tokenHash(token)] = session{
		ExpiresAt: now.Add(SessionLifetime),
	}
	service.sessionMu.Unlock()
	return token, service.user, true, nil
}

func (service *AuthService) Session(token string) (model.User, bool) {
	if token == "" {
		return model.User{}, false
	}
	hash := tokenHash(token)
	now := service.now()
	service.sessionMu.Lock()
	defer service.sessionMu.Unlock()
	service.cleanupExpiredLocked(now)
	current, valid := service.sessions[hash]
	if !valid || !now.Before(current.ExpiresAt) {
		delete(service.sessions, hash)
		return model.User{}, false
	}
	return service.user, true
}

func (service *AuthService) RenewSession(token string) bool {
	hash := tokenHash(token)
	now := service.now()
	service.sessionMu.Lock()
	defer service.sessionMu.Unlock()
	service.cleanupExpiredLocked(now)
	current, valid := service.sessions[hash]
	if !valid || !now.Before(current.ExpiresAt) {
		delete(service.sessions, hash)
		return false
	}
	current.ExpiresAt = now.Add(SessionLifetime)
	service.sessions[hash] = current
	return true
}

func (service *AuthService) Logout(token string) {
	service.sessionMu.Lock()
	delete(service.sessions, tokenHash(token))
	service.sessionMu.Unlock()
}

func (service *AuthService) ChangePassword(
	currentPassword string,
	newPassword string,
	currentToken string,
) error {
	if utf8.RuneCountInString(newPassword) < minimumPasswordLength ||
		len([]byte(newPassword)) > maximumPasswordBytes {
		return ErrInvalidNewPassword
	}

	service.credentialMu.Lock()
	defer service.credentialMu.Unlock()
	if bcrypt.CompareHashAndPassword(
		service.passwordHash,
		[]byte(currentPassword),
	) != nil {
		return ErrCurrentPasswordMismatch
	}
	if currentPassword == newPassword {
		return ErrPasswordUnchanged
	}
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(newPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}
	if service.credentials != nil {
		if err := service.credentials.Save(StoredCredentials{
			Username:     service.user.Username,
			PasswordHash: passwordHash,
		}); err != nil {
			return fmt.Errorf("persist new password: %w", err)
		}
	}
	service.passwordHash = append(service.passwordHash[:0], passwordHash...)

	currentSession := tokenHash(currentToken)
	service.sessionMu.Lock()
	for hash := range service.sessions {
		if hash != currentSession {
			delete(service.sessions, hash)
		}
	}
	service.sessionMu.Unlock()
	return nil
}

func (service *AuthService) cleanupExpiredLocked(now time.Time) {
	if !service.nextCleanupAt.IsZero() && now.Before(service.nextCleanupAt) {
		return
	}
	for hash, current := range service.sessions {
		if !now.Before(current.ExpiresAt) {
			delete(service.sessions, hash)
		}
	}
	service.nextCleanupAt = now.Add(sessionCleanupInterval)
}

func tokenHash(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func normalizedUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" ||
		strings.ContainsAny(username, "\r\n") ||
		utf8.RuneCountInString(username) > 128 {
		return "", fmt.Errorf("username cannot be empty, contain newlines, or exceed 128 characters")
	}
	return username, nil
}
