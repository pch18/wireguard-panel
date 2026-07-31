package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"wireguard-panel/internal/model"
)

const (
	SessionLifetime        = 7 * 24 * time.Hour
	sessionCleanupInterval = 15 * time.Minute
)

type session struct {
	ExpiresAt time.Time
}

// AuthService 使用环境变量加载的单一账号认证，并在内存中保存会话。
// 配置的账号密码及浏览器 Token 原文都不会写入磁盘。
type AuthService struct {
	user          model.User
	usernameHash  [sha256.Size]byte
	passwordHash  [sha256.Size]byte
	mu            sync.Mutex
	sessions      map[[sha256.Size]byte]session
	nextCleanupAt time.Time
	now           func() time.Time
}

func NewAuthService(username string, password string) (*AuthService, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("environment username and password are required")
	}
	return &AuthService{
		user: model.User{
			Username: username,
			Name:     username,
			Role:     model.UserRoleAdmin,
		},
		usernameHash: sha256.Sum256([]byte(username)),
		passwordHash: sha256.Sum256([]byte(password)),
		sessions:     make(map[[sha256.Size]byte]session),
		now:          time.Now,
	}, nil
}

func (service *AuthService) Login(
	username string,
	password string,
) (string, model.User, bool, error) {
	usernameHash := sha256.Sum256([]byte(strings.TrimSpace(username)))
	passwordHash := sha256.Sum256([]byte(password))
	usernameMatches := subtle.ConstantTimeCompare(
		usernameHash[:],
		service.usernameHash[:],
	)
	passwordMatches := subtle.ConstantTimeCompare(
		passwordHash[:],
		service.passwordHash[:],
	)
	if usernameMatches&passwordMatches != 1 {
		return "", model.User{}, false, nil
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", model.User{}, false, fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	now := service.now()
	service.mu.Lock()
	service.cleanupExpiredLocked(now)
	service.sessions[tokenHash(token)] = session{
		ExpiresAt: now.Add(SessionLifetime),
	}
	service.mu.Unlock()
	return token, service.user, true, nil
}

func (service *AuthService) Session(token string) (model.User, bool) {
	if token == "" {
		return model.User{}, false
	}
	hash := tokenHash(token)
	now := service.now()
	service.mu.Lock()
	defer service.mu.Unlock()
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
	service.mu.Lock()
	defer service.mu.Unlock()
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
	service.mu.Lock()
	delete(service.sessions, tokenHash(token))
	service.mu.Unlock()
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
