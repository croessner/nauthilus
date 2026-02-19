package oidckeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/ksuid"
)

const (
	RedisKeyOIDCKeys   = "oidc:keys"
	RedisKeyOIDCActive = "oidc:active_kid"
)

// KeyMetadata stores metadata about an OIDC signing key.
type KeyMetadata struct {
	ID        string    `json:"id"`
	PEM       string    `json:"pem"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Manager handles OIDC signing keys.
type Manager struct {
	deps *deps.Deps
}

// NewManager creates a new Manager.
func NewManager(d *deps.Deps) *Manager {
	return &Manager{deps: d}
}

// GetActiveKey returns the current active private key and its ID.
func (m *Manager) GetActiveKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	// 1. Try to get active key from Redis
	kid, err := m.deps.Redis.GetReadHandle().Get(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCActive).Result()
	if err == nil && kid != "" {
		pemData, err := m.getEncryptedKeyFromRedis(ctx, kid)
		if err == nil {
			key, err := m.pemToPrivateKey(pemData)
			if err == nil {
				return key, kid, nil
			}
		}
	}

	// 2. If auto-rotation is enabled and no active key in Redis, generate one
	if m.deps.Cfg.GetIdP().OIDC.AutoKeyRotation {
		kid, err = m.GenerateNewKey(ctx)
		if err == nil {
			pemData, err := m.getEncryptedKeyFromRedis(ctx, kid)
			if err == nil {
				key, err := m.pemToPrivateKey(pemData)
				if err == nil {
					return key, kid, nil
				}
			}
		}
	}

	// 3. Fallback to static configuration
	oidcCfg := m.deps.Cfg.GetIdP().OIDC
	signingKey, err := oidcCfg.GetSigningKey()
	if err == nil && signingKey != "" {
		key, err := m.pemToPrivateKey(signingKey)
		if err == nil {
			return key, oidcCfg.GetSigningKeyID(), nil
		}
	}

	return nil, "", fmt.Errorf("no active OIDC signing key found")
}

// GetAllKeys returns all valid signing keys (for JWKS).
func (m *Manager) GetAllKeys(ctx context.Context) (map[string]*rsa.PrivateKey, error) {
	keys := make(map[string]*rsa.PrivateKey)

	// 1. Load from static configuration
	oidcCfg := m.deps.Cfg.GetIdP().OIDC
	// Multi keys
	for _, sk := range oidcCfg.SigningKeys {
		content, err := config.GetContent(sk.Key, sk.KeyFile)
		if err == nil {
			key, err := m.pemToPrivateKey(content)
			if err == nil {
				keys[sk.ID] = key
			}
		}
	}

	// 2. Load from Redis
	redisKeys, err := m.deps.Redis.GetReadHandle().HGetAll(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCKeys).Result()
	if err == nil {
		sm := m.deps.Redis.GetSecurityManager()
		now := time.Now()

		for kid, encryptedData := range redisKeys {
			jsonData, err := sm.Decrypt(encryptedData)
			if err != nil {
				continue
			}

			var meta KeyMetadata
			if err := json.Unmarshal([]byte(jsonData), &meta); err != nil {
				continue
			}

			// Check if key is expired
			if !meta.ExpiresAt.IsZero() && now.After(meta.ExpiresAt) {
				continue
			}

			key, err := m.pemToPrivateKey(meta.PEM)
			if err == nil {
				keys[kid] = key
			}
		}
	}

	return keys, nil
}

// GenerateNewKey generates a new RSA key, stores it in Redis and sets it as active.
func (m *Manager) GenerateNewKey(ctx context.Context) (string, error) {
	level.Info(m.deps.Logger).Log("msg", "generating new OIDC signing key")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	kid := ksuid.New().String()
	pemData := m.privateKeyToPEM(key)

	oidcCfg := m.deps.Cfg.GetIdP().OIDC
	now := time.Now()
	expiresAt := now.Add(oidcCfg.KeyMaxAge)
	if oidcCfg.KeyMaxAge == 0 {
		expiresAt = now.Add(365 * 24 * time.Hour)
	}

	metadata := KeyMetadata{
		ID:        kid,
		PEM:       pemData,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	jsonData, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}

	sm := m.deps.Redis.GetSecurityManager()
	encryptedData, err := sm.Encrypt(string(jsonData))
	if err != nil {
		return "", err
	}

	// Store in Redis
	err = m.deps.Redis.GetWriteHandle().HSet(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCKeys, kid, encryptedData).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store key in Redis: %w", err)
	}

	// Set as active
	err = m.deps.Redis.GetWriteHandle().Set(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCActive, kid, 0).Err()
	if err != nil {
		return "", fmt.Errorf("failed to set active key in Redis: %w", err)
	}

	return kid, nil
}

func (m *Manager) getEncryptedKeyFromRedis(ctx context.Context, kid string) (string, error) {
	encryptedData, err := m.deps.Redis.GetReadHandle().HGet(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCKeys, kid).Result()
	if err != nil {
		return "", err
	}

	sm := m.deps.Redis.GetSecurityManager()
	jsonData, err := sm.Decrypt(encryptedData)
	if err != nil {
		return "", err
	}

	var meta KeyMetadata
	if err := json.Unmarshal([]byte(jsonData), &meta); err != nil {
		return "", err
	}

	return meta.PEM, nil
}

func (m *Manager) privateKeyToPEM(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return string(pem.EncodeToMemory(block))
}

func (m *Manager) pemToPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	return signing.ParseRSAPrivateKeyPEM(pemData)
}

// StartRotationJob starts a background job that periodically checks and rotates the signing key.
func (m *Manager) StartRotationJob(ctx context.Context) {
	if !m.deps.Cfg.GetIdP().OIDC.AutoKeyRotation {
		return
	}

	level.Info(m.deps.Logger).Log("msg", "starting OIDC key rotation background job")

	ticker := time.NewTicker(m.deps.Cfg.GetIdP().OIDC.GetKeyRotationInterval())

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.RotateKeys(ctx)
			}
		}
	}()

	// Also run rotation check immediately on start
	go m.RotateKeys(ctx)
}

// RotateKeys checks if the active key needs rotation and generates a new one if necessary.
func (m *Manager) RotateKeys(ctx context.Context) {
	if !m.deps.Cfg.GetIdP().OIDC.AutoKeyRotation {
		return
	}

	// 1. Get current active kid from Redis
	activeKID, err := m.deps.Redis.GetReadHandle().Get(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCActive).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		level.Error(m.deps.Logger).Log("msg", "failed to get active kid from Redis", "error", err)

		return
	}

	if activeKID != "" {
		sm := m.deps.Redis.GetSecurityManager()
		encryptedData, _ := m.deps.Redis.GetReadHandle().HGet(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCKeys, activeKID).Result()
		jsonData, err := sm.Decrypt(encryptedData)

		if err == nil {
			var meta KeyMetadata
			if err := json.Unmarshal([]byte(jsonData), &meta); err == nil {
				now := time.Now()
				if now.Sub(meta.CreatedAt) < m.deps.Cfg.GetIdP().OIDC.GetKeyRotationInterval() {
					// Key is still young enough
					m.CleanupOldKeys(ctx)

					return
				}
			}
		}
	}

	// Need rotation
	_, err = m.GenerateNewKey(ctx)
	if err != nil {
		level.Error(m.deps.Logger).Log("msg", "failed to rotate OIDC signing key", "error", err)
	} else {
		level.Info(m.deps.Logger).Log("msg", "OIDC signing key rotated successfully")
	}

	// Cleanup old keys
	m.CleanupOldKeys(ctx)
}

// CleanupOldKeys removes expired keys from Redis.
func (m *Manager) CleanupOldKeys(ctx context.Context) {
	redisKeys, err := m.deps.Redis.GetReadHandle().HGetAll(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCKeys).Result()
	if err != nil {
		return
	}

	activeKID, _ := m.deps.Redis.GetReadHandle().Get(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCActive).Result()
	sm := m.deps.Redis.GetSecurityManager()
	now := time.Now()

	for kid, encryptedData := range redisKeys {
		if kid == activeKID {
			continue
		}

		jsonData, err := sm.Decrypt(encryptedData)
		if err != nil {
			continue
		}

		var meta KeyMetadata
		if err := json.Unmarshal([]byte(jsonData), &meta); err != nil {
			continue
		}

		if !meta.ExpiresAt.IsZero() && now.After(meta.ExpiresAt) {
			m.deps.Redis.GetWriteHandle().HDel(ctx, m.deps.Cfg.GetServer().GetRedis().GetPrefix()+RedisKeyOIDCKeys, kid)
			level.Info(m.deps.Logger).Log("msg", "cleaned up expired OIDC signing key", "kid", kid)
		}
	}
}
