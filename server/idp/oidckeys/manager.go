package oidckeys

import (
	"context"
	"crypto"
	"crypto/ed25519"
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
	RedisKeyOIDCKeys     = "oidc:keys"
	RedisKeyOIDCActive   = "oidc:active_kid"
	RedisKeyOIDCEdActive = "oidc:active_ed_kid"
	RedisKeyOIDCEdKeys   = "oidc:ed_keys"
)

// KeyMetadata stores metadata about an OIDC signing key.
type KeyMetadata struct {
	ID        string    `json:"id"`
	PEM       string    `json:"pem"`
	Algorithm string    `json:"algorithm,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SigningKeyEntry holds a parsed signing key with its algorithm and public key.
type SigningKeyEntry struct {
	Signer    signing.Signer
	Algorithm string
	PublicKey crypto.PublicKey
}

// Manager handles OIDC signing keys.
type Manager struct {
	deps *deps.Deps
}

// NewManager creates a new Manager.
func NewManager(d *deps.Deps) *Manager {
	return &Manager{deps: d}
}

// GetActiveSigner returns the current active signer for the given algorithm.
// If algorithm is empty, it defaults to RS256.
func (m *Manager) GetActiveSigner(ctx context.Context, algorithm string) (signing.Signer, error) {
	if algorithm == "" || algorithm == signing.AlgorithmRS256 {
		return m.getActiveRSASigner(ctx)
	}

	if algorithm == signing.AlgorithmEdDSA {
		return m.getActiveEdDSASigner(ctx)
	}

	return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
}

// getActiveRSASigner returns the current active RSA signer.
func (m *Manager) getActiveRSASigner(ctx context.Context) (signing.Signer, error) {
	key, kid, err := m.GetActiveKey(ctx)
	if err != nil {
		return nil, err
	}

	return signing.NewRS256Signer(key, kid), nil
}

// getActiveEdDSASigner returns the current active EdDSA signer.
func (m *Manager) getActiveEdDSASigner(ctx context.Context) (signing.Signer, error) {
	// 1. Try Redis
	kid, err := m.deps.Redis.GetReadHandle().Get(ctx, m.redisPrefix()+RedisKeyOIDCEdActive).Result()
	if err == nil && kid != "" {
		pemData, err := m.getEncryptedEdKeyFromRedis(ctx, kid)
		if err == nil {
			edKey, err := signing.ParseEd25519PrivateKeyPEM(pemData)
			if err == nil {
				return signing.NewEdDSASigner(edKey, kid), nil
			}
		}
	}

	// 2. Auto-generate if rotation is enabled
	if m.deps.Cfg.GetIdP().OIDC.AutoKeyRotation {
		kid, err = m.GenerateNewEdKey(ctx)
		if err == nil {
			pemData, err := m.getEncryptedEdKeyFromRedis(ctx, kid)
			if err == nil {
				edKey, err := signing.ParseEd25519PrivateKeyPEM(pemData)
				if err == nil {
					return signing.NewEdDSASigner(edKey, kid), nil
				}
			}
		}
	}

	// 3. Fallback to static configuration
	oidcCfg := m.deps.Cfg.GetIdP().OIDC

	for _, sk := range oidcCfg.SigningKeys {
		if sk.Active && sk.GetAlgorithm() == signing.AlgorithmEdDSA {
			content, err := config.GetContent(sk.Key, sk.KeyFile)
			if err != nil {
				continue
			}

			edKey, err := signing.ParseEd25519PrivateKeyPEM(content)
			if err != nil {
				continue
			}

			return signing.NewEdDSASigner(edKey, sk.ID), nil
		}
	}

	return nil, fmt.Errorf("no active EdDSA signing key found")
}

// GetActiveKey returns the current active RSA private key and its ID.
func (m *Manager) GetActiveKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	// 1. Try to get active key from Redis
	kid, err := m.deps.Redis.GetReadHandle().Get(ctx, m.redisPrefix()+RedisKeyOIDCActive).Result()
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

// GetAllKeys returns all valid RSA signing keys (for JWKS).
func (m *Manager) GetAllKeys(ctx context.Context) (map[string]*rsa.PrivateKey, error) {
	keys := make(map[string]*rsa.PrivateKey)

	// 1. Load RSA keys from static configuration
	oidcCfg := m.deps.Cfg.GetIdP().OIDC

	for _, sk := range oidcCfg.SigningKeys {
		if sk.GetAlgorithm() != signing.AlgorithmRS256 {
			continue
		}

		content, err := config.GetContent(sk.Key, sk.KeyFile)
		if err == nil {
			key, err := m.pemToPrivateKey(content)
			if err == nil {
				keys[sk.ID] = key
			}
		}
	}

	// 2. Load from Redis
	keys, err := m.loadRSAKeysFromRedis(ctx, keys)
	if err != nil {
		return keys, nil
	}

	return keys, nil
}

// GetAllEdKeys returns all valid Ed25519 signing keys (for JWKS).
func (m *Manager) GetAllEdKeys(ctx context.Context) (map[string]ed25519.PrivateKey, error) {
	keys := make(map[string]ed25519.PrivateKey)

	// 1. Load Ed25519 keys from static configuration
	oidcCfg := m.deps.Cfg.GetIdP().OIDC

	for _, sk := range oidcCfg.SigningKeys {
		if sk.GetAlgorithm() != signing.AlgorithmEdDSA {
			continue
		}

		content, err := config.GetContent(sk.Key, sk.KeyFile)
		if err == nil {
			key, err := signing.ParseEd25519PrivateKeyPEM(content)
			if err == nil {
				keys[sk.ID] = key
			}
		}
	}

	// 2. Load from Redis
	keys, err := m.loadEdKeysFromRedis(ctx, keys)
	if err != nil {
		return keys, nil
	}

	return keys, nil
}

// loadRSAKeysFromRedis loads RSA keys from Redis into the provided map.
func (m *Manager) loadRSAKeysFromRedis(ctx context.Context, keys map[string]*rsa.PrivateKey) (map[string]*rsa.PrivateKey, error) {
	redisKeys, err := m.deps.Redis.GetReadHandle().HGetAll(ctx, m.redisPrefix()+RedisKeyOIDCKeys).Result()
	if err != nil {
		return keys, err
	}

	sm := m.deps.Redis.GetSecurityManager()
	now := time.Now()

	for kid, encryptedData := range redisKeys {
		meta, err := m.decryptMetadata(sm, encryptedData)
		if err != nil || isExpired(meta, now) {
			continue
		}

		key, err := m.pemToPrivateKey(meta.PEM)
		if err == nil {
			keys[kid] = key
		}
	}

	return keys, nil
}

// loadEdKeysFromRedis loads Ed25519 keys from Redis into the provided map.
func (m *Manager) loadEdKeysFromRedis(ctx context.Context, keys map[string]ed25519.PrivateKey) (map[string]ed25519.PrivateKey, error) {
	redisKeys, err := m.deps.Redis.GetReadHandle().HGetAll(ctx, m.redisPrefix()+RedisKeyOIDCEdKeys).Result()
	if err != nil {
		return keys, err
	}

	sm := m.deps.Redis.GetSecurityManager()
	now := time.Now()

	for kid, encryptedData := range redisKeys {
		meta, err := m.decryptMetadata(sm, encryptedData)
		if err != nil || isExpired(meta, now) {
			continue
		}

		key, err := signing.ParseEd25519PrivateKeyPEM(meta.PEM)
		if err == nil {
			keys[kid] = key
		}
	}

	return keys, nil
}

// GenerateNewKey generates a new RSA key, stores it in Redis and sets it as active.
func (m *Manager) GenerateNewKey(ctx context.Context) (string, error) {
	level.Info(m.deps.Logger).Log("msg", "generating new OIDC RSA signing key")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	kid := ksuid.New().String()
	pemData := m.rsaPrivateKeyToPEM(key)

	return m.storeKeyInRedis(ctx, kid, pemData, signing.AlgorithmRS256, RedisKeyOIDCKeys, RedisKeyOIDCActive)
}

// GenerateNewEdKey generates a new Ed25519 key, stores it in Redis and sets it as active.
func (m *Manager) GenerateNewEdKey(ctx context.Context) (string, error) {
	level.Info(m.deps.Logger).Log("msg", "generating new OIDC Ed25519 signing key")

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	kid := ksuid.New().String()
	pemData, err := m.ed25519PrivateKeyToPEM(privKey)

	if err != nil {
		return "", fmt.Errorf("failed to encode Ed25519 key to PEM: %w", err)
	}

	return m.storeKeyInRedis(ctx, kid, pemData, signing.AlgorithmEdDSA, RedisKeyOIDCEdKeys, RedisKeyOIDCEdActive)
}

// storeKeyInRedis stores a key in Redis and sets it as active.
func (m *Manager) storeKeyInRedis(ctx context.Context, kid, pemData, algorithm, hashKey, activeKey string) (string, error) {
	oidcCfg := m.deps.Cfg.GetIdP().OIDC
	now := time.Now()

	expiresAt := now.Add(oidcCfg.KeyMaxAge)
	if oidcCfg.KeyMaxAge == 0 {
		expiresAt = now.Add(365 * 24 * time.Hour)
	}

	metadata := KeyMetadata{
		ID:        kid,
		PEM:       pemData,
		Algorithm: algorithm,
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

	prefix := m.redisPrefix()

	// Store in Redis
	err = m.deps.Redis.GetWriteHandle().HSet(ctx, prefix+hashKey, kid, encryptedData).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store key in Redis: %w", err)
	}

	// Set as active
	err = m.deps.Redis.GetWriteHandle().Set(ctx, prefix+activeKey, kid, 0).Err()
	if err != nil {
		return "", fmt.Errorf("failed to set active key in Redis: %w", err)
	}

	return kid, nil
}

func (m *Manager) getEncryptedKeyFromRedis(ctx context.Context, kid string) (string, error) {
	return m.getEncryptedKeyFromRedisHash(ctx, kid, RedisKeyOIDCKeys)
}

func (m *Manager) getEncryptedEdKeyFromRedis(ctx context.Context, kid string) (string, error) {
	return m.getEncryptedKeyFromRedisHash(ctx, kid, RedisKeyOIDCEdKeys)
}

func (m *Manager) getEncryptedKeyFromRedisHash(ctx context.Context, kid, hashKey string) (string, error) {
	encryptedData, err := m.deps.Redis.GetReadHandle().HGet(ctx, m.redisPrefix()+hashKey, kid).Result()
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

func (m *Manager) rsaPrivateKeyToPEM(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return string(pem.EncodeToMemory(block))
}

func (m *Manager) ed25519PrivateKeyToPEM(key ed25519.PrivateKey) (string, error) {
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

func (m *Manager) pemToPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	return signing.ParseRSAPrivateKeyPEM(pemData)
}

// decryptMetadata decrypts and unmarshals key metadata.
func (m *Manager) decryptMetadata(sm interface{ Decrypt(string) (string, error) }, encryptedData string) (*KeyMetadata, error) {
	jsonData, err := sm.Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var meta KeyMetadata

	if err := json.Unmarshal([]byte(jsonData), &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// isExpired checks if a key metadata entry is expired.
func isExpired(meta *KeyMetadata, now time.Time) bool {
	return !meta.ExpiresAt.IsZero() && now.After(meta.ExpiresAt)
}

// redisPrefix returns the Redis key prefix.
func (m *Manager) redisPrefix() string {
	return m.deps.Cfg.GetServer().GetRedis().GetPrefix()
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

// RotateKeys checks if the active keys need rotation and generates new ones if necessary.
func (m *Manager) RotateKeys(ctx context.Context) {
	if !m.deps.Cfg.GetIdP().OIDC.AutoKeyRotation {
		return
	}

	m.rotateKeyType(ctx, RedisKeyOIDCActive, RedisKeyOIDCKeys, "RSA", m.GenerateNewKey)
	m.rotateKeyType(ctx, RedisKeyOIDCEdActive, RedisKeyOIDCEdKeys, "EdDSA", m.GenerateNewEdKey)

	// Cleanup old keys
	m.CleanupOldKeys(ctx)
}

// rotateKeyType checks and rotates a specific key type.
func (m *Manager) rotateKeyType(ctx context.Context, activeRedisKey, hashRedisKey, label string, generateFn func(context.Context) (string, error)) {
	prefix := m.redisPrefix()

	activeKID, err := m.deps.Redis.GetReadHandle().Get(ctx, prefix+activeRedisKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		level.Error(m.deps.Logger).Log("msg", "failed to get active kid from Redis", "algorithm", label, "error", err)

		return
	}

	if activeKID != "" {
		sm := m.deps.Redis.GetSecurityManager()

		encryptedData, _ := m.deps.Redis.GetReadHandle().HGet(ctx, prefix+hashRedisKey, activeKID).Result()

		meta, err := m.decryptMetadata(sm, encryptedData)
		if err == nil {
			if time.Since(meta.CreatedAt) < m.deps.Cfg.GetIdP().OIDC.GetKeyRotationInterval() {
				return
			}
		}
	}

	// Need rotation
	_, err = generateFn(ctx)
	if err != nil {
		level.Error(m.deps.Logger).Log("msg", "failed to rotate OIDC signing key", "algorithm", label, "error", err)
	} else {
		level.Info(m.deps.Logger).Log("msg", "OIDC signing key rotated successfully", "algorithm", label)
	}
}

// CleanupOldKeys removes expired keys from Redis.
func (m *Manager) CleanupOldKeys(ctx context.Context) {
	m.cleanupKeysInHash(ctx, RedisKeyOIDCKeys, RedisKeyOIDCActive)
	m.cleanupKeysInHash(ctx, RedisKeyOIDCEdKeys, RedisKeyOIDCEdActive)
}

// cleanupKeysInHash removes expired keys from a specific Redis hash.
func (m *Manager) cleanupKeysInHash(ctx context.Context, hashKey, activeKey string) {
	prefix := m.redisPrefix()

	redisKeys, err := m.deps.Redis.GetReadHandle().HGetAll(ctx, prefix+hashKey).Result()
	if err != nil {
		return
	}

	activeKID, _ := m.deps.Redis.GetReadHandle().Get(ctx, prefix+activeKey).Result()
	sm := m.deps.Redis.GetSecurityManager()
	now := time.Now()

	for kid, encryptedData := range redisKeys {
		if kid == activeKID {
			continue
		}

		meta, err := m.decryptMetadata(sm, encryptedData)
		if err != nil {
			continue
		}

		if isExpired(meta, now) {
			m.deps.Redis.GetWriteHandle().HDel(ctx, prefix+hashKey, kid)
			level.Info(m.deps.Logger).Log("msg", "cleaned up expired OIDC signing key", "kid", kid)
		}
	}
}
