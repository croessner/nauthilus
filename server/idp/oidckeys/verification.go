// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package oidckeys

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/croessner/nauthilus/v4/server/idp/signing"
	"github.com/redis/go-redis/v9"
)

// VerificationKeyByID returns the public key that verifies tokens signed with key kid of algorithm.
//
// Redis-held keys are served from a short-lived process cache of public keys; unknown key IDs and store
// failures are never cached. Static configuration keys are consulted when Redis does not hold the key.
func (m *Manager) VerificationKeyByID(ctx context.Context, algorithm string, kid string) (crypto.PublicKey, error) {
	_, label := keyStoreFor(algorithm)
	if kid == "" {
		return nil, fmt.Errorf("%s key ID is required", label)
	}

	publicKey, redisErr := m.cachedRedisVerificationKey(ctx, algorithm, kid)
	if redisErr == nil {
		return publicKey, nil
	}

	if publicKey, err := m.staticVerificationKeyByID(algorithm, kid); err == nil {
		return publicKey, nil
	}

	return nil, keyByIDNotFoundError(label, kid, redisErr)
}

// ActiveVerificationKey returns the public key of the active signing key for tokens that carry no kid.
//
// Unlike the signing path it never generates keys, because token validation must not change key state.
// When the Redis key store cannot be read and no static key replaces it, the failure is reported as
// ErrKeyStoreUnavailable instead of an absent key.
func (m *Manager) ActiveVerificationKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	activeKey := RedisKeyOIDCActive
	if algorithm == signing.AlgorithmEdDSA {
		activeKey = RedisKeyOIDCEdActive
	}

	readCtx, cancel := m.redisReadContext(ctx)
	kid, err := m.deps.Redis.GetReadHandle().Get(readCtx, m.redisPrefix()+activeKey).Result()

	cancel()

	var storeErr error

	switch {
	case err == nil && kid != "":
		publicKey, keyErr := m.cachedRedisVerificationKey(ctx, algorithm, kid)
		if keyErr == nil {
			return publicKey, nil
		}

		if errors.Is(keyErr, ErrKeyStoreUnavailable) {
			storeErr = keyErr
		}
	case err != nil && !errors.Is(err, redis.Nil):
		storeErr = fmt.Errorf("%w: %w", ErrKeyStoreUnavailable, err)
	}

	if publicKey, ok := m.staticVerificationKey(algorithm); ok {
		return publicKey, nil
	}

	if storeErr != nil {
		return nil, storeErr
	}

	return nil, fmt.Errorf("no active %s verification key found", algorithm)
}

// cachedRedisVerificationKey serves one Redis-held public key from the cache or loads and caches it.
// The generation is captured before the read so a concurrent rotation cannot resurrect a stale entry.
func (m *Manager) cachedRedisVerificationKey(ctx context.Context, algorithm string, kid string) (crypto.PublicKey, error) {
	hashKey, _ := keyStoreFor(algorithm)
	cacheKey := verificationKeyCacheKey{hashKey: hashKey, kid: kid}

	if publicKey, ok := m.verificationKeys.get(cacheKey); ok {
		return publicKey, nil
	}

	generation := verificationKeyGeneration.Load()

	publicKey, expiresAt, err := m.redisVerificationKey(ctx, algorithm, kid)
	if err != nil {
		return nil, err
	}

	m.verificationKeys.put(cacheKey, publicKey, expiresAt, generation)

	return publicKey, nil
}

// redisVerificationKey loads, decrypts and parses one Redis-held key and returns only its public half and expiry.
func (m *Manager) redisVerificationKey(ctx context.Context, algorithm string, kid string) (crypto.PublicKey, time.Time, error) {
	meta, err := m.unexpiredKeyMetadata(ctx, algorithm, kid)
	if err != nil {
		return nil, time.Time{}, err
	}

	if algorithm == signing.AlgorithmEdDSA {
		key, err := signing.ParseEd25519PrivateKeyPEM(meta.PEM)
		if err != nil {
			return nil, time.Time{}, err
		}

		return key.Public(), meta.ExpiresAt, nil
	}

	key, err := m.pemToPrivateKey(meta.PEM)
	if err != nil {
		return nil, time.Time{}, err
	}

	return detachedRSAPublicKey(key), meta.ExpiresAt, nil
}

// staticVerificationKeyByID returns the public key of the configured static key kid of algorithm.
func (m *Manager) staticVerificationKeyByID(algorithm string, kid string) (crypto.PublicKey, error) {
	if algorithm == signing.AlgorithmEdDSA {
		key, err := m.getStaticEdKeyByID(kid)
		if err != nil {
			return nil, err
		}

		return key.Public(), nil
	}

	key, err := m.getStaticRSAKeyByID(kid)
	if err != nil {
		return nil, err
	}

	return detachedRSAPublicKey(key), nil
}

// detachedRSAPublicKey copies the public half so no reference to the private key outlives the lookup.
func detachedRSAPublicKey(key *rsa.PrivateKey) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
}

// staticVerificationKey returns the public key of the active static signing key of algorithm.
func (m *Manager) staticVerificationKey(algorithm string) (crypto.PublicKey, bool) {
	if algorithm == signing.AlgorithmEdDSA {
		signer, ok := m.staticEdDSASigner()
		if !ok {
			return nil, false
		}

		return signer.PublicKey(), true
	}

	content, _, err := m.activeStaticKeyContent()
	if err != nil || content == "" {
		return nil, false
	}

	key, err := m.pemToPrivateKey(content)
	if err != nil {
		return nil, false
	}

	return detachedRSAPublicKey(key), true
}
