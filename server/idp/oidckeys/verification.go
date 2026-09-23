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
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/idp/signing"
	"github.com/redis/go-redis/v9"
)

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
		publicKey, keyErr := m.redisVerificationKey(ctx, algorithm, kid)
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

// redisVerificationKey loads the public key of one Redis-held signing key.
func (m *Manager) redisVerificationKey(ctx context.Context, algorithm string, kid string) (crypto.PublicKey, error) {
	if algorithm == signing.AlgorithmEdDSA {
		key, err := m.getEdKeyFromRedis(ctx, kid)
		if err != nil {
			return nil, err
		}

		return key.Public(), nil
	}

	key, err := m.getRSAKeyFromRedis(ctx, kid)
	if err != nil {
		return nil, err
	}

	return &key.PublicKey, nil
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

	return &key.PublicKey, true
}
