// Copyright (C) 2026 Christian Roessner
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

package grpcauthority

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/redis/go-redis/v9"
)

const (
	defaultBackendRefKeyPrefix = "grpc:authority:backend_ref:"
	defaultBackendRefTTL       = 15 * time.Minute
	backendRefSchemaVersion    = 1
)

var (
	// ErrBackendRefInvalid means the opaque handle or stored payload is malformed.
	ErrBackendRefInvalid = errors.New("backend reference is invalid")

	// ErrBackendRefExpired means Redis no longer has an active payload for the handle.
	ErrBackendRefExpired = errors.New("backend reference is expired")

	// ErrBackendRefPrincipalMismatch means the caller principal is not bound to the handle.
	ErrBackendRefPrincipalMismatch = errors.New("backend reference service principal mismatch")

	// ErrBackendRefEdgeClusterMismatch means the request came from a different edge cluster.
	ErrBackendRefEdgeClusterMismatch = errors.New("backend reference edge cluster mismatch")

	// ErrBackendRefOperationDenied means the handle is not valid for the requested operation.
	ErrBackendRefOperationDenied = errors.New("backend reference operation denied")

	// ErrBackendRefUsernameMismatch means the handle was issued for another user.
	ErrBackendRefUsernameMismatch = errors.New("backend reference username mismatch")
)

// RedisBackendRefStoreOptions configures authority backend-reference persistence.
type RedisBackendRefStoreOptions struct {
	KeyPrefix string
	Authority string
	TTL       time.Duration
}

// RedisBackendRefStore stores opaque authority backend references in Redis.
type RedisBackendRefStore struct {
	client    rediscli.Client
	keyPrefix string
	authority string
	ttl       time.Duration
}

// NewRedisBackendRefStore constructs a Redis-backed authority reference store.
func NewRedisBackendRefStore(client rediscli.Client, options RedisBackendRefStoreOptions) *RedisBackendRefStore {
	store := &RedisBackendRefStore{
		client:    client,
		keyPrefix: strings.TrimSpace(options.KeyPrefix),
		authority: strings.TrimSpace(options.Authority),
		ttl:       options.TTL,
	}

	if store.keyPrefix == "" {
		store.keyPrefix = defaultBackendRefKeyPrefix
	}

	if store.ttl <= 0 {
		store.ttl = defaultBackendRefTTL
	}

	return store
}

// Issue persists an authority payload and returns its opaque public handle.
func (s *RedisBackendRefStore) Issue(ctx context.Context, payload BackendRefPayload) (*commonv1.BackendRef, error) {
	if s == nil || s.client == nil || s.client.GetWriteHandle() == nil {
		return nil, ErrBackendRefInvalid
	}

	token, err := newBackendRefToken()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	payload.SchemaVersion = backendRefSchemaVersion

	if payload.IssuedAt.IsZero() {
		payload.IssuedAt = now
	}

	ttl := time.Until(payload.ExpiresAt)
	if payload.ExpiresAt.IsZero() {
		payload.ExpiresAt = payload.IssuedAt.Add(s.ttl)
		ttl = s.ttl
	}

	if payload.Authority == "" {
		payload.Authority = s.authority
	}

	encoded, err := s.encodePayload(payload)
	if err != nil {
		return nil, err
	}

	if err = s.client.GetWriteHandle().Set(ctx, s.key(token), encoded, ttl).Err(); err != nil {
		return nil, err
	}

	return payload.backendRef(token), nil
}

// Validate resolves and checks an authority reference without trusting caller-visible echo fields.
func (s *RedisBackendRefStore) Validate(
	ctx context.Context,
	ref *commonv1.BackendRef,
	validation BackendRefValidation,
) (*BackendRefPayload, error) {
	if s == nil || s.client == nil || s.client.GetReadHandle() == nil || ref == nil || strings.TrimSpace(ref.GetOpaqueToken()) == "" {
		return nil, ErrBackendRefInvalid
	}

	encoded, err := s.client.GetReadHandle().Get(ctx, s.key(ref.GetOpaqueToken())).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrBackendRefExpired
	}

	if err != nil {
		return nil, err
	}

	payload, err := s.decodePayload(encoded)
	if err != nil {
		return nil, err
	}

	if err = payload.validate(validation); err != nil {
		return nil, err
	}

	return payload, nil
}

func (s *RedisBackendRefStore) key(token string) string {
	return s.keyPrefix + token
}

func (s *RedisBackendRefStore) encodePayload(payload BackendRefPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	manager := s.client.GetSecurityManager()
	if manager == nil {
		return string(data), nil
	}

	return manager.Encrypt(string(data))
}

func (s *RedisBackendRefStore) decodePayload(encoded string) (*BackendRefPayload, error) {
	manager := s.client.GetSecurityManager()
	if manager != nil {
		decoded, err := manager.Decrypt(encoded)
		if err != nil {
			return nil, err
		}

		encoded = decoded
	}

	var payload BackendRefPayload
	if err := json.Unmarshal([]byte(encoded), &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendRefInvalid, err)
	}

	return &payload, nil
}

func (p BackendRefPayload) backendRef(token string) *commonv1.BackendRef {
	return &commonv1.BackendRef{
		Type:        p.Type,
		Name:        p.Name,
		Protocol:    p.Protocol,
		Authority:   p.Authority,
		OpaqueToken: token,
	}
}

func (p *BackendRefPayload) validate(validation BackendRefValidation) error {
	if p == nil || p.SchemaVersion != backendRefSchemaVersion {
		return ErrBackendRefInvalid
	}

	for _, check := range []func(BackendRefValidation) error{
		p.validateExpiry,
		p.validatePrincipal,
		p.validateEdgeCluster,
		p.validateUsername,
		p.validateOperation,
	} {
		if err := check(validation); err != nil {
			return err
		}
	}

	return nil
}

func (p *BackendRefPayload) validateExpiry(_ BackendRefValidation) error {
	if !p.ExpiresAt.IsZero() && time.Now().UTC().After(p.ExpiresAt) {
		return ErrBackendRefExpired
	}

	return nil
}

func (p *BackendRefPayload) validatePrincipal(validation BackendRefValidation) error {
	if validation.ServicePrincipal != "" && p.ServicePrincipal != validation.ServicePrincipal {
		return ErrBackendRefPrincipalMismatch
	}

	if validation.MTLSClientIdentity != "" && p.MTLSClientIdentity != "" && p.MTLSClientIdentity != validation.MTLSClientIdentity {
		return ErrBackendRefPrincipalMismatch
	}

	return nil
}

func (p *BackendRefPayload) validateEdgeCluster(validation BackendRefValidation) error {
	if validation.EdgeClusterID != "" && p.EdgeClusterID != validation.EdgeClusterID {
		return ErrBackendRefEdgeClusterMismatch
	}

	return nil
}

func (p *BackendRefPayload) validateUsername(validation BackendRefValidation) error {
	if validation.Username != "" && p.Username != "" && p.Username != validation.Username {
		return ErrBackendRefUsernameMismatch
	}

	return nil
}

func (p *BackendRefPayload) validateOperation(validation BackendRefValidation) error {
	if validation.Operation != "" && !p.allows(validation.Operation) {
		return ErrBackendRefOperationDenied
	}

	return nil
}

func (p BackendRefPayload) allows(operation AuthorityOperation) bool {
	if len(p.AllowedOperations) == 0 {
		return true
	}

	for _, allowed := range p.AllowedOperations {
		if allowed == operation {
			return true
		}
	}

	return false
}

func newBackendRefToken() (string, error) {
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(tokenBytes[:]), nil
}
