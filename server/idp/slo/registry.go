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

package slo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
)

var (
	ErrEmptyAccount    = errors.New("empty slo account")
	ErrEmptySPEntityID = errors.New("empty slo service provider entity id")
	ErrInvalidTTL      = errors.New("invalid slo participant ttl")
)

const defaultRegistryPrefix = "idp:saml:slo"

// ParticipantSession stores SAML correlation data for one active SP session.
type ParticipantSession struct {
	Account      string    `json:"account"`
	SPEntityID   string    `json:"sp_entity_id"`
	NameID       string    `json:"name_id,omitzero"`
	SessionIndex string    `json:"session_index,omitzero"`
	AuthnInstant time.Time `json:"authn_instant"`
}

func (s *ParticipantSession) validate() error {
	if s == nil {
		return fmt.Errorf("slo participant session: %w", ErrEmptyAccount)
	}

	if s.Account == "" {
		return fmt.Errorf("slo participant session: %w", ErrEmptyAccount)
	}

	if s.SPEntityID == "" {
		return fmt.Errorf("slo participant session: %w", ErrEmptySPEntityID)
	}

	return nil
}

// SessionRegistry persists active SAML participant sessions for SLO fanout.
type SessionRegistry struct {
	client redis.UniversalClient
	prefix string
}

// NewSessionRegistry creates a new Redis-backed SAML SLO session registry.
func NewSessionRegistry(client redis.UniversalClient, prefix string) *SessionRegistry {
	cleanPrefix := strings.Trim(prefix, ":")
	if cleanPrefix == "" {
		cleanPrefix = defaultRegistryPrefix
	}

	return &SessionRegistry{
		client: client,
		prefix: cleanPrefix,
	}
}

// UpsertParticipant stores or updates one participant session with TTL.
func (r *SessionRegistry) UpsertParticipant(ctx context.Context, session *ParticipantSession, ttl time.Duration) error {
	if r == nil || r.client == nil {
		return nil
	}

	if err := session.validate(); err != nil {
		return err
	}

	if ttl <= 0 {
		return fmt.Errorf("slo participant session: %w", ErrInvalidTTL)
	}

	if session.AuthnInstant.IsZero() {
		session.AuthnInstant = time.Now().UTC()
	} else {
		session.AuthnInstant = session.AuthnInstant.UTC()
	}

	raw, err := jsoniter.ConfigFastest.Marshal(session)
	if err != nil {
		return fmt.Errorf("slo session registry: encode participant session: %w", err)
	}

	participantKey := r.participantKey(session.Account, session.SPEntityID)
	indexKey := r.accountIndexKey(session.Account)

	pipe := r.client.Pipeline()
	pipe.Set(ctx, participantKey, raw, ttl)
	pipe.SAdd(ctx, indexKey, participantKey)
	pipe.ExpireNX(ctx, indexKey, ttl)
	pipe.ExpireGT(ctx, indexKey, ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("slo session registry: upsert participant session: %w", err)
	}

	return nil
}

// LookupParticipants returns all known participant sessions for an account.
func (r *SessionRegistry) LookupParticipants(ctx context.Context, account string) ([]ParticipantSession, error) {
	if r == nil || r.client == nil || account == "" {
		return nil, nil
	}

	indexKey := r.accountIndexKey(account)

	keys, err := r.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("slo session registry: lookup participant index: %w", err)
	}

	if len(keys) == 0 {
		return nil, nil
	}

	result := make([]ParticipantSession, 0, len(keys))
	staleKeys := make([]string, 0)

	for _, participantKey := range keys {
		raw, getErr := r.client.Get(ctx, participantKey).Bytes()
		if errors.Is(getErr, redis.Nil) {
			staleKeys = append(staleKeys, participantKey)

			continue
		}

		if getErr != nil {
			return nil, fmt.Errorf("slo session registry: load participant session: %w", getErr)
		}

		var session ParticipantSession
		if err = jsoniter.ConfigFastest.Unmarshal(raw, &session); err != nil {
			return nil, fmt.Errorf("slo session registry: decode participant session: %w", err)
		}

		result = append(result, session)
	}

	if len(staleKeys) > 0 {
		staleValues := make([]any, len(staleKeys))
		for index := range staleKeys {
			staleValues[index] = staleKeys[index]
		}

		_ = r.client.SRem(ctx, indexKey, staleValues...).Err()
	}

	return result, nil
}

// DeleteParticipant removes one participant session for an account and SP.
func (r *SessionRegistry) DeleteParticipant(ctx context.Context, account, spEntityID string) error {
	if r == nil || r.client == nil || account == "" || spEntityID == "" {
		return nil
	}

	participantKey := r.participantKey(account, spEntityID)
	indexKey := r.accountIndexKey(account)

	pipe := r.client.Pipeline()
	pipe.Del(ctx, participantKey)
	pipe.SRem(ctx, indexKey, participantKey)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("slo session registry: delete participant session: %w", err)
	}

	return nil
}

// DeleteAccount removes all participant sessions for one account.
func (r *SessionRegistry) DeleteAccount(ctx context.Context, account string) error {
	if r == nil || r.client == nil || account == "" {
		return nil
	}

	indexKey := r.accountIndexKey(account)

	keys, err := r.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		return fmt.Errorf("slo session registry: load account index: %w", err)
	}

	pipe := r.client.Pipeline()

	for index := range keys {
		pipe.Del(ctx, keys[index])
	}

	pipe.Del(ctx, indexKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("slo session registry: delete account sessions: %w", err)
	}

	return nil
}

func (r *SessionRegistry) accountIndexKey(account string) string {
	return r.prefix + ":index:" + url.QueryEscape(account)
}

func (r *SessionRegistry) participantKey(account, spEntityID string) string {
	sum := sha256.Sum256([]byte(spEntityID))

	return r.prefix + ":participant:" + url.QueryEscape(account) + ":" + hex.EncodeToString(sum[:])
}
