// Copyright (C) 2025 Christian Rößner
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

package flow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
)

const defaultRedisPrefix = "idp:flow"

// RedisStore persists full flow state in Redis.
type RedisStore struct {
	client redis.UniversalClient
	ttl    time.Duration
	prefix string
}

// NewRedisStore creates a Redis-backed flow state store with normalized
// key prefix and default TTL fallback.
func NewRedisStore(client redis.UniversalClient, prefix string, ttl time.Duration) *RedisStore {
	cleanPrefix := strings.Trim(prefix, ":")
	if cleanPrefix == "" {
		cleanPrefix = defaultRedisPrefix
	}

	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	return &RedisStore{client: client, ttl: ttl, prefix: cleanPrefix}
}

// Load fetches and deserializes a flow state by flow ID.
func (s *RedisStore) Load(ctx context.Context, flowID string) (*State, error) {
	if s == nil || s.client == nil {
		return nil, nil
	}

	if flowID == "" {
		reportStoreRead("redis", "miss")

		return nil, nil
	}

	blob, err := s.client.Get(ctx, s.redisKey(flowID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			reportStoreRead("redis", "miss")

			return nil, nil
		}

		reportStoreRead("redis", "error")

		return nil, err
	}

	state := &State{}
	if err = jsoniter.ConfigFastest.Unmarshal(blob, state); err != nil {
		reportStoreRead("redis", "error")

		return nil, fmt.Errorf("redis flow store: decode state %s: %w", flowID, err)
	}

	reportStoreRead("redis", "hit")

	return state, nil
}

// Save serializes and writes a flow state to Redis with TTL.
func (s *RedisStore) Save(ctx context.Context, state *State) error {
	if s == nil || s.client == nil || state == nil {
		return nil
	}

	blob, err := jsoniter.ConfigFastest.Marshal(state)
	if err != nil {
		reportStoreWrite("redis", "error")

		return fmt.Errorf("redis flow store: encode state %s: %w", state.FlowID, err)
	}

	if err = s.client.Set(ctx, s.redisKey(state.FlowID), blob, s.ttl).Err(); err != nil {
		reportStoreWrite("redis", "error")

		return err
	}

	reportStoreWrite("redis", "ok")

	return nil
}

// Delete removes a flow state key from Redis.
func (s *RedisStore) Delete(ctx context.Context, flowID string) error {
	if s == nil || s.client == nil || flowID == "" {
		return nil
	}

	if err := s.client.Del(ctx, s.redisKey(flowID)).Err(); err != nil {
		reportStoreWrite("redis", "error")

		return err
	}

	reportStoreWrite("redis", "delete")

	return nil
}

// TouchTTL refreshes the TTL of an existing flow state key.
func (s *RedisStore) TouchTTL(ctx context.Context, flowID string, ttl time.Duration) error {
	if s == nil || s.client == nil || flowID == "" {
		return nil
	}

	touchTTL := s.ttl
	if ttl > 0 {
		touchTTL = ttl
	}

	updated, err := s.client.Expire(ctx, s.redisKey(flowID), touchTTL).Result()
	if err != nil {
		reportStoreTouchTTL("redis", "error")

		return err
	}

	if !updated {
		reportStoreTouchTTL("redis", "miss")

		return nil
	}

	reportStoreTouchTTL("redis", "ok")

	return nil
}

func (s *RedisStore) redisKey(flowID string) string {
	return s.prefix + ":" + flowID
}
