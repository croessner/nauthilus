// Copyright (C) 2024 Christian Rößner
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

// Package l1 provides l1 functionality.
package l1

import (
	"context"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/localcache"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"

	"go.opentelemetry.io/otel/attribute"
)

// Decision captures a local decision result.
type Decision struct {
	Rule    string
	Reason  string
	Allowed bool
	Blocked bool
}

// Reputation captures local reputation data for an IP.
type Reputation struct {
	Positive int64
	Negative int64
}

// Engine is a dedicated L1 decision engine using an in-memory micro-cache.
type Engine struct {
	cache *localcache.MemoryShardedCache
}

var (
	l1EngineOnce sync.Once
	l1Engine     *Engine
)

// GetEngine returns the singleton instance of the L1 decision engine.
func GetEngine() *Engine {
	l1EngineOnce.Do(func() {
		// Default TTL for micro-decisions is 300ms.
		// Cleanup happens at the same interval.
		ttl := 300 * time.Millisecond
		l1Engine = &Engine{
			cache: localcache.NewMemoryShardedCache(32, ttl, ttl),
		}
	})

	return l1Engine
}

// Get retrieves a decision from the L1 cache for the given key.
func (e *Engine) Get(ctx context.Context, key string) (Decision, bool) {
	return getCached(ctx, e, key, "l1.get", decisionCacheAttributes)
}

// Set stores a decision in the L1 cache for the given key with a specific TTL.
// If ttl is 0, the cache's default TTL is used.
func (e *Engine) Set(ctx context.Context, key string, decision Decision, ttl time.Duration) {
	setCached(ctx, e, key, "l1.set", decision, ttl, decisionSetAttributes)
}

// GetReputation retrieves reputation data from the L1 cache for the given key.
func (e *Engine) GetReputation(ctx context.Context, key string) (Reputation, bool) {
	return getCached(ctx, e, key, "l1.get_reputation", reputationCacheAttributes)
}

// SetReputation stores reputation data in the L1 cache for the given key with a specific TTL.
func (e *Engine) SetReputation(ctx context.Context, key string, reputation Reputation, ttl time.Duration) {
	setCached(ctx, e, key, "l1.set_reputation", reputation, ttl, reputationSetAttributes)
}

// getCached reads a typed cache value and records common trace attributes.
func getCached[T any](ctx context.Context, engine *Engine, key string, spanName string, attributes func(T, bool) []attribute.KeyValue) (T, bool) {
	var zero T

	if engine == nil || engine.cache == nil {
		return zero, false
	}

	tr := monittrace.New("nauthilus/bruteforce/l1")

	_, sp := tr.Start(ctx, spanName, attribute.String("key", key))
	defer sp.End()

	val, ok := engine.cache.Get(key)
	if !ok {
		return zero, false
	}

	typedValue, ok := val.(T)
	sp.SetAttributes(attributes(typedValue, ok)...)

	return typedValue, ok
}

// setCached stores a typed cache value and records common trace attributes.
func setCached[T any](ctx context.Context, engine *Engine, key string, spanName string, value T, ttl time.Duration, attributes func(T) []attribute.KeyValue) {
	if engine == nil || engine.cache == nil {
		return
	}

	tr := monittrace.New("nauthilus/bruteforce/l1")

	spanAttributes := append([]attribute.KeyValue{
		attribute.String("key", key),
		attribute.String("ttl", ttl.String()),
	}, attributes(value)...)

	_, sp := tr.Start(ctx, spanName, spanAttributes...)
	defer sp.End()

	engine.cache.Set(key, value, ttl)
}

// decisionCacheAttributes formats trace attributes for cached decisions.
func decisionCacheAttributes(decision Decision, hit bool) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("hit", hit),
		attribute.Bool("blocked", decision.Blocked),
		attribute.String("rule", decision.Rule),
	}
}

// decisionSetAttributes formats trace attributes for stored decisions.
func decisionSetAttributes(decision Decision) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("blocked", decision.Blocked),
		attribute.String("rule", decision.Rule),
	}
}

// reputationCacheAttributes formats trace attributes for cached reputation.
func reputationCacheAttributes(reputation Reputation, hit bool) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("hit", hit),
		attribute.Int64("positive", reputation.Positive),
		attribute.Int64("negative", reputation.Negative),
	}
}

// reputationSetAttributes formats trace attributes for stored reputation.
func reputationSetAttributes(reputation Reputation) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int64("positive", reputation.Positive),
		attribute.Int64("negative", reputation.Negative),
	}
}

// KeyNetwork generates a key for a network-based L1 decision.
func KeyNetwork(network string) string {
	return "net:" + network
}

// KeyBurst generates a key for a user/burst-based L1 decision.
func KeyBurst(burstKey string) string {
	return "bfdec:" + burstKey
}

// KeyWhitelist generates a key for an IP-based whitelist L1 decision.
func KeyWhitelist(ip string) string {
	return "wl:" + ip
}

// KeySoftWhitelist generates a key for a user+IP-based soft whitelist L1 decision.
func KeySoftWhitelist(user, ip string) string {
	return "swl:" + user + ":" + ip
}

// KeyReputation generates a key for an IP-based reputation L1 decision.
func KeyReputation(ip string) string {
	return "rep:" + ip
}

// Clear removes all items from the L1 cache.
func (e *Engine) Clear() {
	if e == nil || e.cache == nil {
		return
	}

	// We use localcache.NewMemoryShardedCache to replace the internal cache as a quick clear.
	// Since it's for testing and micro-caching, this is acceptable.
	e.cache = localcache.NewMemoryShardedCache(32, 300*time.Millisecond, 300*time.Millisecond)
}
