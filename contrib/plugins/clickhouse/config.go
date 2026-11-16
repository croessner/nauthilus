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

// Package main provides the bundled ClickHouse native post-action plugin.
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	defaultBatchSize      = 100
	defaultMaxBufferRows  = 10000
	defaultCacheKey       = "clickhouse:batch:logins"
	defaultEventsCacheKey = "clickhouse:batch:auth_events"
	defaultEventsFlush    = 10 * time.Second

	defaultBruteForceLifecycleCacheKey = "clickhouse:batch:bruteforce_lifecycle"
	defaultBruteForceCountedCacheKey   = "clickhouse:batch:bruteforce_counted"
	defaultBruteForceHitsCacheKey      = "clickhouse:batch:bruteforce_hits"
	defaultTimeout                     = 10 * time.Second
	defaultMaxResponseBytes            = int64(8192)
	defaultAuthDedupTTL                = 300 * time.Second
)

// bruteForceStreamConfig holds the brute-force event targets; both insert URLs are optional.
type bruteForceStreamConfig struct {
	BruteForceLifecycleInsertURL string        `mapstructure:"-"`
	BruteForceAttemptsInsertURL  string        `mapstructure:"-"`
	BruteForceLifecycleCacheKey  string        `mapstructure:"-"`
	BruteForceCountedCacheKey    string        `mapstructure:"-"`
	BruteForceHitsCacheKey       string        `mapstructure:"-"`
	BruteForceFlushInterval      time.Duration `mapstructure:"-"`
}

type moduleConfig struct {
	bruteForceStreamConfig
	Deployment      string        `mapstructure:"-"`
	Instance        string        `mapstructure:"-"`
	InsertURL       string        `mapstructure:"-"`
	EventsInsertURL string        `mapstructure:"-"`
	User            string        `mapstructure:"-"`
	Password        string        `mapstructure:"-"`
	CacheKey        string        `mapstructure:"-"`
	EventsCacheKey  string        `mapstructure:"-"`
	Timeout         time.Duration `mapstructure:"-"`
	AuthDedupTTL    time.Duration `mapstructure:"-"`
	FlushInterval   time.Duration `mapstructure:"-"`
	// EventsFlushInterval is always positive: step events rarely fill a batch and must still leave the process.
	EventsFlushInterval time.Duration `mapstructure:"-"`
	BatchSize           int           `mapstructure:"-"`
	MaxBufferRows       int           `mapstructure:"-"`
	MaxResponseBytes    int64         `mapstructure:"-"`
	DedupSuccess        bool          `mapstructure:"-"`
	DedupFailure        bool          `mapstructure:"-"`
}

type rawModuleConfig struct {
	Deployment      string `mapstructure:"deployment"`
	Instance        string `mapstructure:"instance"`
	InsertURL       string `mapstructure:"insert_url"`
	EventsInsertURL string `mapstructure:"events_insert_url"`
	User            string `mapstructure:"user"`
	Password        string `mapstructure:"password"`
	CacheKey        string `mapstructure:"cache_key"`
	EventsCacheKey  string `mapstructure:"events_cache_key"`
	Timeout         string `mapstructure:"timeout"`
	AuthDedupTTL    string `mapstructure:"auth_dedup_ttl"`
	FlushInterval   string `mapstructure:"flush_interval"`
	EventsFlush     string `mapstructure:"events_flush_interval"`

	BruteForceLifecycleInsertURL string `mapstructure:"bruteforce_lifecycle_insert_url"`
	BruteForceAttemptsInsertURL  string `mapstructure:"bruteforce_attempts_insert_url"`
	BruteForceLifecycleCacheKey  string `mapstructure:"bruteforce_lifecycle_cache_key"`
	BruteForceCountedCacheKey    string `mapstructure:"bruteforce_counted_cache_key"`
	BruteForceHitsCacheKey       string `mapstructure:"bruteforce_hits_cache_key"`
	BruteForceFlush              string `mapstructure:"bruteforce_flush_interval"`
	BatchSize                    int    `mapstructure:"batch_size"`
	MaxBufferRows                int    `mapstructure:"max_buffer_rows"`
	MaxResponseBytes             int64  `mapstructure:"max_response_bytes"`
	DedupSuccess                 bool   `mapstructure:"dedup_success"`
	DedupFailure                 bool   `mapstructure:"dedup_failure"`
}

// decodeModuleConfig reads and validates the ClickHouse plugin-owned config.
func decodeModuleConfig(view pluginapi.ConfigView) (moduleConfig, error) {
	raw := rawModuleConfig{DedupSuccess: true}
	if view != nil && !view.IsZero() {
		if err := view.Decode(&raw); err != nil {
			return moduleConfig{}, fmt.Errorf("decode clickhouse config: %w", err)
		}
	}

	insertURL, err := pluginutil.ValidateOptionalHTTPURL("insert_url", raw.InsertURL)
	if err != nil {
		return moduleConfig{}, err
	}

	eventsInsertURL, err := pluginutil.ValidateOptionalHTTPURL("events_insert_url", raw.EventsInsertURL)
	if err != nil {
		return moduleConfig{}, err
	}

	eventsFlushInterval, err := pluginutil.ParsePositiveDefaultedDuration(
		"events_flush_interval", raw.EventsFlush, defaultEventsFlush,
	)
	if err != nil {
		return moduleConfig{}, err
	}

	batchSize, err := pluginutil.ParsePositiveDefaultedInt("batch_size", raw.BatchSize, defaultBatchSize)
	if err != nil {
		return moduleConfig{}, err
	}

	maxBufferRows, err := pluginutil.ParsePositiveDefaultedInt("max_buffer_rows", raw.MaxBufferRows, defaultMaxBufferRows)
	if err != nil {
		return moduleConfig{}, err
	}

	maxResponseBytes, err := pluginutil.ParsePositiveDefaultedInt64("max_response_bytes", raw.MaxResponseBytes, defaultMaxResponseBytes)
	if err != nil {
		return moduleConfig{}, err
	}

	timeout, err := pluginutil.ParsePositiveDefaultedDuration("timeout", raw.Timeout, defaultTimeout)
	if err != nil {
		return moduleConfig{}, err
	}

	authDedupTTL, err := pluginutil.ParsePositiveDefaultedDuration("auth_dedup_ttl", raw.AuthDedupTTL, defaultAuthDedupTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	// Zero keeps size-only batching; a positive interval enables the periodic flush worker.
	flushInterval, err := pluginutil.ParseDefaultedDuration("flush_interval", raw.FlushInterval, 0)
	if err != nil {
		return moduleConfig{}, err
	}

	cacheKey := defaultedCacheKey(raw.CacheKey, defaultCacheKey)
	eventsCacheKey := defaultedCacheKey(raw.EventsCacheKey, defaultEventsCacheKey)

	bruteForce, err := decodeBruteForceStreamConfig(raw)
	if err != nil {
		return moduleConfig{}, err
	}

	if err = requireDistinctCacheKeys(cacheKey, eventsCacheKey, bruteForce.BruteForceLifecycleCacheKey,
		bruteForce.BruteForceCountedCacheKey, bruteForce.BruteForceHitsCacheKey); err != nil {
		return moduleConfig{}, err
	}

	return moduleConfig{
		bruteForceStreamConfig: bruteForce,
		MaxBufferRows:          maxBufferRows,
		DedupSuccess:           raw.DedupSuccess,
		DedupFailure:           raw.DedupFailure,
		Deployment:             strings.TrimSpace(raw.Deployment),
		Instance:               strings.TrimSpace(raw.Instance),
		InsertURL:              insertURL,
		EventsInsertURL:        eventsInsertURL,
		EventsCacheKey:         eventsCacheKey,
		// The events worker interval is mandatory so a quiet process still delivers step events.
		EventsFlushInterval: eventsFlushInterval,
		User:                strings.TrimSpace(raw.User),
		Password:            raw.Password,
		CacheKey:            cacheKey,
		Timeout:             timeout,
		AuthDedupTTL:        authDedupTTL,
		FlushInterval:       flushInterval,
		BatchSize:           batchSize,
		MaxResponseBytes:    maxResponseBytes,
	}, nil
}

// defaultedCacheKey trims a configured module-cache key and falls back to its default.
func defaultedCacheKey(value string, fallback string) string {
	if key := strings.TrimSpace(value); key != "" {
		return key
	}

	return fallback
}

// decodeBruteForceStreamConfig validates the optional brute-force event targets and their mandatory flush interval.
func decodeBruteForceStreamConfig(raw rawModuleConfig) (bruteForceStreamConfig, error) {
	lifecycleURL, err := pluginutil.ValidateOptionalHTTPURL("bruteforce_lifecycle_insert_url", raw.BruteForceLifecycleInsertURL)
	if err != nil {
		return bruteForceStreamConfig{}, err
	}

	attemptsURL, err := pluginutil.ValidateOptionalHTTPURL("bruteforce_attempts_insert_url", raw.BruteForceAttemptsInsertURL)
	if err != nil {
		return bruteForceStreamConfig{}, err
	}

	// Always positive: lifecycle events are rare and must still leave a quiet process.
	flushInterval, err := pluginutil.ParsePositiveDefaultedDuration("bruteforce_flush_interval", raw.BruteForceFlush, defaultEventsFlush)
	if err != nil {
		return bruteForceStreamConfig{}, err
	}

	return bruteForceStreamConfig{
		BruteForceLifecycleInsertURL: lifecycleURL,
		BruteForceAttemptsInsertURL:  attemptsURL,
		BruteForceLifecycleCacheKey:  defaultedCacheKey(raw.BruteForceLifecycleCacheKey, defaultBruteForceLifecycleCacheKey),
		BruteForceCountedCacheKey:    defaultedCacheKey(raw.BruteForceCountedCacheKey, defaultBruteForceCountedCacheKey),
		BruteForceHitsCacheKey:       defaultedCacheKey(raw.BruteForceHitsCacheKey, defaultBruteForceHitsCacheKey),
		BruteForceFlushInterval:      flushInterval,
	}, nil
}

// requireDistinctCacheKeys rejects configurations in which two streams would share one module-cache buffer.
func requireDistinctCacheKeys(keys ...string) error {
	seen := make(map[string]struct{}, len(keys))

	for _, key := range keys {
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("clickhouse cache keys must be distinct; %q is used twice", key)
		}

		seen[key] = struct{}{}
	}

	return nil
}
