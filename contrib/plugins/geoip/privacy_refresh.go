// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

type privacySnapshotCache struct {
	path string
}

type privacyRefreshCall struct {
	done chan struct{}
	err  error
}

type privacySourceCoordinator struct {
	httpClient pluginapi.HTTPClient
	cache      *privacySnapshotCache
	now        func() time.Time
	jitter     func(time.Duration) time.Duration
	semaphore  chan struct{}
	config     privacySourceConfig
	snapshot   privacySnapshot
	inflight   *privacyRefreshCall
	etag       string
	modified   string
	next       time.Time
	failures   uint
	mu         sync.RWMutex
}

// newPrivacySourceCoordinator creates one coalescing remote-source owner.
func newPrivacySourceCoordinator(config privacySourceConfig, client pluginapi.HTTPClient, semaphore chan struct{}) *privacySourceCoordinator {
	coordinator := &privacySourceCoordinator{httpClient: client, now: time.Now, jitter: privacyRandomJitter, semaphore: semaphore, config: config}
	if config.CachePath != "" {
		coordinator.cache = &privacySnapshotCache{path: config.CachePath}
	}

	return coordinator
}

// Refresh coalesces concurrent triggers and atomically publishes one validated candidate.
func (c *privacySourceCoordinator) Refresh(ctx context.Context) error {
	c.mu.Lock()
	if c.inflight != nil {
		call := c.inflight
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-call.done:
			return call.err
		}
	}

	call := &privacyRefreshCall{done: make(chan struct{})}
	c.inflight = call
	c.mu.Unlock()

	err := c.refreshOnce(ctx)

	c.mu.Lock()
	call.err = err
	c.inflight = nil

	close(call.done)
	c.mu.Unlock()

	return err
}

// Snapshot returns a defensive copy of the current last-known-good source state.
func (c *privacySourceCoordinator) Snapshot() privacySnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return clonePrivacySnapshot(c.snapshot)
}

// LoadCache validates and publishes a persistent snapshot before network refresh.
func (c *privacySourceCoordinator) LoadCache() error {
	if c.cache == nil {
		return nil
	}

	snapshot, err := c.cache.Load(c.config, c.now())
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.snapshot = snapshot
	c.mu.Unlock()

	return nil
}

// NextAttempt reports the scheduling lower bound derived from local and upstream policy.
func (c *privacySourceCoordinator) NextAttempt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.next
}

// DeferUntil establishes a lifecycle scheduling lower bound without performing I/O.
func (c *privacySourceCoordinator) DeferUntil(next time.Time) {
	c.mu.Lock()
	c.next = next
	c.mu.Unlock()
}

// refreshOnce performs one bounded conditional request outside the request-evaluation path.
func (c *privacySourceCoordinator) refreshOnce(ctx context.Context) error {
	if c.httpClient == nil {
		return c.recordFailure(errors.New("privacy HTTP client is unavailable"), nil)
	}

	if err := c.acquire(ctx); err != nil {
		return c.recordFailure(err, nil)
	}
	defer c.release()

	request := pluginapi.HTTPRequest{
		Method:           http.MethodGet,
		URL:              c.config.URL,
		Service:          c.config.ID,
		Timeout:          min(c.config.MinRefreshInterval, 30*time.Second),
		MaxResponseBytes: c.config.MaxDownloadBytes,
		Headers:          c.conditionalHeaders(),
	}

	response, err := c.httpClient.Do(ctx, request)
	if err != nil {
		return c.recordFailure(errors.New("privacy source request failed"), nil)
	}

	return c.handleResponse(response)
}

// handleResponse validates HTTP status and atomically applies one successful response.
func (c *privacySourceCoordinator) handleResponse(response pluginapi.HTTPResponse) error {
	now := c.now()
	if response.StatusCode == http.StatusNotModified {
		c.mu.Lock()
		if c.snapshot.SourceID == "" {
			c.mu.Unlock()

			return c.recordFailure(errors.New("privacy source returned not-modified without a local snapshot"), response.Headers)
		}

		c.snapshot.ConfirmedAt = now
		c.updateValidatorsLocked(response.Headers)
		c.recordSuccessLocked(response.Headers, now)
		c.mu.Unlock()

		return nil
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return c.recordFailure(fmt.Errorf("privacy source returned HTTP status %d", response.StatusCode), response.Headers)
	}

	snapshot, err := c.parseCandidate(response.Body, now)
	if err != nil {
		return c.recordFailure(err, response.Headers)
	}

	if c.cache != nil {
		if err := c.cache.Store(snapshot); err != nil {
			return c.recordFailure(err, response.Headers)
		}
	}

	c.mu.Lock()
	c.snapshot = snapshot
	c.updateValidatorsLocked(response.Headers)
	c.recordSuccessLocked(response.Headers, now)
	c.mu.Unlock()

	return nil
}

// parseCandidate dispatches only format-specific validation to the selected parser.
func (c *privacySourceCoordinator) parseCandidate(raw []byte, now time.Time) (privacySnapshot, error) {
	switch c.config.Kind {
	case privacySourceKindTor:
		return parseTorPrivacySnapshot(raw, c.config, now)
	case privacySourceKindNormalized:
		return parseNormalizedPrivacySnapshot(raw, c.config, now)
	default:
		return privacySnapshot{}, fmt.Errorf("unsupported privacy source kind %q", c.config.Kind)
	}
}

// conditionalHeaders builds cache validators without exposing source credentials.
func (c *privacySourceCoordinator) conditionalHeaders() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	headers := make(map[string][]string, 2)
	if c.etag != "" {
		headers["If-None-Match"] = []string{c.etag}
	}

	if c.modified != "" {
		headers["If-Modified-Since"] = []string{c.modified}
	}

	return headers
}

// updateValidatorsLocked retains upstream validators across successful refresh cycles.
func (c *privacySourceCoordinator) updateValidatorsLocked(headers map[string][]string) {
	if etag := privacyHeader(headers, "ETag"); etag != "" {
		c.etag = etag
	}

	if modified := privacyHeader(headers, "Last-Modified"); modified != "" {
		c.modified = modified
	}
}

// recordSuccessLocked resets failure backoff and honors upstream cache lower bounds.
func (c *privacySourceCoordinator) recordSuccessLocked(headers map[string][]string, now time.Time) {
	c.failures = 0

	delay := c.config.RefreshInterval
	if upstream := privacyCacheDelay(headers, now); upstream > delay {
		delay = upstream
	}

	if c.jitter != nil {
		delay += c.jitter(c.config.RefreshJitter)
	}

	c.next = now.Add(max(delay, c.config.MinRefreshInterval))
}

// privacyRandomJitter returns one bounded non-negative scheduling offset.
func privacyRandomJitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}

	return time.Duration(rand.Int64N(int64(limit) + 1))
}

// recordFailure preserves the current snapshot and advances bounded exponential backoff.
func (c *privacySourceCoordinator) recordFailure(err error, headers map[string][]string) error {
	c.mu.Lock()
	c.failures++
	exponent := min(c.failures-1, uint(20))
	delay := c.config.MinRefreshInterval * time.Duration(1<<exponent)

	delay = min(delay, c.config.MaxRefreshBackoff)
	if retryAfter := privacyRetryAfter(headers, c.now()); retryAfter > delay {
		delay = retryAfter
	}

	c.next = c.now().Add(delay)
	c.mu.Unlock()

	return err
}

// acquire waits for one slot in the shared bounded download semaphore.
func (c *privacySourceCoordinator) acquire(ctx context.Context) error {
	if c.semaphore == nil {
		return nil
	}

	select {
	case c.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release returns one slot to the shared bounded download semaphore.
func (c *privacySourceCoordinator) release() {
	if c.semaphore != nil {
		<-c.semaphore
	}
}

// Store writes only validated snapshots using restrictive permissions and atomic rename.
func (c privacySnapshotCache) Store(snapshot privacySnapshot) error {
	if c.path == "" {
		return nil
	}

	raw, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode privacy cache: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("create privacy cache directory: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".privacy-cache-*")
	if err != nil {
		return fmt.Errorf("create privacy cache candidate: %w", err)
	}

	temporaryPath := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("secure privacy cache candidate: %w", err)
	}

	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("write privacy cache candidate: %w", err)
	}

	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("sync privacy cache candidate: %w", err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close privacy cache candidate: %w", err)
	}

	if err := os.Rename(temporaryPath, c.path); err != nil {
		return fmt.Errorf("publish privacy cache: %w", err)
	}

	return nil
}

// Load validates cached metadata and entries before making it available.
func (c privacySnapshotCache) Load(config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	limit := config.MaxDownloadBytes
	if limit <= 0 {
		limit = defaultPrivacyMaxDownloadBytes
	}

	file, err := os.Open(c.path)
	if err != nil {
		return privacySnapshot{}, fmt.Errorf("read privacy cache: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return privacySnapshot{}, fmt.Errorf("read privacy cache: %w", err)
	}

	if int64(len(raw)) > limit {
		return privacySnapshot{}, fmt.Errorf("privacy cache exceeds configured size limit")
	}

	var snapshot privacySnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return privacySnapshot{}, fmt.Errorf("decode privacy cache: %w", err)
	}

	if err := validateCachedPrivacySnapshot(snapshot, config); err != nil {
		return privacySnapshot{}, err
	}

	snapshot.MaxAge = config.MaxAge
	snapshot.LoadedAt = now

	return snapshot, nil
}

// validateCachedPrivacySnapshot rechecks metadata and every persisted entry.
func validateCachedPrivacySnapshot(snapshot privacySnapshot, config privacySourceConfig) error {
	if snapshot.SourceID != config.ID || snapshot.Kind != config.Kind || snapshot.Authority != config.Authority {
		return fmt.Errorf("privacy cache metadata does not match source %q", config.ID)
	}

	if len(snapshot.Entries) == 0 || len(snapshot.Entries) > config.MaxEntries {
		return fmt.Errorf("privacy cache entry count is outside configured bounds")
	}

	for index, entry := range snapshot.Entries {
		if !entry.Prefix.IsValid() || !slicesContainsPrivacyClass(entry.Class) {
			return fmt.Errorf("privacy cache entry %d is invalid", index)
		}

		if err := validatePrivacyFeedPrefix(entry.Prefix); err != nil {
			return fmt.Errorf("privacy cache entry %d: %w", index, err)
		}

		if err := validatePrivacyConfidence(config.Authority, entry.Confidence); err != nil {
			return fmt.Errorf("privacy cache entry %d: %w", index, err)
		}
	}

	return nil
}

// clonePrivacySnapshot prevents callers from mutating published entry slices.
func clonePrivacySnapshot(snapshot privacySnapshot) privacySnapshot {
	result := snapshot
	result.Entries = append([]privacyEntry(nil), snapshot.Entries...)

	return result
}

// privacyHeader reads a response header case-insensitively from the API value map.
func privacyHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}

	return ""
}

// privacyCacheDelay parses Cache-Control max-age and Expires lower bounds.
func privacyCacheDelay(headers map[string][]string, now time.Time) time.Duration {
	var delay time.Duration

	for _, directive := range strings.Split(privacyHeader(headers, "Cache-Control"), ",") {
		name, value, found := strings.Cut(strings.TrimSpace(directive), "=")
		if !found || !strings.EqualFold(name, "max-age") {
			continue
		}

		seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err == nil && seconds > 0 {
			delay = time.Duration(seconds) * time.Second
		}
	}

	if expires, err := http.ParseTime(privacyHeader(headers, "Expires")); err == nil && expires.After(now) {
		delay = max(delay, expires.Sub(now))
	}

	return delay
}

// privacyRetryAfter parses delta-seconds and HTTP-date retry lower bounds.
func privacyRetryAfter(headers map[string][]string, now time.Time) time.Duration {
	value := privacyHeader(headers, "Retry-After")
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when.Sub(now)
	}

	return 0
}

// slicesContainsPrivacyClass checks cached enum values without accepting future unknown classes.
func slicesContainsPrivacyClass(class privacyClass) bool {
	for _, candidate := range privacyClassOrder {
		if candidate == class {
			return true
		}
	}

	return false
}
