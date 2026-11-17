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

package main

import (
	"context"
	"time"
)

// streamTarget resolves the insert URL and module-cache key of one stream from the current module config.
type streamTarget func(moduleConfig) (insertURL string, cacheKey string)

// rowStream owns the in-memory batching, insert gate, retry pause, and metrics of one ClickHouse insert target.
// Plugin.mu guards every field. Streams never share buffers, so a stalled target cannot delay the other one.
type rowStream struct {
	retryAfter time.Time
	target     streamTarget
	// isLimitedRow marks rows that count against the stream's reserved-share limit; nil disables the share.
	isLimitedRow func(any) bool
	metrics      pluginMetrics
	names        metricNames
	retryDelay   time.Duration
	pendingRows  int
	// pendingLimited counts buffered rows that isLimitedRow marks; it is rebuilt whenever rows are re-pushed.
	pendingLimited int
	flushing       bool
}

// limitedRowsFull reports whether one more marked row would exceed the stream's reserved share.
func (s *rowStream) limitedRowsFull(row any, limit int) (bool, bool) {
	if s.isLimitedRow == nil || !s.isLimitedRow(row) {
		return false, false
	}

	return true, s.pendingLimited >= limit
}

// loginStreamTarget selects the authentication-row target.
func loginStreamTarget(config moduleConfig) (string, string) {
	return config.InsertURL, config.CacheKey
}

// eventStreamTarget selects the step-event target.
func eventStreamTarget(config moduleConfig) (string, string) {
	return config.EventsInsertURL, config.EventsCacheKey
}

// bruteForceLifecycleStreamTarget selects the ban lifecycle target.
func bruteForceLifecycleStreamTarget(config moduleConfig) (string, string) {
	return config.BruteForceLifecycleInsertURL, config.BruteForceLifecycleCacheKey
}

// bruteForceCountedStreamTarget selects the attempts target for counted and tolerated rows.
func bruteForceCountedStreamTarget(config moduleConfig) (string, string) {
	return config.BruteForceAttemptsInsertURL, config.BruteForceCountedCacheKey
}

// bruteForceHitsStreamTarget selects the attempts target for ban hit rows with their own buffer.
func bruteForceHitsStreamTarget(config moduleConfig) (string, string) {
	return config.BruteForceAttemptsInsertURL, config.BruteForceHitsCacheKey
}

// streamQueue binds one stream to the plugin lock and module cache for batch flushing.
type streamQueue struct {
	plugin *Plugin
	stream *rowStream
}

// pushRows admits rows into the stream buffer within its row limit.
func (q streamQueue) pushRows(ctx context.Context, rows ...any) int {
	q.plugin.mu.Lock()
	defer q.plugin.mu.Unlock()

	return q.plugin.pushRowsLocked(ctx, q.stream, rows...)
}

// beginFlush atomically claims the current batch without waiting for an active insert.
func (q streamQueue) beginFlush(ctx context.Context) []any {
	q.plugin.mu.Lock()
	defer q.plugin.mu.Unlock()

	stream := q.stream
	if q.plugin.cache == nil || stream.flushing || time.Now().Before(stream.retryAfter) {
		return nil
	}

	_, cacheKey := stream.target(q.plugin.config)
	rows := q.plugin.cache.PopAll(ctx, cacheKey)

	stream.pendingRows = 0
	stream.pendingLimited = 0

	if len(rows) != 0 {
		stream.flushing = true
	}

	return rows
}

// finishFlush releases the insert slot and backs off failures, resetting after success.
func (q streamQueue) finishFlush(failed bool) {
	q.plugin.mu.Lock()
	defer q.plugin.mu.Unlock()

	q.stream.finishFlushLocked(failed)
}

// finishFlushLocked applies the exponential retry pause of one finished insert.
func (s *rowStream) finishFlushLocked(failed bool) {
	s.flushing = false
	if !failed {
		s.retryDelay = 0
		s.retryAfter = time.Time{}

		return
	}

	if s.retryDelay == 0 {
		s.retryDelay = initialRetryDelay
	} else {
		s.retryDelay = min(2*s.retryDelay, maximumRetryDelay)
	}

	s.retryAfter = time.Now().Add(s.retryDelay)
}
