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

const (
	initialRetryDelay = time.Second
	maximumRetryDelay = time.Minute
)

// beginFlush atomically claims the current batch without waiting for an active insert.
func (p *Plugin) beginFlush(ctx context.Context) []any {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cache == nil || p.flushing || time.Now().Before(p.retryAfter) {
		return nil
	}

	rows := p.cache.PopAll(ctx, p.config.CacheKey)

	p.pendingRows = 0
	if len(rows) != 0 {
		p.flushing = true
	}

	return rows
}

// finishFlush releases the insert slot and backs off failures, resetting after success.
func (p *Plugin) finishFlush(failed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.flushing = false
	if !failed {
		p.retryDelay = 0
		p.retryAfter = time.Time{}

		return
	}

	if p.retryDelay == 0 {
		p.retryDelay = initialRetryDelay
	} else {
		p.retryDelay = min(2*p.retryDelay, maximumRetryDelay)
	}

	p.retryAfter = time.Now().Add(p.retryDelay)
}
