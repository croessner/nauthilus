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

package loopsfx

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/redifx"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/stats"
)

// StatsService is a service that manages periodic tasks and CPU usage monitoring using a defined interval and hooks.
type StatsService struct {
	interval time.Duration

	startMeasureCPU func(context.Context)
	onTick          func(context.Context)

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	ticker  *time.Ticker
	wg      sync.WaitGroup
	running bool
}

// NewDefaultStatsService initializes and returns a StatsService with default settings for statistical monitoring tasks.
func NewDefaultStatsService(cfgProvider configfx.Provider, logger *slog.Logger, redisClient redifx.Client) *StatsService {
	return NewStatsService(
		definitions.StatsDelay*time.Second,
		stats.MeasureCPU,
		func(ctx context.Context) {
			stats.PrintStats()

			snap := cfgProvider.Current()
			if snap.File == nil {
				return
			}

			core.SaveStatsToRedis(ctx, snap.File, logger, redisClient)
		},
	)
}

// NewStatsService initializes a StatsService with a specified interval, CPU measurement function, and tick callback.
func NewStatsService(interval time.Duration, startMeasureCPU func(context.Context), onTick func(context.Context)) *StatsService {
	return &StatsService{
		interval:        interval,
		startMeasureCPU: startMeasureCPU,
		onTick:          onTick,
	}
}

// Start begins the service, initializing its context, ticker, and running state, and spawns necessary goroutines for tasks.
func (s *StatsService) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	ctx, cancel := context.WithCancel(parent)
	ticker := time.NewTicker(s.interval)

	s.ctx = ctx
	s.cancel = cancel
	s.ticker = ticker
	s.running = true

	if s.startMeasureCPU != nil {
		s.wg.Add(1)
		go func(measureCtx context.Context) {
			defer s.wg.Done()

			s.startMeasureCPU(measureCtx)
		}(ctx)
	}

	s.wg.Add(1)
	go func(loopCtx context.Context, loopTicker *time.Ticker) {
		defer s.wg.Done()

		for {
			select {
			case <-loopCtx.Done():
				return
			case <-loopTicker.C:
				if s.onTick != nil {
					s.onTick(loopCtx)
				}
			}
		}
	}(ctx, ticker)

	return nil
}

// Stop terminates the stats service.
//
// It attempts to stop within the provided context deadline.
func (s *StatsService) Stop(stopCtx context.Context) error {
	return stopLoop(&s.mu, &s.running, &s.cancel, &s.ticker, &s.ctx, &s.wg, stopCtx)
}
