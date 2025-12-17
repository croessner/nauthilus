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
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backendmonitoring"
	"github.com/croessner/nauthilus/server/definitions"
)

// BackendMonitoringService provides functionality to monitor backend services at specified intervals.
type BackendMonitoringService struct {
	interval time.Duration

	mu      sync.Mutex
	parent  context.Context
	ctx     context.Context
	cancel  context.CancelFunc
	ticker  *time.Ticker
	wg      sync.WaitGroup
	running bool
}

// NewDefaultBackendMonitoringService creates a BackendMonitoringService with a default delay for backend monitoring.
func NewDefaultBackendMonitoringService() *BackendMonitoringService {
	return NewBackendMonitoringService(definitions.BackendServerMonitoringDelay * time.Second)
}

// NewBackendMonitoringService initializes a new BackendMonitoringService with the provided monitoring interval.
func NewBackendMonitoringService(interval time.Duration) *BackendMonitoringService {
	return &BackendMonitoringService{interval: interval}
}

// Start begins backend monitoring by initializing context, ticker, and spawning monitoring goroutine.
func (s *BackendMonitoringService) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	ctx, cancel := context.WithCancel(parent)
	ticker := time.NewTicker(s.interval)

	s.parent = parent
	s.ctx = ctx
	s.cancel = cancel
	s.ticker = ticker
	s.running = true

	s.wg.Add(1)
	go func(loopCtx context.Context, loopTicker *time.Ticker) {
		defer s.wg.Done()

		backendmonitoring.Run(loopCtx, loopTicker)
	}(ctx, ticker)

	return nil
}

// Stop terminates the backend monitoring process, stops the ticker, cancels the context, and waits for all goroutines to finish.
func (s *BackendMonitoringService) Stop(stopCtx context.Context) error {
	return stopLoop(&s.mu, &s.running, &s.cancel, &s.ticker, &s.ctx, &s.wg, stopCtx)
}

// Restart restarts the backend monitoring service by stopping and then starting its monitoring loop.
func (s *BackendMonitoringService) Restart(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	parent := s.parent
	s.mu.Unlock()

	if parent == nil {
		parent = context.Background()
	}

	return s.Start(parent)
}
