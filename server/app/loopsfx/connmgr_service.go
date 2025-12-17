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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/stats"
)

// ConnMgrService manages the lifecycle of connection monitoring with configurable intervals and context handling.
type ConnMgrService struct {
	interval                time.Duration
	startGenericConnections func(context.Context)

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
}

// NewDefaultConnMgrService creates a ConnMgrService with default settings for connection monitoring and context handling.
func NewDefaultConnMgrService() *ConnMgrService {
	return NewConnMgrService(5*time.Second, stats.UpdateGenericConnectionsWithContext)
}

// NewConnMgrService initializes and returns a new instance of ConnMgrService with the given interval and start function.
func NewConnMgrService(interval time.Duration, startGenericConnections func(context.Context)) *ConnMgrService {
	return &ConnMgrService{
		interval:                interval,
		startGenericConnections: startGenericConnections,
	}
}

// Start initializes and starts the connection monitoring process with the provided parent context.
func (s *ConnMgrService) Start(parent context.Context) error {
	if !config.GetFile().GetServer().GetInsights().IsMonitorConnectionsEnabled() {
		level.Info(log.Logger).Log(definitions.LogKeyMsg, "Connection monitoring is disabled")

		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	s.ctx, s.cancel = context.WithCancel(parent)
	s.running = true

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Starting connection monitoring")

	manager := connmgr.GetConnectionManager()
	manager.Register(s.ctx, config.GetFile().GetServer().Address, "local", "HTTP server")

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		manager.StartTickerWithContext(s.ctx, s.interval)
	}()

	if s.startGenericConnections != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

			s.startGenericConnections(s.ctx)
		}()
	}

	manager.StartMonitoring(s.ctx)

	return nil
}

// Stop terminates the connection monitoring service.
//
// It attempts to stop within the provided context deadline.
func (s *ConnMgrService) Stop(stopCtx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()

		return nil
	}

	cancel := s.cancel
	s.running = false
	s.cancel = nil
	s.ctx = nil

	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-stopCtx.Done():
		return stopCtx.Err()
	}
}
