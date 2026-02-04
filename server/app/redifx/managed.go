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

package redifx

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// ManagedClient is a swap-capable Redis client facade.
//
// It implements `rediscli.Client` by delegating to an atomically stored
// underlying client. Restart orchestration can rebuild/swap the underlying
// client without requiring consumers to call global singletons.
//
// Note: callers must treat rebuild as best-effort and still run readiness
// checks (e.g., `setupRedis`) at higher layers.
type ManagedClient struct {
	cur atomic.Value // stores clientHolder

	// rebuildMu serializes rebuild operations.
	// Consumers continue to read from atomic pointer.
	rebuildMu sync.Mutex
}

type clientHolder struct {
	c rediscli.Client
}

var _ rediscli.Client = (*ManagedClient)(nil)
var _ Rebuilder = (*ManagedClient)(nil)

func NewManagedClient(initial rediscli.Client) *ManagedClient {
	m := &ManagedClient{}
	// atomic.Value must store a consistent concrete type
	m.cur.Store(clientHolder{c: initial})

	return m
}

func (m *ManagedClient) get() rediscli.Client {
	if m == nil {
		return nil
	}

	if v := m.cur.Load(); v != nil {
		if h, ok := v.(clientHolder); ok {
			return h.c
		}
	}

	return nil
}

func (m *ManagedClient) GetWriteHandle() redis.UniversalClient {
	if c := m.get(); c != nil {
		return c.GetWriteHandle()
	}

	return nil
}

func (m *ManagedClient) GetReadHandle() redis.UniversalClient {
	if c := m.get(); c != nil {
		return c.GetReadHandle()
	}

	return nil
}

func (m *ManagedClient) GetWritePipeline() redis.Pipeliner {
	if c := m.get(); c != nil {
		return c.GetWritePipeline()
	}

	return nil
}

func (m *ManagedClient) GetReadPipeline() redis.Pipeliner {
	if c := m.get(); c != nil {
		return c.GetReadPipeline()
	}

	return nil
}

func (m *ManagedClient) Close() {
	if c := m.get(); c != nil {
		c.Close()
	}
}

func (m *ManagedClient) GetSecurityManager() *rediscli.SecurityManager {
	if c := m.get(); c != nil {
		return c.GetSecurityManager()
	}

	return nil
}

func (m *ManagedClient) Rebuild(cfg config.File, logger *slog.Logger) error {
	if cfg == nil {
		return errors.New("config is nil")
	}

	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()

	old := m.get()
	newClient := rediscli.NewClientWithDeps(cfg, logger)
	m.cur.Store(clientHolder{c: newClient})

	if old != nil {
		old.Close()
	}

	return nil
}
