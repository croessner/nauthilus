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

package redislib

import (
	stdlog "log"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/rediscli"
)

// Redis DI seam for Lua Redislib.
//
// `redislib` is used by Lua execution contexts which are created deep inside the
// request path. To avoid calling the legacy global singleton (`rediscli.GetClient()`)
// in these runtime paths, we keep a process-wide default client that is set at
// the HTTP boundary from the injected `redifx.Client`.
//
// Non-migrated call sites keep the legacy fallback.

type clientHolder struct {
	c rediscli.Client
}

var defaultClient atomic.Value

var warnFallbackOnce sync.Once

func init() {
	// atomic.Value must always store the same concrete type.
	defaultClient.Store(clientHolder{c: nil})
}

// SetDefaultClient sets the process-wide default Redis client for the Lua redislib.
func SetDefaultClient(c rediscli.Client) {
	defaultClient.Store(clientHolder{c: c})
}

func getDefaultClient() rediscli.Client {
	if v := defaultClient.Load(); v != nil {
		if h, ok := v.(clientHolder); ok {
			if h.c != nil {
				return h.c
			}
		}
	}

	// Hard fail always.
	// If this triggers, an entry point executed Lua redislib without configuring the default client.
	warnFallbackOnce.Do(func() {
		stdlog.Printf("ERROR: lualib/redislib default Redis client is not configured. Ensure all entry points call redislib.SetDefaultClient(...)\n")
	})

	panic("lualib/redislib: default Redis client not configured. Call redislib.SetDefaultClient(...) at the boundary")
}
