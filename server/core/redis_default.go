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

package core

import (
	stdlog "log"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/rediscli"
)

// Redis DI seam for selected core subtrees.
//
// Some core packages (e.g. stats/metrics helpers) historically pull Redis via
// `rediscli.GetClient()`. To migrate incrementally without changing many public
// signatures, we keep a process-wide default client that boundaries can set
// from the injected `redifx.Client`.

type redisHolder struct {
	c rediscli.Client
}

var defaultRedis atomic.Value

var warnMissingRedisOnce sync.Once

func init() {
	defaultRedis.Store(redisHolder{c: nil})
}

// SetDefaultRedisClient sets the process-wide default Redis client for core.
func SetDefaultRedisClient(c rediscli.Client) {
	defaultRedis.Store(redisHolder{c: c})
}

func getDefaultRedisClient() rediscli.Client {
	if v := defaultRedis.Load(); v != nil {
		if h, ok := v.(redisHolder); ok {
			if h.c != nil {
				return h.c
			}
		}
	}

	// Hard fail: the default Redis client must be configured at the boundary.
	warnMissingRedisOnce.Do(func() {
		stdlog.Printf("ERROR: core default Redis client is not configured. Ensure the boundary calls core.SetDefaultRedisClient(...)\n")
	})

	panic("core: default Redis client not configured")
}
