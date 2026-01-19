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

package tolerate

import (
	stdlog "log"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/rediscli"
)

// Redis DI seam for bruteforce tolerations.
//
// The tolerate subsystem historically accessed Redis via the global singleton.
// To migrate consumers without a large signature refactor, we keep a package-level
// default client that is set at boundaries from the injected `redifx.Client`.

type clientHolder struct {
	c rediscli.Client
}

var defaultClient atomic.Value

var warnMissingRedisOnce sync.Once

func init() {
	defaultClient.Store(clientHolder{c: nil})
}

// SetDefaultClient sets the tolerate-wide default Redis client.
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
	warnMissingRedisOnce.Do(func() {
		stdlog.Printf("ERROR: tolerate default Redis client is not configured. Ensure the boundary calls tolerate.SetDefaultClient(...)\n")
	})

	panic("tolerate: default Redis client not configured")
}
