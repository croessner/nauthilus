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

	"github.com/croessner/nauthilus/server/backend/accountcache"
)

// AccountCache injection seam for core subtrees.
//
// Runtime must configure a default account cache at the boundary.

type accountCacheHolder struct {
	ac *accountcache.Manager
}

var defaultAccountCache atomic.Value
var warnMissingAccountCacheOnce sync.Once

func init() {
	defaultAccountCache.Store(accountCacheHolder{ac: nil})
}

// SetDefaultAccountCache sets the process-wide default account cache for core.
func SetDefaultAccountCache(ac *accountcache.Manager) {
	defaultAccountCache.Store(accountCacheHolder{ac: ac})
}

func getDefaultAccountCache() *accountcache.Manager {
	if v := defaultAccountCache.Load(); v != nil {
		if h, ok := v.(accountCacheHolder); ok {
			if h.ac != nil {
				return h.ac
			}
		}
	}

	warnMissingAccountCacheOnce.Do(func() {
		stdlog.Printf("ERROR: core default account cache is not configured. Ensure the boundary calls core.SetDefaultAccountCache(...)\n")
	})

	panic("core: default account cache not configured")
}
