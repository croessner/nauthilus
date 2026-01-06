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

package action

import (
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
)

// Environment injection seam for the Lua action worker package.
//
// This removes direct `config.GetEnvironment()` usage from migrated code paths
// while keeping a legacy fallback for non-migrated call sites.

type envHolder struct {
	env config.Environment
}

var defaultEnvironment atomic.Value

func init() {
	defaultEnvironment.Store(envHolder{env: nil})
}

// SetDefaultEnvironment sets the process-wide default environment for `lualib/action`.
func SetDefaultEnvironment(env config.Environment) {
	defaultEnvironment.Store(envHolder{env: env})
}

func getDefaultEnvironment() config.Environment {
	if v := defaultEnvironment.Load(); v != nil {
		if h, ok := v.(envHolder); ok {
			if h.env != nil {
				return h.env
			}
		}
	}

	return config.GetEnvironment()
}
