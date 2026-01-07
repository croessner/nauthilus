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

	"github.com/croessner/nauthilus/server/config"
)

// Environment injection seam for core subtrees.
//
// This enables incremental migration away from direct `config.GetEnvironment()`
// calls by providing a process-wide default that is set at the boundary.

type envHolder struct {
	env config.Environment
}

var defaultEnvironment atomic.Value

var warnMissingEnvOnce sync.Once

func init() {
	// Keep nil by default to avoid touching config/env globals during init.
	// atomic.Value must never store an untyped nil.
	defaultEnvironment.Store(envHolder{env: nil})
}

// SetDefaultEnvironment sets the process-wide default environment.
// Call this at boundaries (HTTP startup, workers, etc.) once the environment is known.
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

	// Hard fail: environment must be configured at the boundary.
	warnMissingEnvOnce.Do(func() {
		stdlog.Printf("ERROR: core default Environment is not configured. Ensure the boundary calls core.SetDefaultEnvironment(...)\n")
	})

	panic("core: default Environment not configured")
}
