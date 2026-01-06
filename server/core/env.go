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
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
)

// Make environment consumption injectable for core subtrees.
//
// Until all consumers accept explicit deps, we keep a process-wide default that
// is set at the HTTP boundary (and other boundaries later). This removes direct
// `config.GetEnvironment()` calls from migrated code while keeping backward
// compatibility for non-migrated call sites.

type envHolder struct {
	env config.Environment
}

var defaultEnvironment atomic.Value

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

	// Legacy fallback for non-migrated call sites.
	// This may still panic if the legacy singleton is uninitialized, preserving old behavior.
	return config.GetEnvironment()
}
