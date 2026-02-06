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

package util

import (
	stdlog "log"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
)

// Environment injection seam for util package.
//
// `util` is a widely used leaf-ish package. To avoid pulling core dependencies
// into util, we keep a small process-wide default that can be set at boundaries.
// This removes direct `config.GetEnvironment()` usage from migrated util code.

type envHolder struct {
	env config.Environment
}

var defaultEnvironment atomic.Value

var warnMissingEnvOnce sync.Once

func init() {
	defaultEnvironment.Store(envHolder{env: nil})
}

// SetDefaultEnvironment sets the process-wide default environment for util.
func SetDefaultEnvironment(env config.Environment) {
	defaultEnvironment.Store(envHolder{env: env})
}

// GetDefaultEnvironment returns the process-wide default environment for util.
func GetDefaultEnvironment() config.Environment {
	return getDefaultEnvironment()
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
		stdlog.Printf("ERROR: util default Environment is not configured. Ensure the boundary calls util.SetDefaultEnvironment(...)\n")
	})

	panic("util: default Environment not configured")
}

// ShouldSetSecureCookie reports whether cookies should be marked as Secure.
// It returns false in developer mode to allow HTTP callbacks.
func ShouldSetSecureCookie() bool {
	return !getDefaultEnvironment().GetDevMode()
}
