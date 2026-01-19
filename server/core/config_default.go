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

// Config injection seam for core subtrees.
//
// Runtime must configure a default config snapshot at the boundary.

type cfgHolder struct {
	cfg config.File
}

var defaultCfg atomic.Value
var warnMissingCfgOnce sync.Once

func init() {
	defaultCfg.Store(cfgHolder{cfg: nil})
}

// SetDefaultConfigFile sets the process-wide default config snapshot for core.
func SetDefaultConfigFile(cfg config.File) {
	defaultCfg.Store(cfgHolder{cfg: cfg})
}

// GetDefaultConfigFile returns the process-wide default config snapshot for core.
func GetDefaultConfigFile() config.File {
	return getDefaultConfigFile()
}

func getDefaultConfigFile() config.File {
	if v := defaultCfg.Load(); v != nil {
		if h, ok := v.(cfgHolder); ok {
			if h.cfg != nil {
				return h.cfg
			}
		}
	}

	warnMissingCfgOnce.Do(func() {
		stdlog.Printf("ERROR: core default config snapshot is not configured. Ensure the boundary calls core.SetDefaultConfigFile(...)\n")
	})

	panic("core: default config snapshot not configured")
}
