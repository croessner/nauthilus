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
	"log/slog"
	"sync"
	"sync/atomic"
)

// Logger injection seam for core subtrees.
//
// Runtime must configure a default logger at the boundary.

type loggerHolder struct {
	l *slog.Logger
}

var defaultLogger atomic.Value
var warnMissingLoggerOnce sync.Once

func init() {
	defaultLogger.Store(loggerHolder{l: nil})
}

// SetDefaultLogger sets the process-wide default logger for core.
func SetDefaultLogger(l *slog.Logger) {
	defaultLogger.Store(loggerHolder{l: l})
}

func getDefaultLogger() *slog.Logger {
	if v := defaultLogger.Load(); v != nil {
		if h, ok := v.(loggerHolder); ok {
			if h.l != nil {
				return h.l
			}
		}
	}

	warnMissingLoggerOnce.Do(func() {
		stdlog.Printf("ERROR: core default logger is not configured. Ensure the boundary calls core.SetDefaultLogger(...)\n")
	})

	panic("core: default logger not configured")
}
