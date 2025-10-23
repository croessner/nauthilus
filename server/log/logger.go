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

package log

import (
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/croessner/nauthilus/server/definitions"
)

var (
	mu sync.Mutex

	// Logger is used for all messages that are printed to stdout
	Logger *slog.Logger
)

// SetupLogging initializes the global "Logger" object.
func SetupLogging(configLogLevel int, formatJSON bool, useColor bool, addSource bool, instance string) { // useColor kept for signature compatibility; coloring not implemented in slog TextHandler
	mu.Lock()
	defer mu.Unlock()

	// Map configLogLevel to slog level
	var minLevel slog.Level

	switch configLogLevel {
	case definitions.LogLevelNone:
		// Level value is irrelevant when output is discarded; keep a sane default
		minLevel = slog.LevelInfo
	case definitions.LogLevelError:
		minLevel = slog.LevelError
	case definitions.LogLevelWarn:
		minLevel = slog.LevelWarn
	case definitions.LogLevelInfo:
		minLevel = slog.LevelInfo
	case definitions.LogLevelDebug:
		minLevel = slog.LevelDebug
	default:
		minLevel = slog.LevelInfo
	}

	handlerOpts := &slog.HandlerOptions{Level: minLevel, AddSource: addSource}

	// Choose output target: for LogLevelNone, discard everything using io.Discard
	var out io.Writer = os.Stdout
	if configLogLevel == definitions.LogLevelNone {
		out = io.Discard
	}

	var handler slog.Handler

	if formatJSON {
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}

	Logger = slog.New(handler).With(slog.String(definitions.LogKeyInstance, instance))
}
