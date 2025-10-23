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
	logcolor "github.com/croessner/nauthilus/server/log/color"

	"golang.org/x/sys/unix"
)

var (
	mu sync.Mutex

	// Logger is used for all messages that are printed to stdout
	Logger *slog.Logger
)

// isTerminal checks if the given file descriptor corresponds to a terminal by verifying termios configuration.
func isTerminal(w *os.File) bool {
	_, err := unix.IoctlGetTermios(int(w.Fd()), unix.TIOCGETA)

	return err == nil
}

// SetupLogging initializes the global "Logger" object.
func SetupLogging(configLogLevel int, formatJSON bool, useColor bool, addSource bool, instance string) {
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

	termTheme := os.Getenv("NAUTHILUS_TERM_THEME")

	if formatJSON {
		// JSON output should never be colored
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else if useColor && isTerminal(os.Stdout) && configLogLevel != definitions.LogLevelNone {
		// Use wrapper to preserve TextHandler format while coloring full line; theme-aware colors
		colors := logcolor.ThemeColorMap(termTheme)
		handler = logcolor.NewLineWrapper(out, handlerOpts, colors)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}

	Logger = slog.New(handler).With(slog.String(definitions.LogKeyInstance, instance))
}
