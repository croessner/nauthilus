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
	"os"
	"sync"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-kit/log/term"
)

var (
	mu sync.Mutex

	// Logger is used for all messages that are printed to stdout
	Logger log.Logger
)

// SetupLogging initializes the global "Logger" object.
func SetupLogging(configLogLevel int, formatJSON bool, useColor bool, instance string) {
	var logLevel level.Option

	mu.Lock()

	defer mu.Unlock()

	if useColor {
		colorFn := func(keyvals ...any) term.FgBgColor {
			for i := 0; i < len(keyvals)-1; i += 2 {
				if keyvals[i] != level.Key() {
					continue
				}

				switch keyvals[i+1] {
				case level.DebugValue():
					return term.FgBgColor{Fg: term.DarkBlue}
				case level.InfoValue():
					return term.FgBgColor{Fg: term.Default}
				case level.WarnValue():
					return term.FgBgColor{Fg: term.Yellow}
				case level.ErrorValue():
					return term.FgBgColor{Fg: term.Red}
				default:
					return term.FgBgColor{}
				}
			}

			return term.FgBgColor{}
		}

		if formatJSON {
			Logger = term.NewLogger(os.Stdout, log.NewJSONLogger, colorFn)
		} else {
			Logger = term.NewLogger(os.Stdout, log.NewLogfmtLogger, colorFn)
		}
	} else {
		if formatJSON {
			Logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
		} else {
			Logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
		}
	}

	switch configLogLevel {
	case definitions.LogLevelNone:
		logLevel = level.AllowNone()
	case definitions.LogLevelError:
		logLevel = level.AllowError()
	case definitions.LogLevelWarn:
		logLevel = level.AllowWarn()
	case definitions.LogLevelInfo:
		logLevel = level.AllowInfo()
	case definitions.LogLevelDebug:
		logLevel = level.AllowDebug()
	}

	Logger = level.NewFilter(Logger, logLevel)

	Logger = log.With(
		Logger,
		"ts", log.DefaultTimestamp, "caller", log.DefaultCaller, definitions.LogKeyInstance, instance,
	)
}
