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

package logfx

import (
	"fmt"
	"log/slog"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"

	"go.uber.org/fx/fxevent"
)

// FxEventLogger adapts fx internal events to the existing slog-based logging.
type FxEventLogger struct {
	logger *slog.Logger
}

func NewFxEventLogger(logger *slog.Logger) fxevent.Logger {
	return &FxEventLogger{logger: logger}
}

func (l *FxEventLogger) LogEvent(event fxevent.Event) {
	if l == nil || l.logger == nil {
		return
	}

	switch e := event.(type) {
	case *fxevent.LoggerInitialized:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx logger initialized")
	case *fxevent.Started:
		level.Info(l.logger).Log(definitions.LogKeyMsg, "fx started")
	case *fxevent.Stopped:
		level.Info(l.logger).Log(definitions.LogKeyMsg, "fx stopped")
	case *fxevent.RollingBack:
		level.Warn(l.logger).Log(definitions.LogKeyMsg, "fx rolling back", definitions.LogKeyError, e.StartErr)
	case *fxevent.RolledBack:
		level.Warn(l.logger).Log(definitions.LogKeyMsg, "fx rolled back", definitions.LogKeyError, e.Err)
	case *fxevent.OnStartExecuting:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx OnStart executing", "callee", e.FunctionName)
	case *fxevent.OnStartExecuted:
		l.logHookResult("fx OnStart executed", e.FunctionName, e.Err)
	case *fxevent.OnStopExecuting:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx OnStop executing", "callee", e.FunctionName)
	case *fxevent.OnStopExecuted:
		l.logHookResult("fx OnStop executed", e.FunctionName, e.Err)
	case *fxevent.Supplied:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx supplied", "type", e.TypeName, "stacktrace", e.StackTrace)
	case *fxevent.Provided:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx provided", "constructor", e.ConstructorName, "output_type", e.OutputTypeNames, "module", e.ModuleName)
	case *fxevent.Invoking:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx invoking", "function", e.FunctionName, "module", e.ModuleName)
	case *fxevent.Invoked:
		if e.Err != nil {
			level.Error(l.logger).Log(definitions.LogKeyMsg, "fx invoked", "function", e.FunctionName, definitions.LogKeyError, e.Err)

			return
		}

		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx invoked", "function", e.FunctionName)
	default:
		level.Debug(l.logger).Log(definitions.LogKeyMsg, "fx event", "type", fmt.Sprintf("%T", event))
	}
}

func (l *FxEventLogger) logHookResult(msg string, callee string, err error) {
	if err != nil {
		level.Error(l.logger).Log(definitions.LogKeyMsg, msg, "callee", callee, definitions.LogKeyError, err)

		return
	}

	level.Debug(l.logger).Log(definitions.LogKeyMsg, msg, "callee", callee)
}
