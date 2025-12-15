// Copyright (C) 2025 Christian Rößner
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
	"context"
	stdlog "log"
	"log/slog"

	"go.uber.org/fx"

	"github.com/croessner/nauthilus/server/log"
)

// NewLogger provides the process logger.
func NewLogger() *slog.Logger {
	return log.Logger
}

// BridgeStdLog wires the standard library log package to the provided slog logger.
//
// This is executed in an fx lifecycle hook to ensure the logger is available.
func BridgeStdLog(lc fx.Lifecycle, logger *slog.Logger) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if logger == nil {
				return nil
			}

			stdlog.SetOutput(&slogStdWriter{logger: logger})

			return nil
		},
	})
}
