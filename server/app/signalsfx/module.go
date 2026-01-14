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

package signalsfx

import (
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/app/restartfx"

	"go.uber.org/fx"
)

// Module wires signal ownership into the fx application.
//
// It provides a testable signal Notifier, binds reload/restart manager implementations
// to the Controller runner interfaces, and registers the Controller as an fx lifecycle hook.
func Module() fx.Option {
	return fx.Options(
		fx.Provide(func(m *reloadfx.Manager) ReloadRunner { return m }),
		fx.Provide(func(m *restartfx.Manager) RestartRunner { return m }),
		fx.Provide(NewNotifier),
		fx.Provide(NewController),
		fx.Invoke(func(lc fx.Lifecycle, c *Controller) {
			lc.Append(fx.Hook{
				OnStart: c.Start,
				OnStop:  c.Stop,
			})
		}),
	)
}
