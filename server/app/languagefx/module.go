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

package languagefx

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/core/language"
	"go.uber.org/fx"
)

// Module provides the language manager to the fx application.
func Module() fx.Option {
	return fx.Provide(
		func(cfgProvider configfx.Provider, logger *slog.Logger) (language.Manager, error) {
			return language.NewManager(cfgProvider.Current().File, logger)
		},
	)
}
