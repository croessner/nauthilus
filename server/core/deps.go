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
	"log/slog"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
)

// AuthDeps bundles dependencies required by authentication request paths.
type AuthDeps struct {
	Cfg          config.File
	Logger       *slog.Logger
	Env          config.Environment
	Redis        rediscli.Client
	Tolerate     tolerate.Tolerate
	AccountCache *accountcache.Manager
	Channel      backend.Channel
}

type HydraHandlers struct {
	deps AuthDeps
}

func NewHydraHandlers(deps AuthDeps) *HydraHandlers {
	return &HydraHandlers{deps: deps}
}
