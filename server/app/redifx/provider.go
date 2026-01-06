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

package redifx

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
)

// Client is the Redis facade type used for DI.
type Client = rediscli.Client

// NewClient provides a Redis client facade.
func NewClient() Client {
	// This project uses DI-owned Redis construction.
	//
	// This legacy constructor previously delegated to the global singleton.
	// It is intentionally disabled to prevent re-introducing global access.
	panic("redifx.NewClient is deprecated; use DI-owned Redis construction (ManagedClient via fx wiring)")
}

// Rebuilder can rebuild/swap the underlying Redis client instance.
//
// Used by restart orchestration to rebuild Redis without relying on
// the global singleton.
type Rebuilder interface {
	Rebuild(cfg config.File, logger *slog.Logger) error
}
