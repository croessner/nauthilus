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

package custom

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
)

// Handler registers custom Lua hook endpoint(s).
type Handler struct {
	cfgProvider configfx.Provider
	logger      *slog.Logger
	redis       rediscli.Client
	validator   oidcbearer.TokenValidator
}

// New creates a Handler with zero dependencies (for testing).
func New() *Handler {
	return &Handler{}
}

// NewWithDeps creates a Handler with explicit dependencies.
// The validator may be nil when OIDC authentication is not configured.
func NewWithDeps(cfgProvider configfx.Provider, logger *slog.Logger, redis rediscli.Client, validator oidcbearer.TokenValidator) *Handler {
	return &Handler{cfgProvider: cfgProvider, logger: logger, redis: redis, validator: validator}
}

// Register registers the custom hook route on the given router.
func (h *Handler) Register(r gin.IRouter) {
	r.Any("/custom/*hook", CustomRequestHandler(h.cfgProvider, h.logger, h.redis, h.validator))
}
