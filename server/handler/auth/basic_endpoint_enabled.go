//go:build auth_basic_endpoint

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

package auth

import (
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
)

func (h *Handler) registerBasicEndpoint(
	authGroup gin.IRouter,
	withService func(service string, next gin.HandlerFunc) gin.HandlerFunc,
) {
	authGroup.GET("/"+definitions.ServBasic, withService(definitions.ServBasic, h.basic))
}

func (h *Handler) basic(ctx *gin.Context) {
	h.handleWithTrace(ctx, h.deps.Cfg.GetServer().GetEndpoint().IsAuthBasicDisabled, "rest.auth_basic")
}
