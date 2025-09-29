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

package bruteforce

import (
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"

	"github.com/gin-gonic/gin"
)

type Handler struct{}

func New() *Handler {
	return &Handler{}
}

func (h *Handler) Register(router gin.IRouter) {
	bg := router.Group("/" + definitions.CatBruteForce)

	bg.GET("/"+definitions.ServList, core.HanldeBruteForceList)
	bg.POST("/"+definitions.ServList, core.HanldeBruteForceList)
	bg.DELETE("/"+definitions.ServFlush, core.HandleBruteForceRuleFlush)
}
