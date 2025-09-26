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

package router

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// Router is a small builder around gin.Engine to assemble middlewares and routes
// without leaking application-specific logic into this package.
type Router struct {
	Engine *gin.Engine
	Cfg    config.File
}

// NewRouter creates a new Router builder with a fresh gin.Engine.
func NewRouter(cfg config.File) *Router {
	return &Router{Engine: gin.New(), Cfg: cfg}
}

// Build returns the underlying gin.Engine.
func (r *Router) Build() *gin.Engine {
	return r.Engine
}
