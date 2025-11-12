// Copyright (C) 2024-2025 Christian Rößner
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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

// LuaFilter encapsulates the Lua filter pipeline and returns an AuthResult.
//
//goland:nointerface
type LuaFilter interface {
	Filter(ctx *gin.Context, view *StateView, result *PassDBResult) definitions.AuthResult
}

// PostActionInput aggregates the minimal inputs required for the Lua post action.
// It deliberately reduces dozens of parameters to a compact value object.
type PostActionInput struct {
	View   *StateView
	Result *PassDBResult
}

// PostAction encapsulates the asynchronous post-action dispatch to the Lua worker.
//
//goland:nointerface
type PostAction interface {
	Run(input PostActionInput)
}
