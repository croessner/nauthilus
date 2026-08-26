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
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// CapturedLuaSubject executes one generation-owned precompiled subject source.
type CapturedLuaSubject interface {
	AnalyzeSource(
		ctx *gin.Context,
		view *StateView,
		result *PassDBResult,
		name string,
		prototype *lua.FunctionProto,
		pools *vmpool.Manager,
		poolKey vmpool.PoolKey,
		modules *luaseal.Modules,
	) definitions.AuthResult
}

// RBLService encapsulates RBL checking and aggregation.
//
//goland:nointerface
type RBLService interface {
	// Score computes the aggregated RBL score for the request.
	Score(ctx *gin.Context, view *StateView) (int, error)
}

// RBLFactService computes the aggregated RBL score together with policy-visible facts.
type RBLFactService interface {
	// ScoreWithFacts computes the aggregated RBL score and returns the request-local policy facts.
	ScoreWithFacts(ctx *gin.Context, view *StateView) (RBLPolicyFact, error)
}
