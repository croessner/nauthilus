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

// FeatureEngine encapsulates the evaluation of Lua-based features.
// It returns whether a feature was triggered, whether further features should be aborted,
// and optional logs plus a new StatusMessage.
//
//goland:nointerface
type FeatureEngine interface {
	Evaluate(ctx *gin.Context, view *StateView) (triggered bool, abort bool, logs []any, newStatus *string, err error)
}

// ActionDispatcher encapsulates triggering Lua actions (performAction).
//
//goland:nointerface
type ActionDispatcher interface {
	Dispatch(view *StateView, featureName string, luaAction definitions.LuaAction)
}

// RBLService encapsulates RBL checking and aggregation.
//
//goland:nointerface
type RBLService interface {
	// Score computes the aggregated RBL score for the request.
	Score(ctx *gin.Context, view *StateView) (int, error)

	// Threshold returns the configured threshold at which a feature is triggered.
	Threshold() int
}
