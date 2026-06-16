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
	"github.com/croessner/nauthilus/server/policy/report"
	"github.com/gin-gonic/gin"
)

// LuaSubject encapsulates the Lua subject source pipeline and returns an AuthResult.
//
//goland:nointerface
type LuaSubject interface {
	Analyze(ctx *gin.Context, view *StateView, result *PassDBResult) definitions.AuthResult
}

// PluginSubjectSourceBridge adapts native post-backend subject sources without importing pluginruntime.
//
//goland:nointerface
type PluginSubjectSourceBridge interface {
	Analyze(ctx *gin.Context, view *StateView, result *PassDBResult, current definitions.AuthResult) (definitions.AuthResult, bool)
}

// PostActionInput aggregates the minimal inputs required for the Lua post action.
// It deliberately reduces dozens of parameters to a compact value object.
type PostActionInput struct {
	View                     *StateView
	Result                   *PassDBResult
	EnvironmentRejected      bool
	EnvironmentStageExpected bool
	SubjectStageExpected     bool
}

// PostAction encapsulates the asynchronous post-action dispatch to the Lua worker.
//
//goland:nointerface
type PostAction interface {
	Run(input PostActionInput)
}

// PluginEffectBridge executes native policy-selected effects without importing pluginruntime.
//
//goland:nointerface
type PluginEffectBridge interface {
	ExecutePolicyEffect(ctx *gin.Context, view *StateView, effect report.EffectRequest) (handled bool, ok bool)
}

// EnvironmentEngine encapsulates the evaluation of Lua environment sources.
// It returns whether an environment source was triggered, whether later sources should be aborted,
// and optional logs plus a new StatusMessage.
//
//goland:nointerface
type EnvironmentEngine interface {
	Evaluate(ctx *gin.Context, view *StateView) (triggered bool, abort bool, logs []any, newStatus *string, err error)
}

// ActionDispatcher encapsulates triggering Lua actions (performAction).
//
//goland:nointerface
type ActionDispatcher interface {
	Dispatch(view *StateView, environmentName string, luaAction definitions.LuaAction)
}

// RBLService encapsulates RBL checking and aggregation.
//
//goland:nointerface
type RBLService interface {
	// Score computes the aggregated RBL score for the request.
	Score(ctx *gin.Context, view *StateView) (int, error)

	// Threshold returns the configured threshold at which an environment control is triggered.
	Threshold() int
}

// RBLFactService computes the aggregated RBL score together with policy-visible facts.
type RBLFactService interface {
	// ScoreWithFacts computes the aggregated RBL score and returns the request-local policy facts.
	ScoreWithFacts(ctx *gin.Context, view *StateView) (RBLPolicyFact, error)
}
