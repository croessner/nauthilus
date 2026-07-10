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
	"context"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy/report"
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

// PluginEnvironmentSourceBridge adapts native pre-auth environment sources without importing pluginruntime.
//
//goland:nointerface
type PluginEnvironmentSourceBridge interface {
	Evaluate(ctx *gin.Context, view *StateView) (triggered bool, abort bool, handled bool, err error)
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

// PostActionPlanInput supplies the detached plan runtime to one Lua post-action step.
type PostActionPlanInput struct {
	Runtime map[string]any
}

// PostActionPlanPreparer captures request-bound Lua state before detached execution.
type PostActionPlanPreparer interface {
	PreparePlanStep(input PostActionInput) PostActionPlanRunner
}

// PostActionPlanRunner executes one already captured shared-plan step.
type PostActionPlanRunner interface {
	RunPlanStep(ctx context.Context, input PostActionPlanInput) (pluginapi.RuntimeDelta, bool)
}

// PostActionPlanStepKind identifies the executable post-action step type.
type PostActionPlanStepKind string

const (
	// PostActionPlanStepNative identifies a native plugin post-action target.
	PostActionPlanStepNative PostActionPlanStepKind = "native"

	// PostActionPlanStepLua identifies the default Lua post-action dispatcher.
	PostActionPlanStepLua PostActionPlanStepKind = "lua"
)

// PostActionPlanStep describes one ordered post-action step captured by the policy executor.
type PostActionPlanStep struct {
	cleanup   func()
	effect    report.EffectRequest
	luaRunner PostActionPlanRunner
	id        string
	kind      PostActionPlanStepKind
}

// NewNativePostActionPlanStep creates a plan step for a native plugin post-action effect.
func NewNativePostActionPlanStep(effect report.EffectRequest) PostActionPlanStep {
	return PostActionPlanStep{
		effect: effect,
		id:     effect.ID,
		kind:   PostActionPlanStepNative,
	}
}

// NewLuaPostActionPlanStep creates a plan step for a Lua post-action dispatcher.
func NewLuaPostActionPlanStep(id string, runner PostActionPlanRunner, cleanup func()) PostActionPlanStep {
	return PostActionPlanStep{
		cleanup:   cleanup,
		luaRunner: runner,
		id:        id,
		kind:      PostActionPlanStepLua,
	}
}

// ID returns the policy effect identifier represented by the step.
func (s PostActionPlanStep) ID() string {
	return s.id
}

// Kind returns whether the step targets Lua or a native plugin.
func (s PostActionPlanStep) Kind() PostActionPlanStepKind {
	return s.kind
}

// NativeEffect returns the native effect carried by this step.
func (s PostActionPlanStep) NativeEffect() (report.EffectRequest, bool) {
	return s.effect, s.kind == PostActionPlanStepNative
}

// LuaStep returns the already captured Lua plan runner.
func (s PostActionPlanStep) LuaStep() (PostActionPlanRunner, bool) {
	return s.luaRunner, s.kind == PostActionPlanStepLua && s.luaRunner != nil
}

// Release frees resources owned by the captured plan step.
func (s PostActionPlanStep) Release() {
	if s.cleanup != nil {
		s.cleanup()
	}
}

// ReleasePostActionPlanSteps releases resources owned by all captured plan steps.
func ReleasePostActionPlanSteps(steps []PostActionPlanStep) {
	for index := range steps {
		steps[index].Release()
	}
}

// PluginEffectBridge executes native policy-selected effects without importing pluginruntime.
//
//goland:nointerface
type PluginEffectBridge interface {
	// IsPostActionEffect reports whether an effect targets a native post-action component.
	IsPostActionEffect(effect report.EffectRequest) bool

	// EnqueuePostActionPlan starts one host-supervised ordered post-action plan.
	EnqueuePostActionPlan(ctx *gin.Context, view *StateView, steps []PostActionPlanStep) (handled bool, ok bool)

	// ExecutePolicyEffect runs a synchronous native policy effect.
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
