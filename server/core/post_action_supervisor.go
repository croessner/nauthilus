// Copyright (C) 2026 Christian Roessner
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
	"log/slog"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/svcctx"
	"github.com/gin-gonic/gin"
)

const (
	authPostActionProvider    = "authn/post_action"
	authPostActionCapacity    = 128
	authPostActionConcurrency = 8
	authPostActionBudget      = 30 * time.Second
)

var (
	defaultPostActionSupervisor     *PostActionSupervisor
	defaultPostActionSupervisorOnce sync.Once
)

// PostActionSupervisor adapts captured auth work to the generic host-internal primitive.
type PostActionSupervisor struct {
	supervisor *effectsupervisor.Supervisor
}

type luaPostActionSequence struct {
	runtimeValues map[string]any
	mu            sync.Mutex
	remaining     int
}

type luaPostActionStepWork struct {
	sequence    *luaPostActionSequence
	runner      PostActionPlanRunner
	step        PostActionPlanStep
	previous    <-chan bool
	completed   chan bool
	finishOnce  sync.Once
	cleanupOnce sync.Once
}

type directLuaPostActionWork struct {
	runtime PostActionRuntime
	args    PostActionArgs
	once    sync.Once
}

// NewPostActionSupervisor creates one bounded auth post-action supervisor generation.
func NewPostActionSupervisor(lifetime context.Context) *PostActionSupervisor {
	logger := optionalDefaultLogger()
	if logger == nil {
		logger = slog.Default()
	}

	observer := effectsupervisor.NewOperationalObserver(
		logger,
		stats.GetMetrics().GetPostActionEffectStatesTotal(),
		effectsupervisor.NewLoggingAuditSink(logger),
	)

	supervisor, err := effectsupervisor.New(effectsupervisor.Config{
		Lifetime: lifetime,
		Observer: observer,
		Capacity: authPostActionCapacity,
		Workers:  authPostActionConcurrency,
	}, effectsupervisor.ProviderBinding{
		Name:     authPostActionProvider,
		Provider: effectsupervisor.NewExecutableProvider(),
	})
	if err != nil {
		panic(err)
	}

	return &PostActionSupervisor{supervisor: supervisor}
}

// Accept synchronously transfers one immutable auth post-action into host ownership.
func (s *PostActionSupervisor) Accept(
	ctx *gin.Context,
	view *StateView,
	ordinal uint32,
	work effectsupervisor.ExecutableWork,
) (effectsupervisor.Receipt, error) {
	if s == nil || s.supervisor == nil || view == nil || view.Auth() == nil {
		return effectsupervisor.Receipt{}, effectsupervisor.ErrInvalidPlan
	}

	auth := view.Auth()
	gate := PostActionFinalizationGate(ctx)
	policyCtx := existingPolicyContext(ctx)
	generation := uint64(0)

	if policyCtx != nil {
		_, _, generation = policyCtx.SnapshotMetadata()
	}

	plan, err := effectsupervisor.NewPlan(effectsupervisor.PlanInput{
		DecisionID:     auth.Runtime.GUID,
		EffectOrdinal:  ordinal,
		Target:         "authn/" + string(auth.policyOperation()),
		Provider:       authPostActionProvider,
		DeadlineBudget: postActionDeadlineBudget(auth),
		Gate:           gate,
		Observability: effectsupervisor.ObservabilityMetadata{
			RuntimeGeneration: generation,
			Source:            "authn",
		},
		Work: work,
	})
	if err != nil {
		return effectsupervisor.Receipt{}, err
	}

	return s.supervisor.Accept(contextFromGin(ctx), plan)
}

// WaitIdle waits until this generation has executed and cleaned every accepted item.
func (s *PostActionSupervisor) WaitIdle(ctx context.Context) error {
	if s == nil {
		return nil
	}

	return s.supervisor.WaitIdle(ctx)
}

// Shutdown rejects new work and cancels and cleans every accepted item.
func (s *PostActionSupervisor) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}

	return s.supervisor.Shutdown(ctx)
}

// IsShutdown reports whether this generation has permanently stopped accepting work.
func (s *PostActionSupervisor) IsShutdown() bool {
	return s == nil || s.supervisor == nil || s.supervisor.IsShutdown()
}

// EnqueueLuaPostActionPlan transfers one already captured Lua plan into supervisor ownership.
func EnqueueLuaPostActionPlan(
	ctx *gin.Context,
	view *StateView,
	ordinal uint32,
	runners []PostActionPlanRunner,
	steps []PostActionPlanStep,
) (effectsupervisor.Receipt, error) {
	works, err := newLuaPostActionStepWorks(runners, steps)
	if err != nil {
		ReleasePostActionPlanSteps(steps)

		return effectsupervisor.Receipt{}, err
	}

	var first effectsupervisor.Receipt

	for index, work := range works {
		effectOrdinal := ordinal + uint32(index)
		if index < len(steps) && steps[index].EffectOrdinal() > 0 {
			effectOrdinal = steps[index].EffectOrdinal()
		}

		receipt, acceptErr := acceptAuthPostAction(ctx, view, effectOrdinal, work)
		if acceptErr != nil {
			for _, rejected := range works[index:] {
				rejected.Cleanup()
			}

			return effectsupervisor.Receipt{}, acceptErr
		}

		if index == 0 {
			first = receipt
		}
	}

	return first, nil
}

// newLuaPostActionStepWorks creates one accepted owner per selected effect ordinal.
func newLuaPostActionStepWorks(runners []PostActionPlanRunner, steps []PostActionPlanStep) ([]*luaPostActionStepWork, error) {
	if len(runners) == 0 || (len(steps) > 0 && len(steps) != len(runners)) {
		return nil, effectsupervisor.ErrInvalidWork
	}

	for _, runner := range runners {
		if runner == nil {
			return nil, effectsupervisor.ErrInvalidWork
		}

		if err := runner.ValidatePlanStep(); err != nil {
			return nil, err
		}
	}

	sequence := &luaPostActionSequence{runtimeValues: make(map[string]any), remaining: len(runners)}
	previous := make(chan bool, 1)

	previous <- true

	works := make([]*luaPostActionStepWork, 0, len(runners))

	for index, runner := range runners {
		completed := make(chan bool, 1)

		work := &luaPostActionStepWork{
			sequence:  sequence,
			runner:    runner,
			previous:  previous,
			completed: completed,
		}
		if index < len(steps) {
			work.step = steps[index]
		}

		works = append(works, work)
		previous = completed
	}

	return works, nil
}

// Validate confirms that one selected Lua step has an immutable sequence owner.
func (w *luaPostActionStepWork) Validate() error {
	if w == nil || w.sequence == nil || w.runner == nil || w.previous == nil || w.completed == nil {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute waits for its predecessor and invokes one selected Lua effect.
func (w *luaPostActionStepWork) Execute(ctx context.Context) effectsupervisor.Result {
	select {
	case proceed := <-w.previous:
		if !proceed {
			w.finish(false)

			return effectsupervisor.Failed("prior_step_failed")
		}
	case <-ctx.Done():
		w.finish(false)

		return effectsupervisor.Failed("canceled")
	}

	w.sequence.mu.Lock()

	runtimeValues := make(map[string]any, len(w.sequence.runtimeValues))
	for key, value := range w.sequence.runtimeValues {
		runtimeValues[key] = value
	}
	w.sequence.mu.Unlock()

	delta, result := w.runner.RunPlanStep(ctx, PostActionPlanInput{Runtime: runtimeValues})
	if result.State() != effectsupervisor.StateSucceeded {
		w.finish(false)

		return result
	}

	w.sequence.mu.Lock()
	applyPostActionRuntimeDelta(w.sequence.runtimeValues, delta)
	w.sequence.mu.Unlock()
	w.finish(true)

	return effectsupervisor.Succeeded()
}

// Cleanup releases one step and the shared sequence through one idempotent path.
func (w *luaPostActionStepWork) Cleanup() {
	if w == nil {
		return
	}

	w.cleanupOnce.Do(func() {
		w.finish(false)
		w.step.Release()

		w.sequence.mu.Lock()
		w.sequence.remaining--

		if w.sequence.remaining == 0 {
			w.sequence.runtimeValues = nil
		}
		w.sequence.mu.Unlock()
	})
}

// finish publishes whether the next ordered effect may execute.
func (w *luaPostActionStepWork) finish(proceed bool) {
	if w == nil {
		return
	}

	w.finishOnce.Do(func() {
		w.completed <- proceed
	})
}

// applyPostActionRuntimeDelta merges one trusted Lua delta into later plan input.
func applyPostActionRuntimeDelta(runtimeValues map[string]any, delta pluginapi.RuntimeDelta) {
	for key, value := range delta.Set {
		runtimeValues[key] = value
	}

	for _, key := range delta.Delete {
		delete(runtimeValues, key)
	}
}

// Validate confirms the direct Lua work has captured a request context.
func (w *directLuaPostActionWork) Validate() error {
	if w == nil || w.args.HTTPRequest == nil {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute invokes the established Lua worker once under supervisor ownership.
func (w *directLuaPostActionWork) Execute(ctx context.Context) effectsupervisor.Result {
	return w.runtime.RunResult(ctx, w.args)
}

// Cleanup clears captured password bytes after direct Lua work finishes.
func (w *directLuaPostActionWork) Cleanup() {
	if w == nil {
		return
	}

	w.once.Do(func() {
		clear(w.args.Request.Password)
		w.args = PostActionArgs{}
		w.runtime = PostActionRuntime{}
	})
}

// acceptAuthPostAction uses the currently registered generation or the Lua-only fallback.
func acceptAuthPostAction(
	ctx *gin.Context,
	view *StateView,
	ordinal uint32,
	work effectsupervisor.ExecutableWork,
) (effectsupervisor.Receipt, error) {
	supervisor := getPostActionSupervisor()
	if supervisor == nil {
		supervisor = fallbackPostActionSupervisor()
	}

	return supervisor.Accept(ctx, view, ordinal, work)
}

// fallbackPostActionSupervisor owns Lua-only deployments without a native plugin runner.
func fallbackPostActionSupervisor() *PostActionSupervisor {
	defaultPostActionSupervisorOnce.Do(func() {
		defaultPostActionSupervisor = NewPostActionSupervisor(svcctx.Get())
	})

	return defaultPostActionSupervisor
}

// postActionDeadlineBudget captures a bounded total budget from request configuration.
func postActionDeadlineBudget(auth *AuthState) time.Duration {
	if auth == nil || auth.Cfg() == nil || auth.Cfg().GetServer() == nil {
		return authPostActionBudget
	}

	budget := auth.Cfg().GetServer().GetTimeouts().GetLuaScript()
	if budget < time.Millisecond || budget > 10*time.Minute {
		return authPostActionBudget
	}

	return budget
}
