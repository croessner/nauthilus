package pluginruntime

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/pluginregistry"
	"github.com/croessner/nauthilus/server/policy/report"

	"github.com/gin-gonic/gin"
)

var _ core.PluginEffectBridge = (*EffectBridge)(nil)

// EffectBridge adapts policy-selected native plugin effects into core.
type EffectBridge struct {
	runner *Runner
}

// NewEffectBridge returns an effect bridge bound to one plugin runner.
func NewEffectBridge(runner *Runner) *EffectBridge {
	return &EffectBridge{runner: runner}
}

// ExecutePolicyEffect dispatches one policy-selected native plugin effect.
func (b *EffectBridge) ExecutePolicyEffect(ctx *gin.Context, view *core.StateView, effect report.EffectRequest) (bool, bool) {
	auth := authFromView(view)
	if b == nil || b.runner == nil || auth == nil || effect.ID == "" {
		return false, false
	}

	component, ok := b.runner.registry.Lookup(effect.ID)
	if !ok {
		return false, false
	}

	switch component.Kind {
	case pluginregistry.ComponentKindObligationTarget:
		return true, b.executeObligation(ctx, auth, effect)
	case pluginregistry.ComponentKindPostActionTarget:
		return true, b.enqueuePostAction(ctx, auth, effect)
	default:
		return false, false
	}
}

func (b *EffectBridge) executeObligation(ctx *gin.Context, auth *core.AuthState, effect report.EffectRequest) bool {
	request, err := newPluginEffectRequest(auth, effect.Args)
	if err != nil {
		return false
	}

	result, err := b.runner.ExecuteObligation(contextFromGin(ctx), effect.ID, pluginapi.ObligationRequest{
		Snapshot: request.snapshot,
		Runtime:  request.runtime,
		Args:     request.args,
	})
	if err != nil {
		return false
	}

	applyPluginStatus(auth, result.Status)
	applySubjectLogs(auth, result.Logs)
	applyEffectRuntimeDelta(auth, result.RuntimeDelta)

	return result.Applied || !result.Temporary
}

func (b *EffectBridge) enqueuePostAction(ctx *gin.Context, auth *core.AuthState, effect report.EffectRequest) bool {
	if b.runner.host == nil {
		return false
	}

	b.runner.host.Go(contextFromGin(ctx), effect.ID, func(workerCtx context.Context) error {
		request, err := newPluginEffectRequest(auth, effect.Args)
		if err != nil {
			return err
		}

		_, err = b.runner.EnqueuePostAction(workerCtx, effect.ID, pluginapi.PostActionRequest{
			Snapshot: request.snapshot,
			Runtime:  request.runtime,
			Args:     request.args,
		})

		return err
	})

	return true
}

type pluginEffectRequest struct {
	runtime  pluginapi.RuntimeContext
	args     pluginapi.ArgsView
	snapshot pluginapi.RequestSnapshot
}

func newPluginEffectRequest(auth *core.AuthState, args map[string]any) (pluginEffectRequest, error) {
	runtimeContext, err := NewRuntimeContext(runtimeSnapshot(auth))
	if err != nil {
		return pluginEffectRequest{}, err
	}

	return pluginEffectRequest{
		snapshot: NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg())),
		runtime:  runtimeContext,
		args:     pluginregistry.NewArgsView(args),
	}, nil
}

func applyEffectRuntimeDelta(auth *core.AuthState, delta pluginapi.RuntimeDelta) {
	if auth == nil {
		return
	}

	if err := ValidateRuntimeDelta(delta); err != nil {
		return
	}

	if auth.Runtime.Context == nil {
		return
	}

	for _, key := range delta.Delete {
		auth.Runtime.Context.Delete(key)
	}

	for key, value := range delta.Set {
		auth.Runtime.Context.Set(key, value)
	}
}
