// Copyright (C) 2026 Christian Rößner
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
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type authnPolicyEffectOwnerContextKey struct{}

type authnPolicyEffectOwner interface {
	executeAuthnPolicyEffect(report.EffectRequest) effectsupervisor.Result
	prepareAuthnPostAction(report.EffectRequest, uint32) (effectsupervisor.ExecutableWork, error)
}

type authnPolicySyncEffectProvider struct{}

type authnPolicyPostActionProvider struct{}

// authnStandardEffectBindingMaps creates generation bindings from the immutable registry mapping.
func authnStandardEffectBindingMaps() (
	map[string]policyruntime.SyncEffectProvider,
	map[string]policyruntime.PostActionProvider,
) {
	syncEffects := make(map[string]policyruntime.SyncEffectProvider)
	postActions := make(map[string]policyruntime.PostActionProvider)

	for _, binding := range registry.BuiltinAuthEffectBindings() {
		switch binding.Execution {
		case registry.ExecutionHostSync:
			syncEffects[binding.Provider] = authnPolicySyncEffectProvider{}
		case registry.ExecutionHostPostAction:
			postActions[binding.Provider] = authnPolicyPostActionProvider{}
		}
	}

	return syncEffects, postActions
}

// contextWithAuthnPolicyEffectOwner attaches one request-local standard-auth effect owner.
func contextWithAuthnPolicyEffectOwner(ctx context.Context, owner authnPolicyEffectOwner) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if owner == nil {
		return ctx
	}

	return context.WithValue(ctx, authnPolicyEffectOwnerContextKey{}, owner)
}

// authnPolicyEffectOwnerFromContext resolves the admitted request-local owner.
func authnPolicyEffectOwnerFromContext(ctx context.Context) authnPolicyEffectOwner {
	if ctx == nil {
		return nil
	}

	owner, _ := ctx.Value(authnPolicyEffectOwnerContextKey{}).(authnPolicyEffectOwner)

	return owner
}

// Execute dispatches one standard-auth synchronous selection to the request-local owner.
func (authnPolicySyncEffectProvider) Execute(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	owner := authnPolicyEffectOwnerFromContext(ctx)

	request, err := authnPolicyEffectRequest(execution)
	if owner == nil || err != nil {
		return effectsupervisor.Failed("authn_effect_owner_unavailable")
	}

	return owner.executeAuthnPolicyEffect(request)
}

// Prepare captures one standard-auth post-action for generic supervisor ownership.
func (authnPolicyPostActionProvider) Prepare(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	owner := authnPolicyEffectOwnerFromContext(ctx)

	request, err := authnPolicyEffectRequest(execution)
	if err != nil {
		return nil, err
	}

	if owner == nil {
		return nil, fmt.Errorf("authn post-action owner is unavailable")
	}

	return owner.prepareAuthnPostAction(request, execution.Ordinal())
}

// authnPolicyEffectRequest restores the established request over strict captured parameters.
func authnPolicyEffectRequest(execution policyruntime.EffectExecution) (report.EffectRequest, error) {
	binding, ok := registry.BuiltinAuthEffectBindingForEffect(execution.EffectID())
	if !ok || binding.Provider != execution.Provider() {
		return report.EffectRequest{}, fmt.Errorf("authn effect binding %q is invalid", execution.EffectID())
	}

	args := make(map[string]any, execution.Parameters().Len())
	for key, value := range execution.Parameters().Values() {
		projected, valid := value.Any()
		if !valid {
			return report.EffectRequest{}, fmt.Errorf("authn effect parameter %q is invalid", key)
		}

		args[key] = projected
	}

	return report.EffectRequest{ID: binding.Selection, Args: args}, nil
}

// executeAuthnPolicyEffect routes one synchronous effect through the existing executor seam.
func (e *authnCandidateExecution) executeAuthnPolicyEffect(request report.EffectRequest) effectsupervisor.Result {
	if e == nil || e.auth == nil || e.ginCtx == nil {
		return effectsupervisor.Failed("authn_effect_owner_unavailable")
	}

	if e.executeEffect != nil {
		return e.executeEffect(request)
	}

	if newPolicyObligationExecutor(e.auth).executeOne(e.ginCtx, request) {
		return effectsupervisor.Succeeded()
	}

	return effectsupervisor.Failed("authn_effect_failed")
}

// prepareAuthnPostAction captures one existing Lua or native step without accepting it twice.
func (e *authnCandidateExecution) prepareAuthnPostAction(
	request report.EffectRequest,
	ordinal uint32,
) (effectsupervisor.ExecutableWork, error) {
	if e == nil || e.auth == nil || e.ginCtx == nil {
		return nil, fmt.Errorf("authn post-action owner is unavailable")
	}

	if e.preparePost != nil {
		return e.preparePost(request, ordinal)
	}

	return newPolicyObligationExecutor(e.auth).preparePostActionWork(e.ginCtx, request, ordinal)
}

var (
	_ policyruntime.SyncEffectProvider = authnPolicySyncEffectProvider{}
	_ policyruntime.PostActionProvider = authnPolicyPostActionProvider{}
)
