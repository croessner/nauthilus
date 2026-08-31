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

	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

type authnPolicyEffectOwnerContextKey struct{}

type authnPolicyEffectOwner interface {
	executeAuthnPolicyEffect(report.EffectRequest) effectsupervisor.Result
}

type authnPolicySyncEffectProvider struct{}

// AuthnStandardEffectBindings creates detached generation bindings from the immutable registry mapping.
func AuthnStandardEffectBindings() (
	map[string]policyruntime.SyncEffectProvider,
	map[string]policyruntime.PostActionProvider,
) {
	syncEffects := make(map[string]policyruntime.SyncEffectProvider)
	postActions := make(map[string]policyruntime.PostActionProvider)

	for _, binding := range registry.BuiltinAuthEffectBindings() {
		switch binding.Execution {
		case registry.ExecutionHostSync:
			syncEffects[binding.Provider] = authnPolicySyncEffectProvider{}
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

// contextWithAuthnLuaActionOwner binds exact configured actions beside the builtin host owner.
func contextWithAuthnLuaActionOwner(ctx context.Context, owner policyruntime.AuthnLuaActionHost) context.Context {
	return policyruntime.ContextWithAuthnLuaActionHost(ctx, owner)
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

// authnPolicyEffectRequest projects strict captured parameters without translating the canonical effect identity.
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

	return report.EffectRequest{ID: execution.EffectID(), Args: args}, nil
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

var _ policyruntime.SyncEffectProvider = authnPolicySyncEffectProvider{}
