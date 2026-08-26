// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package runtime owns immutable Policy generations and their request-local bindings.
package runtime

import (
	"context"

	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

type authnLuaActionHostContextKey struct{}

type authnNativeEffectHostContextKey struct{}

// AuthnLuaActionProgram is one immutable generation-owned configured action.
type AuthnLuaActionProgram interface {
	ID() string
}

// AuthnLuaActionHost owns request-local execution and post-action capture for configured programs.
type AuthnLuaActionHost interface {
	ExecuteAuthnLuaAction(context.Context, AuthnLuaActionProgram, EffectExecution) effectsupervisor.Result
	PrepareAuthnLuaPostAction(
		context.Context,
		AuthnLuaActionProgram,
		EffectExecution,
	) (effectsupervisor.Work, error)
}

// ContextWithAuthnLuaActionHost binds one admitted request-local action owner.
func ContextWithAuthnLuaActionHost(ctx context.Context, host AuthnLuaActionHost) context.Context {
	return contextWithHost(ctx, authnLuaActionHostContextKey{}, host)
}

// AuthnLuaActionHostFromContext resolves the request-local owner under a captured Decision Session.
func AuthnLuaActionHostFromContext(ctx context.Context) (AuthnLuaActionHost, bool) {
	return hostFromContext[AuthnLuaActionHost](ctx, authnLuaActionHostContextKey{})
}

// AuthnNativeEffectProgram is one immutable generation-owned public auth extension target.
type AuthnNativeEffectProgram interface {
	ID() string
}

// AuthnNativeEffectHost owns request-local native obligation execution and post-action capture.
type AuthnNativeEffectHost interface {
	ExecuteAuthnNativeObligation(
		context.Context,
		AuthnNativeEffectProgram,
		EffectExecution,
	) effectsupervisor.Result
	PrepareAuthnNativePostAction(
		context.Context,
		AuthnNativeEffectProgram,
		EffectExecution,
	) (effectsupervisor.Work, error)
}

// ContextWithAuthnNativeEffectHost binds one admitted request-local native effect owner.
func ContextWithAuthnNativeEffectHost(ctx context.Context, host AuthnNativeEffectHost) context.Context {
	return contextWithHost(ctx, authnNativeEffectHostContextKey{}, host)
}

// AuthnNativeEffectHostFromContext resolves the request-local owner under a captured Decision Session.
func AuthnNativeEffectHostFromContext(ctx context.Context) (AuthnNativeEffectHost, bool) {
	return hostFromContext[AuthnNativeEffectHost](ctx, authnNativeEffectHostContextKey{})
}
