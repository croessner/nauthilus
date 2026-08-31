// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	pluginpassword "github.com/croessner/nauthilus/v4/pluginapi/v1/password"
	"github.com/croessner/nauthilus/v4/server/core"
)

// AuthnRequestRuntime projects public request values without selecting plugin components.
type AuthnRequestRuntime struct{}

// NewAuthnRequestRuntime returns the stateless explicit request projection boundary.
func NewAuthnRequestRuntime() *AuthnRequestRuntime {
	return &AuthnRequestRuntime{}
}

// Capture freezes request-owned values for one already selected generation binding.
func (*AuthnRequestRuntime) Capture(
	ctx context.Context,
	input core.AuthnNativeCaptureInput,
) (core.AuthnNativeCapture, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	auth := input.Auth
	if auth == nil {
		return core.AuthnNativeCapture{}, core.ErrAuthOutcomeMissing
	}

	runtimeValues := map[string]any{}
	if auth.Runtime.Context != nil {
		runtimeValues = auth.Runtime.Context.Snapshot()
	}

	runtimeContext, err := NewRuntimeContext(runtimeValues)
	if err != nil {
		return core.AuthnNativeCapture{}, err
	}

	requestContext := ctx
	if input.Detached {
		requestContext = context.WithoutCancel(ctx)
	}

	capture := core.AuthnNativeCapture{
		Runtime: runtimeContext,
		Credentials: NewCredentialProvider(
			requestContext,
			auth.GetPassword(),
			input.Capabilities,
		),
		Snapshot: NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg())),
	}
	if input.Detached {
		capture.PasswordHash = authnPostActionPasswordHash(auth)
	}

	return capture, nil
}

// ApplyRuntimeDelta validates and applies one public result to request-local state only.
func (*AuthnRequestRuntime) ApplyRuntimeDelta(auth *core.AuthState, delta pluginapi.RuntimeDelta) error {
	if err := ValidateRuntimeDelta(delta); err != nil {
		return err
	}

	if auth == nil || auth.Runtime.Context == nil {
		if len(delta.Set)+len(delta.Delete) == 0 {
			return nil
		}

		return core.ErrAuthOutcomeMissing
	}

	for _, key := range delta.Delete {
		auth.Runtime.Context.Delete(key)
	}

	for key, value := range delta.Set {
		auth.Runtime.Context.Set(key, value)
	}

	return nil
}

// authnPostActionPasswordHash derives the detached public hash from captured request configuration.
func authnPostActionPasswordHash(auth *core.AuthState) string {
	if auth == nil || auth.GetPassword().IsZero() {
		return ""
	}

	var passwordHash string

	auth.GetPassword().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		options := authnPostActionPasswordHashOptions(auth)
		defer clear(options.Nonce)

		passwordHash = pluginpassword.GenerateHashBytes(value, options)
	})

	return passwordHash
}

// authnPostActionPasswordHashOptions snapshots host-owned nonce and development-mode inputs.
func authnPostActionPasswordHashOptions(auth *core.AuthState) pluginpassword.HashOptions {
	options := pluginpassword.HashOptions{}
	if auth == nil {
		return options
	}

	if auth.Env() != nil {
		options.DevMode = auth.Env().GetDevMode()
	}

	cfg := auth.Cfg()
	if cfg == nil || cfg.GetServer() == nil || cfg.GetServer().GetRedis() == nil {
		return options
	}

	cfg.GetServer().GetRedis().GetPasswordNonce().WithBytes(func(value []byte) {
		options.Nonce = append([]byte(nil), value...)
	})

	return options
}

var _ core.AuthnNativeRuntime = (*AuthnRequestRuntime)(nil)
