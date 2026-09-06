// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/secret"
)

func TestAuthnRequestRuntimeDetachedCaptureIsBoundedIndependentlyOfRequestContext(t *testing.T) {
	requestContext := context.Background()
	for index := range 32 {
		requestContext = context.WithValue(requestContext, detachedCaptureContextKey(index), index)
	}

	auth := &core.AuthState{}
	auth.Request.Username = "detached-user"
	auth.Request.Password = secret.New("detached-password")

	capture, err := NewAuthnRequestRuntime().Capture(requestContext, core.AuthnNativeCaptureInput{
		Auth: auth, Capabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials}, Detached: true,
	})
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}

	request := pluginapi.PostActionRequest{
		Snapshot: capture.Snapshot, Runtime: capture.Runtime, Credentials: capture.Credentials,
		PasswordHash: capture.PasswordHash, Args: pluginregistry.NewArgsView(nil),
	}
	if err = effectsupervisor.ValidateBoundedValue(request, effectsupervisor.DefaultWorkBounds()); err != nil {
		t.Fatalf("detached post-action capture bounds error = %v", err)
	}
}

type detachedCaptureContextKey int

func TestAuthnRequestRuntimeDetachedPasswordMaterialRequiresCapability(t *testing.T) {
	for _, test := range []struct {
		name            string
		capabilities    []pluginapi.Capability
		wantHash        bool
		wantCredentials bool
	}{
		{name: "reputation without credentials"},
		{name: "hash only", capabilities: []pluginapi.Capability{pluginapi.CapabilityPasswordHash}, wantHash: true},
		{name: "credentials only", capabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials}, wantCredentials: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := &core.AuthState{}
			auth.Request.Password = secret.New("learning-boundary-password")

			capture, err := NewAuthnRequestRuntime().Capture(context.Background(), core.AuthnNativeCaptureInput{
				Auth: auth, Capabilities: test.capabilities, Detached: true,
			})
			if err != nil {
				t.Fatal(err)
			}

			if (capture.PasswordHash != "") != test.wantHash {
				t.Errorf("password hash presence = %v, want %v", capture.PasswordHash != "", test.wantHash)
			}

			if _, available := capture.Credentials.Password(context.Background()); available != test.wantCredentials {
				t.Errorf("credential access = %v, want %v", available, test.wantCredentials)
			}
		})
	}
}
