// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

// idpSetupFailureRuntime enables the frontend and OIDC without Redis, so the canonical browser runtime cannot be
// built. The same path is taken when the frontend encryption secret is too short for the envelope codec.
func idpSetupFailureRuntime() httpServerRuntime {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{Frontend: config.Frontend{Enabled: true}},
		IDP:    &config.IDPSection{OIDC: config.OIDCConfig{Enabled: true}},
	}

	return httpServerRuntime{
		store:  &contextStore{pluginRunner: &pluginruntime.Runner{}},
		cfg:    cfg,
		env:    config.NewTestEnvironmentConfig(),
		logger: slog.Default(),
	}
}

func TestBuildHTTPSetupCallbacksFailsWhenIDPCannotBeBuilt(t *testing.T) {
	_, err := buildHTTPSetupCallbacks(idpSetupFailureRuntime(), httpServerStartOptions{})
	if err == nil {
		t.Fatal("buildHTTPSetupCallbacks() error = nil, want the IDP initialization failure")
	}

	if !strings.Contains(err.Error(), "canonical IDP browser runtime initialization failed") {
		t.Fatalf("buildHTTPSetupCallbacks() error = %q, want the browser runtime failure", err)
	}
}

func TestBuildHTTPSetupCallbacksKeepsRestartServingWithoutIDP(t *testing.T) {
	callbacks, err := buildHTTPSetupCallbacks(idpSetupFailureRuntime(), httpServerStartOptions{
		continueHTTPOnIDPSetupError: true,
	})
	if err != nil {
		t.Fatalf("buildHTTPSetupCallbacks() error = %v, want nil on the restart path", err)
	}

	if callbacks.idp != nil {
		t.Fatal("IDP routes were registered although the IDP could not be built")
	}

	if callbacks.health == nil || callbacks.metrics == nil || callbacks.backchannel == nil {
		t.Fatal("restart path dropped the routes that do not depend on the IDP")
	}
}

func TestBuildIDPSetupCallbackSkipsDisabledFrontend(t *testing.T) {
	runtime := idpSetupFailureRuntime()
	runtime.cfg = &config.FileSettings{Server: &config.ServerSection{}}

	callback, err := buildIDPSetupCallback(runtime)
	if err != nil || callback != nil {
		t.Fatalf("buildIDPSetupCallback() = (%v, %v), want no routes and no error", callback != nil, err)
	}
}
