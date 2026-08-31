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

package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	coreauth "github.com/croessner/nauthilus/v4/server/core/auth"
	handlerauthority "github.com/croessner/nauthilus/v4/server/handler/grpcauthority"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

func TestStartGRPCAuthorityForHTTPFailsInitialStartup(t *testing.T) {
	startErr := errors.New("bind failed")
	store := &contextStore{}
	runtime := httpServerRuntime{store: store, logger: slog.Default()}

	err := startGRPCAuthorityForHTTP(context.Background(), runtime, httpServerStartOptions{
		grpcAuthorityStarter: failingGRPCAuthorityStarter(startErr),
	})
	if !errors.Is(err, startErr) {
		t.Fatalf("error = %v, want %v", err, startErr)
	}
}

func TestStartGRPCAuthorityForHTTPAllowsRestartFallback(t *testing.T) {
	startErr := errors.New("bind failed")
	store := &contextStore{
		grpcAuthorityDone: closedDoneChannel(),
	}
	runtime := httpServerRuntime{store: store, logger: slog.Default()}

	err := startGRPCAuthorityForHTTP(context.Background(), runtime, httpServerStartOptions{
		continueHTTPOnGRPCAuthorityError: true,
		grpcAuthorityStarter:             failingGRPCAuthorityStarter(startErr),
	})
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}

	if store.grpcAuthorityDone != nil {
		t.Fatal("grpcAuthorityDone was not cleared after tolerated gRPC start failure")
	}
}

func TestStartGRPCAuthorityForHTTPInjectsSharedRuntimeAuthorities(t *testing.T) {
	generationStore := policyruntime.NewGenerationStore()

	source, err := decisionservice.NewStoreGenerationSource(generationStore)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	policyDecision, err := decisionservice.NewDecisionService(source)
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	authApplication, err := core.NewProductionAuthApplicationService(core.AuthDeps{
		Cfg: &config.FileSettings{Server: &config.ServerSection{}},
		Env: config.NewTestEnvironmentConfig(), Logger: slog.Default(),
		HostServices: coreauth.NewDefaultHostServices(),
	}, policyDecision)
	if err != nil {
		t.Fatalf("NewProductionAuthApplicationService() error = %v", err)
	}

	routeArtifacts := &core.RouteArtifacts{}
	runtime := httpServerRuntime{
		store: &contextStore{pluginRunner: &pluginruntime.Runner{}}, logger: slog.Default(),
		policyDecision: policyDecision, authApplication: authApplication, routeArtifacts: routeArtifacts,
	}

	var captured handlerauthority.ServerDeps

	err = startGRPCAuthorityForHTTP(context.Background(), runtime, httpServerStartOptions{
		grpcAuthorityStarter: func(_ context.Context, deps handlerauthority.ServerDeps) (<-chan struct{}, error) {
			captured = deps

			return closedDoneChannel(), nil
		},
	})
	if err != nil {
		t.Fatalf("startGRPCAuthorityForHTTP() error = %v", err)
	}

	if captured.AuthService != authApplication || captured.PolicyService != policyDecision {
		t.Fatal("gRPC authority did not receive the runtime-owned auth and Policy authorities")
	}

	if captured.PluginBackendFactory == nil {
		t.Fatal("gRPC authority did not receive the runner-bound plugin backend factory")
	}

	if captured.RouteArtifacts != routeArtifacts {
		t.Fatal("gRPC authority did not receive the pre-commit route artifacts")
	}
}

func failingGRPCAuthorityStarter(err error) grpcAuthorityStarter {
	return func(context.Context, handlerauthority.ServerDeps) (<-chan struct{}, error) {
		return nil, err
	}
}

func closedDoneChannel() <-chan struct{} {
	done := make(chan struct{})
	close(done)

	return done
}
