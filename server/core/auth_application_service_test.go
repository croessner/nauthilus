// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestAuthApplicationHostMapsTransportNeutralControls(t *testing.T) {
	tests := []struct {
		name  string
		input AuthInput
		want  string
	}{
		{name: "authenticate", input: AuthInput{Mode: AuthModeAuthenticate}, want: "/grpc/auth/v1/Authenticate"},
		{name: "lookup", input: AuthInput{Mode: AuthModeLookupIdentity}, want: "/grpc/auth/v1/LookupIdentity?mode=no-auth"},
		{
			name: "list HTTP route and cache controls",
			input: AuthInput{
				Mode:               AuthModeListAccounts,
				DisableMemoryCache: true,
				DisableCache:       true,
				Context: AuthContext{Transport: AuthTransportContext{
					HTTPRoute: "/api/v1/auth/json",
				}},
			},
			want: "/api/v1/auth/json?cache=0&in-memory=0&mode=list-accounts",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := authApplicationPath(test.input); got != test.want {
				t.Fatalf("application path = %q, want %q", got, test.want)
			}
		})
	}
}

func TestValidateLookupIdentityInputPreservesHTTPAndGRPCContracts(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		username string
		wantErr  bool
	}{
		{name: "HTTP empty username reaches admitted host", service: definitions.ServJSON},
		{name: "HTTP invalid username reaches admitted host", service: definitions.ServCBOR, username: "invalid username"},
		{name: "gRPC empty username is rejected", service: definitions.ServGRPC, wantErr: true},
		{name: "gRPC invalid username is rejected", service: definitions.ServGRPC, username: "invalid username", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := AuthInput{
				Credentials: NewCredentials(WithUsername(test.username)),
				Mode:        AuthModeLookupIdentity,
				Service:     test.service,
			}
			err := validateLookupIdentityInput(input)

			if (err != nil) != test.wantErr {
				t.Fatalf("validateLookupIdentityInput() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestAuthApplicationServiceKeepsImmutableConstructorConfig(t *testing.T) {
	db, _ := redismock.NewClientMock()
	startup := &config.FileSettings{}
	service := &authApplicationService{deps: AuthDeps{
		Cfg:   startup,
		Env:   config.NewTestEnvironmentConfig(),
		Redis: rediscli.NewTestClient(db),
	}}

	deps, err := service.effectiveDeps(context.Background())
	if err != nil {
		t.Fatalf("effectiveDeps() error = %v", err)
	}

	if deps.Cfg != startup {
		t.Fatalf("effectiveDeps().Cfg = %p, want immutable constructor snapshot %p", deps.Cfg, startup)
	}
}

// setupPhase4AuthApplicationServiceTest returns explicit request-owner dependencies for host tests.
func setupPhase4AuthApplicationServiceTest(t *testing.T, backendName string) (AuthDeps, redismock.ClientMock) {
	t.Helper()

	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	var backend config.Backend
	if err := backend.Set(backendName); err != nil {
		t.Fatalf("backend.Set(%q) failed: %v", backendName, err)
	}

	cfg, ok := config.GetFile().(*config.FileSettings)
	if !ok {
		t.Fatalf("unexpected config type %T", config.GetFile())
	}

	cfg.Server.Backends = []*config.Backend{&backend}
	db, mock := redismock.NewClientMock()
	deps := setupAuthDeps()
	deps.Cfg = cfg
	deps.Redis = rediscli.NewTestClient(db)
	deps.AccountCache = accountcache.NewManager(cfg)
	deps.HostServices = newTestAuthnHostServices(t, testPasswordVerifier{}, testLuaSubject{})

	return deps, mock
}

// newTestAuthnHostServices freezes complete explicit host dependencies for candidate tests.
func newTestAuthnHostServices(
	t *testing.T,
	verifier PasswordVerifier,
	subject CapturedLuaSubject,
) AuthnHostServices {
	t.Helper()

	services, err := NewAuthnHostServices(AuthnHostServicesInput{
		PasswordVerifier: verifier,
		Cache:            testAuthnCacheService{},
		BruteForce:       testAuthnBruteForceService{},
		Subject:          subject,
		RBL:              testAuthnRBLService{},
	})
	if err != nil {
		t.Fatalf("NewAuthnHostServices() error = %v", err)
	}

	return services
}

type testPasswordVerifier struct{}

func (testPasswordVerifier) Verify(
	ctx *gin.Context,
	auth *AuthState,
	passDBs []*PassDBMap,
) (*PassDBResult, error) {
	return VerifyPasswordPipeline(ctx, auth, passDBs)
}

type failingPasswordVerifier struct{}

func (failingPasswordVerifier) Verify(
	_ *gin.Context,
	auth *AuthState,
	_ []*PassDBMap,
) (*PassDBResult, error) {
	result := GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = false
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendTest
	result.Attributes = map[string][]any{
		"uid": {auth.Request.Username},
	}

	return result, nil
}

type testLuaSubject struct{}

func (testLuaSubject) AnalyzeSource(
	_ *gin.Context,
	view *StateView,
	result *PassDBResult,
	_ string,
	_ *lua.FunctionProto,
	_ *vmpool.Manager,
	_ vmpool.PoolKey,
	_ *luaseal.Modules,
) definitions.AuthResult {
	if result != nil && result.Authenticated {
		view.Auth().Runtime.Authorized = true

		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

type testAuthnCacheService struct{}

func (testAuthnCacheService) OnSuccess(*AuthState, string) error { return nil }
func (testAuthnCacheService) OnFailure(*AuthState, string)       {}
func (testAuthnCacheService) Purge(*AuthState, string)           {}

type testAuthnBruteForceService struct{}

func (testAuthnBruteForceService) WaitDelay(uint, uint) int { return 0 }
func (testAuthnBruteForceService) LoadHistories(*gin.Context, *AuthState, string) {
}

type testAuthnRBLService struct{}

func (testAuthnRBLService) Score(*gin.Context, *StateView) (int, error) { return 0, nil }
