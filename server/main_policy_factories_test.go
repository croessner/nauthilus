// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/app/bootfx"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/app/policyfx"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"

	redismock "github.com/go-redis/redismock/v9"
)

const policyFactoryTestIssuer = "https://issuer.example.test"

type policyFactoryTestFixture struct {
	httpCert string
	httpKey  string
	grpcCert string
	grpcKey  string
	clientCA string
}

type policyFactoryNoopThrottler struct{}

// BeforeAttempt permits one test-only Policy-Basic attempt without external state.
func (policyFactoryNoopThrottler) BeforeAttempt(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordFailure accepts one test-only Policy-Basic failure without external state.
func (policyFactoryNoopThrottler) RecordFailure(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordSuccess accepts one test-only Policy-Basic success without external state.
func (policyFactoryNoopThrottler) RecordSuccess(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

func TestProductionPolicyFactoriesBuildRealCandidateDependencies(t *testing.T) {
	fixture := newPolicyFactoryTestFixture(t)
	cfg := policyFactoryTestConfig(fixture)
	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tokenFactory, err := newPolicyAccessTokenValidatorFactory(
		&bootstrapped{file: cfg},
		&config.EnvironmentSettings{},
		logger,
		redisClient,
		accountcache.NewManager(cfg),
		backend.NewChannel(cfg),
	)
	if err != nil {
		t.Fatalf("newPolicyAccessTokenValidatorFactory() error = %v", err)
	}

	tokenValidator, err := tokenFactory(t.Context(), cfg)
	if err != nil || tokenValidator == nil {
		t.Fatalf("access-token factory = %T, %v", tokenValidator, err)
	}

	changedIssuer := policyFactoryTestConfig(fixture)

	changedIssuer.IDP.OIDC.Issuer = "https://changed-issuer.example.test"
	if _, err = tokenFactory(t.Context(), changedIssuer); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("changed token issuer error = %v, want restart required", err)
	}

	changedSigningKey := policyFactoryTestConfig(fixture)

	changedSigningKey.IDP.OIDC.SigningKeys[0].Key = secret.New("changed-signing-secret")
	if _, err = tokenFactory(t.Context(), changedSigningKey); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("changed signing key error = %v, want restart required", err)
	}

	changedRedisSecret := policyFactoryTestConfig(fixture)

	changedRedisSecret.Server.Redis.EncryptionSecret = secret.New("changed-redis-encryption-secret")
	if _, err = tokenFactory(t.Context(), changedRedisSecret); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("changed Redis secret error = %v, want restart required", err)
	}

	throttlerFactory := newPolicyBasicThrottlerFactory(redisClient)

	throttler, err := throttlerFactory(t.Context(), cfg)
	if err != nil || throttler == nil {
		t.Fatalf("Basic throttler factory = %T, %v", throttler, err)
	}
}

func TestPolicyTransportFactoryProjectsOnlyLiveProtectedEnabledRoutes(t *testing.T) {
	fixture := newPolicyFactoryTestFixture(t)
	baseline := policyFactoryTestConfig(fixture)

	factory, err := newPolicyTransportCapabilitiesFactory(&bootstrapped{file: baseline})
	if err != nil {
		t.Fatalf("newPolicyTransportCapabilitiesFactory() error = %v", err)
	}

	capabilities, err := factory(t.Context(), baseline)
	if err != nil {
		t.Fatalf("transport factory error = %v", err)
	}

	if !capabilities.HTTPProtected || !capabilities.GRPCProtected || !capabilities.GRPCVerifiedClientCertificate {
		t.Fatalf("transport capabilities = %#v, want protected HTTP and verified-client-certificate gRPC", capabilities)
	}

	disabled := policyFactoryTestConfig(fixture)
	disabled.Policy.API.Enabled = false

	capabilities, err = factory(t.Context(), disabled)
	if err != nil {
		t.Fatalf("disabled transport factory error = %v", err)
	}

	if capabilities != (callerauth.TransportCapabilities{}) {
		t.Fatalf("disabled transport capabilities = %#v, want none", capabilities)
	}
}

func TestPolicyTransportFactoryDoesNotClaimUnverifiedClientCertificateEvidence(t *testing.T) {
	baseline := policyFactoryTestConfig(newPolicyFactoryTestFixture(t))
	baseline.Policy.API.GRPC.RequireMTLS = false
	baseline.Runtime.Servers.GRPC.Authority.TLS.ClientCA = ""
	baseline.Runtime.Servers.GRPC.Authority.TLS.RequireClientCert = false

	factory, err := newPolicyTransportCapabilitiesFactory(&bootstrapped{file: baseline})
	if err != nil {
		t.Fatalf("newPolicyTransportCapabilitiesFactory() error = %v", err)
	}

	capabilities, err := factory(t.Context(), baseline)
	if err != nil {
		t.Fatalf("transport factory error = %v", err)
	}

	if !capabilities.GRPCProtected || capabilities.GRPCVerifiedClientCertificate {
		t.Fatalf("transport capabilities = %#v, want protected gRPC without verified client-certificate evidence", capabilities)
	}
}

func TestPolicyTransportFactoryRejectsUnsatisfiedAndChangedBootBaseline(t *testing.T) {
	fixture := newPolicyFactoryTestFixture(t)
	baseline := policyFactoryTestConfig(fixture)

	factory, err := newPolicyTransportCapabilitiesFactory(&bootstrapped{file: baseline})
	if err != nil {
		t.Fatalf("newPolicyTransportCapabilitiesFactory() error = %v", err)
	}

	tests := []struct {
		mutate func(*config.FileSettings)
		name   string
	}{
		{
			name: "HTTP TLS",
			mutate: func(candidate *config.FileSettings) {
				candidate.Server.TLS.Enabled = false
			},
		},
		{
			name: "trusted proxies",
			mutate: func(candidate *config.FileSettings) {
				candidate.Server.TrustedProxies = []string{"192.0.2.0/24"}
			},
		},
		{
			name: "gRPC listener",
			mutate: func(candidate *config.FileSettings) {
				candidate.Runtime.Servers.GRPC.Authority.Address = "127.0.0.1:9555"
			},
		},
		{
			name: "gRPC TLS",
			mutate: func(candidate *config.FileSettings) {
				candidate.Runtime.Servers.GRPC.Authority.TLS.Cert = "/changed/cert.pem"
			},
		},
		{
			name: "gRPC client certificate requirement",
			mutate: func(candidate *config.FileSettings) {
				candidate.Runtime.Servers.GRPC.Authority.TLS.RequireClientCert = false
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := policyFactoryTestConfig(fixture)
			test.mutate(candidate)

			_, candidateErr := factory(t.Context(), candidate)
			if !errors.Is(candidateErr, pluginruntime.ErrRestartRequired) {
				t.Fatalf("transport mutation error = %v, want restart required", candidateErr)
			}
		})
	}

	assertPolicyTransportRejectsInsufficientMTLS(t, fixture)
}

// assertPolicyTransportRejectsInsufficientMTLS verifies listener evidence at factory activation.
func assertPolicyTransportRejectsInsufficientMTLS(t *testing.T, fixture policyFactoryTestFixture) {
	t.Helper()

	insufficient := policyFactoryTestConfig(fixture)
	insufficient.Policy.API.GRPC.RequireMTLS = true
	insufficient.Runtime.Servers.GRPC.Authority.TLS.RequireClientCert = false

	insufficientFactory, err := newPolicyTransportCapabilitiesFactory(&bootstrapped{file: insufficient})
	if err != nil {
		t.Fatalf("construct insufficient baseline factory: %v", err)
	}

	if _, err = insufficientFactory(t.Context(), insufficient); err == nil {
		t.Fatal("gRPC mTLS policy accepted a listener without required client certificates")
	}
}

func TestProductionCoordinatorRetainsGenerationOnTransportBaselineMutation(t *testing.T) {
	fixture := newPolicyFactoryTestFixture(t)
	baseline := policyFactoryTestConfig(fixture)

	transports, err := newPolicyTransportCapabilitiesFactory(&bootstrapped{file: baseline})
	if err != nil {
		t.Fatalf("newPolicyTransportCapabilitiesFactory() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()

	coordinator, err := newPolicyFactoryTestCoordinator(store, transports, baseline)
	if err != nil {
		t.Fatalf("new Policy coordinator: %v", err)
	}

	if err = coordinator.Apply(t.Context(), configSnapshot(baseline, 1)); err != nil {
		t.Fatalf("apply initial generation: %v", err)
	}

	active := store.Active()
	candidate := policyFactoryTestConfig(fixture)
	candidate.Server.TrustedProxies = []string{"192.0.2.0/24"}

	if err = coordinator.Apply(t.Context(), configSnapshot(candidate, 2)); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("apply transport-mutated candidate error = %v, want restart required", err)
	}

	if store.Active() != active {
		t.Fatal("transport-mutated candidate replaced the active generation")
	}
}

func TestProductionCoordinatorRetainsGenerationWhenHTTPOnlyClientRequiresMTLS(t *testing.T) {
	fixture := newPolicyFactoryTestFixture(t)
	baseline := policyFactoryTestConfig(fixture)

	transports, err := newPolicyTransportCapabilitiesFactory(&bootstrapped{file: baseline})
	if err != nil {
		t.Fatalf("newPolicyTransportCapabilitiesFactory() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()

	coordinator, err := newPolicyFactoryTestCoordinator(store, transports, baseline)
	if err != nil {
		t.Fatalf("new Policy coordinator: %v", err)
	}

	if err = coordinator.Apply(t.Context(), configSnapshot(baseline, 1)); err != nil {
		t.Fatalf("apply initial generation: %v", err)
	}

	active := store.Active()
	candidate := policyFactoryTestConfig(fixture)
	candidate.Policy.API.GRPC.Enabled = false
	candidate.Policy.API.GRPC.RequireMTLS = false
	candidate.Policy.API.Clients = []policyconfig.ClientProfileConfig{{
		Authentication: policyconfig.ClientAuthenticationConfig{Basic: &policyconfig.BasicAuthenticationConfig{
			Username: "http-only-mtls-client",
			Password: secret.New("http-only-mtls-secret"),
		}},
		Principal:           "http-only-mtls-client",
		AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
		Targets: []policyconfig.ClientTargetConfig{{
			Namespace: policy.AuthnNamespace,
			Actions:   []string{string(policy.OperationAuthenticate)},
		}},
		RequireMTLS: true,
	}}

	if err = coordinator.Apply(t.Context(), configSnapshot(candidate, 2)); !errors.Is(err, callerauth.ErrConfiguration) {
		t.Fatalf("apply HTTP-only mTLS client candidate error = %v, want caller-auth configuration error", err)
	}

	if store.Active() != active {
		t.Fatal("HTTP-only mTLS client candidate replaced the active generation")
	}
}

// newPolicyFactoryTestCoordinator builds a production coordinator without activating external credentials.
func newPolicyFactoryTestCoordinator(
	store *policyruntime.GenerationStore,
	transports policyfx.TransportCapabilitiesFactory,
	configured config.File,
) (*policyfx.Coordinator, error) {
	startup := policyfx.NewStartupCatalog()
	if err := startup.Capture(configured, bootfx.LuaInitCatalogPreparation{}); err != nil {
		return nil, err
	}

	restart, err := policyfx.NewRestartBaseline(configured)
	if err != nil {
		return nil, err
	}

	return policyfx.NewCoordinator(
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&pluginloader.State{},
		func(context.Context, config.File) (callerauth.AccessTokenValidator, error) {
			return nil, errors.New("unexpected bearer factory call")
		},
		func(context.Context, config.File) (callerauth.BasicThrottler, error) {
			return policyFactoryNoopThrottler{}, nil
		},
		transports,
		localization.NewMapCatalog(nil),
		startup,
		restart,
	)
}

// configSnapshot returns one focused immutable generation candidate.
func configSnapshot(file config.File, version uint64) configfx.Snapshot {
	return configfx.Snapshot{File: file, Version: version}
}

// newPolicyFactoryTestFixture creates exact listener trust files shared by one test's candidates.
func newPolicyFactoryTestFixture(t *testing.T) policyFactoryTestFixture {
	t.Helper()

	directory := t.TempDir()

	fixture := policyFactoryTestFixture{
		httpCert: filepath.Join(directory, "http-cert.pem"),
		httpKey:  filepath.Join(directory, "http-key.pem"),
		grpcCert: filepath.Join(directory, "grpc-cert.pem"),
		grpcKey:  filepath.Join(directory, "grpc-key.pem"),
		clientCA: filepath.Join(directory, "client-ca.pem"),
	}
	for path, content := range map[string]string{
		fixture.httpCert: "HTTP cert\n", fixture.httpKey: "HTTP key\n",
		fixture.grpcCert: "gRPC cert\n", fixture.grpcKey: "gRPC key\n",
		fixture.clientCA: "client CA\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write Policy factory TLS fixture %q: %v", path, err)
		}
	}

	return fixture
}

// policyFactoryTestConfig returns a detached protected HTTP/gRPC candidate.
func policyFactoryTestConfig(fixture policyFactoryTestFixture) *config.FileSettings {
	return &config.FileSettings{
		Runtime: &config.RuntimeSection{Servers: config.RuntimeServersSection{
			GRPC: config.RuntimeGRPCServersSection{Authority: config.RuntimeGRPCAuthServerSection{
				Address: "127.0.0.1:9444",
				Enabled: true,
				TLS: config.RuntimeGRPCTLSSection{
					Enabled: true, Cert: fixture.grpcCert, Key: fixture.grpcKey,
					ClientCA: fixture.clientCA, RequireClientCert: true,
				},
			}},
		}},
		Server: &config.ServerSection{
			TLS:            config.TLS{Enabled: true, Cert: fixture.httpCert, Key: fixture.httpKey},
			TrustedProxies: []string{"198.51.100.0/24"},
			Redis: config.Redis{
				PasswordNonce:    secret.New("policy-password-nonce"),
				EncryptionSecret: secret.New("policy-encryption-secret"),
			},
		},
		IDP: &config.IDPSection{OIDC: config.OIDCConfig{
			Enabled: true, Issuer: policyFactoryTestIssuer,
			SigningKeys: []config.OIDCKey{{ID: "policy", Key: secret.New("policy-signing-secret"), Active: true}},
		}},
		Policy: policyconfig.PolicyConfig{API: policyconfig.APIConfig{
			Enabled: true,
			HTTP:    policyconfig.HTTPConfig{Enabled: true},
			GRPC:    policyconfig.GRPCConfig{Enabled: true, RequireMTLS: true},
		}},
	}
}
