// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"bytes"
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/secret"
)

func TestPolicyCallerAuthProjectionCapturesBasicAndBearerProfiles(t *testing.T) {
	const password = "dedicated-policy-basic-secret"

	document := policyCallerAuthProjectionDocument(password)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	configuration := input.CallerAuthentication()
	requirePolicyCallerAuthAssemblyFieldsUnset(t, configuration)

	if len(configuration.ExternalProfiles) != 2 {
		t.Fatalf("external profiles = %d, want 2", len(configuration.ExternalProfiles))
	}

	requirePolicyBearerAuthProjection(t, configuration.ExternalProfiles[0])
	requirePolicyBasicAuthProjection(t, configuration.ExternalProfiles[1], []byte(password))
}

// requirePolicyCallerAuthAssemblyFieldsUnset verifies that projection does not assume generation dependencies.
func requirePolicyCallerAuthAssemblyFieldsUnset(t *testing.T, configuration callerauth.Configuration) {
	t.Helper()

	if configuration.TokenValidator != nil {
		t.Fatal("projection injected a token validator")
	}

	if configuration.Throttler != nil {
		t.Fatal("projection injected a Basic throttler")
	}

	if configuration.TransportCapabilities.HTTPProtected || configuration.TransportCapabilities.GRPCProtected {
		t.Fatal("projection injected transport capabilities")
	}

	if len(configuration.InternalCallers) != 0 {
		t.Fatalf("internal callers = %d, want code-owned rules to remain unset", len(configuration.InternalCallers))
	}
}

// requirePolicyBearerAuthProjection verifies one exact Bearer-only profile projection.
func requirePolicyBearerAuthProjection(t *testing.T, bearer callerauth.ExternalProfile) {
	t.Helper()

	if bearer.Principal != "Policy-Bearer.Client" {
		t.Fatalf("Bearer principal = %q, want exact configured case", bearer.Principal)
	}

	if len(bearer.AuthenticationKinds) != 1 || bearer.AuthenticationKinds[0] != "oidc_bearer" {
		t.Fatalf("Bearer kinds = %v, want exact oidc_bearer", bearer.AuthenticationKinds)
	}

	if bearer.Basic != nil {
		t.Fatal("Bearer-only profile unexpectedly owns Basic credentials")
	}

	if !bearer.RequireMTLS {
		t.Fatal("Bearer profile lost its mTLS requirement")
	}
}

// requirePolicyBasicAuthProjection verifies dedicated Basic ownership without exposing its password.
func requirePolicyBasicAuthProjection(t *testing.T, basic callerauth.ExternalProfile, password []byte) {
	t.Helper()

	if basic.Principal != "policy-basic-client" {
		t.Fatalf("Basic principal = %q, want policy-basic-client", basic.Principal)
	}

	if len(basic.AuthenticationKinds) != 1 || basic.AuthenticationKinds[0] != "basic" {
		t.Fatalf("Basic kinds = %v, want exact basic", basic.AuthenticationKinds)
	}

	if basic.Basic == nil {
		t.Fatal("Basic profile lost its dedicated credentials")
	}

	if basic.Basic.Username != "Policy-Basic.User" {
		t.Fatalf("Basic username = %q, want exact configured case", basic.Basic.Username)
	}

	requireSecretBytes(t, basic.Basic.Password, password)
}

func TestPolicyCallerAuthProjectionCapturesGlobalGRPCMTLS(t *testing.T) {
	input, err := Normalize(context.Background(), policyCallerAuthProjectionDocument("dedicated-secret"))
	requireNoError(t, err)

	configuration := input.CallerAuthentication()
	if !configuration.RequireGRPCMTLS {
		t.Fatal("global gRPC mTLS requirement was not projected")
	}
}

func TestPolicyCallerAuthProjectionReturnsDetachedCopies(t *testing.T) {
	const password = "immutable-policy-basic-secret"

	document := policyCallerAuthProjectionDocument(password)
	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	document.Policy.API.Clients[0].AuthenticationKinds[0] = "mutated-source"
	input.Policy.API.Clients[0].AuthenticationKinds[0] = "mutated-public-policy"
	document.Policy.API.Clients[1].Authentication.Basic.Username = "mutated-source-user"
	input.Policy.API.Clients[1].Authentication.Basic.Username = "mutated-public-user"
	input.Policy.API.Clients[0].RequireMTLS = false
	input.Policy.API.GRPC.RequireMTLS = false

	first := input.CallerAuthentication()
	first.ExternalProfiles[0].AuthenticationKinds[0] = "mutated-return"
	first.ExternalProfiles[1].Basic.Username = "mutated-user"
	first.ExternalProfiles[1].Basic.Password = secret.New("mutated-secret")
	first.ExternalProfiles = append(first.ExternalProfiles, first.ExternalProfiles[0])

	second := input.CallerAuthentication()
	if len(second.ExternalProfiles) != 2 {
		t.Fatalf("external profiles = %d, want stored projection to remain 2", len(second.ExternalProfiles))
	}

	if !second.RequireGRPCMTLS || !second.ExternalProfiles[0].RequireMTLS {
		t.Fatal("detached projection lost stored global or profile mTLS ownership")
	}

	if got := second.ExternalProfiles[0].AuthenticationKinds[0]; got != "oidc_bearer" {
		t.Fatalf("detached Bearer kind = %q, want oidc_bearer", got)
	}

	if second.ExternalProfiles[1].Basic == nil {
		t.Fatal("detached Basic profile lost its credentials")
	}

	if got := second.ExternalProfiles[1].Basic.Username; got != "Policy-Basic.User" {
		t.Fatalf("detached Basic username = %q, want Policy-Basic.User", got)
	}

	requireSecretBytes(t, second.ExternalProfiles[1].Basic.Password, []byte(password))
}

// policyCallerAuthProjectionDocument builds a valid mixed caller-authentication snapshot.
func policyCallerAuthProjectionDocument(password string) policyconfig.Document {
	return policyconfig.Document{Policy: policyconfig.PolicyConfig{API: policyconfig.APIConfig{
		GRPC: policyconfig.GRPCConfig{
			Enabled:     true,
			RequireMTLS: true,
		},
		Clients: []policyconfig.ClientProfileConfig{
			{
				Principal:           "Policy-Bearer.Client",
				AuthenticationKinds: []string{"oidc_bearer"},
				RequireMTLS:         true,
			},
			{
				Authentication: policyconfig.ClientAuthenticationConfig{
					Basic: &policyconfig.BasicAuthenticationConfig{
						Username: "Policy-Basic.User",
						Password: secret.New(password),
					},
				},
				Principal:           "policy-basic-client",
				AuthenticationKinds: []string{"basic"},
			},
		},
	}}}
}

// requireSecretBytes compares secret material only inside the scoped byte callback.
func requireSecretBytes(t *testing.T, value secret.Value, expected []byte) {
	t.Helper()

	matched := false

	value.WithBytes(func(actual []byte) {
		matched = bytes.Equal(actual, expected)
	})

	if !matched {
		t.Fatal("projected secret bytes do not match the dedicated Policy-Basic credential")
	}
}
