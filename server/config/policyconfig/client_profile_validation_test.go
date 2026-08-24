// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"fmt"
	"testing"
)

type clientAttributeAllowlist struct {
	set      func(*ClientProfileConfig, []string)
	category string
	field    string
}

func TestClientProfileAttributeAllowlistsRejectInvalidAndDuplicateFacts(t *testing.T) {
	for _, allowlist := range clientAttributeAllowlists() {
		t.Run(allowlist.category+"/invalid", func(t *testing.T) {
			client := validClientProfile()
			allowlist.set(&client, []string{"profile..name"})

			requireClientProfilePathError(t, client, "policy.api.clients[0]."+allowlist.field+"[0]")
		})

		t.Run(allowlist.category+"/duplicate", func(t *testing.T) {
			client := validClientProfile()
			allowlist.set(&client, []string{"profile.display-name", "profile.display-name"})

			requireClientProfilePathError(t, client, "policy.api.clients[0]."+allowlist.field+"[1]")
		})
	}
}

func TestClientProfileAttributeAllowlistsRejectTrustedPrefixes(t *testing.T) {
	trustedPrefixes := []string{"caller", "token", "transport", "nauthilus", "backend", "lua", "plugin"}

	for _, prefix := range trustedPrefixes {
		t.Run(prefix, func(t *testing.T) {
			client := validClientProfile()
			client.AllowedSubjectAttributes = []string{prefix + ".forged"}

			requireClientProfilePathError(t, client, "policy.api.clients[0].allowed_subject_attributes[0]")
		})
	}
}

func TestClientProfileAttributeAllowlistsAcceptCanonicalRelativeFacts(t *testing.T) {
	client := validClientProfile()
	values := []string{"id", "profile.display-name"}
	client.AllowedSubjectAttributes = values
	client.AllowedResourceAttributes = values
	client.AllowedEnvironmentAttributes = values
	client.AllowedInputAttributes = values

	requireNoError(t, Validate(clientProfileDocument(client, APILimitsConfig{})))
}

func TestClientProfileAllowedSchemasRequireUniqueExactReferences(t *testing.T) {
	tests := []struct {
		name    string
		schemas []string
		index   int
	}{
		{name: "missing exact version", schemas: []string{"authn/password/latest"}},
		{name: "zero version", schemas: []string{"authn/password/v0"}},
		{name: "version out of range", schemas: []string{"authn/password/v999999999999999999999999"}},
		{name: "duplicate", schemas: []string{"authn/password/v1", "authn/password/v1"}, index: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := validClientProfile()
			client.AllowedSchemas = test.schemas

			path := fmt.Sprintf("policy.api.clients[0].allowed_schemas[%d]", test.index)
			requireClientProfilePathError(t, client, path)
		})
	}
}

func TestClientProfileAllowedSchemasAcceptExactReferences(t *testing.T) {
	client := validClientProfile()
	client.AllowedSchemas = []string{"authn/password/v1", "dkim2/sign-message/v2"}

	requireNoError(t, Validate(clientProfileDocument(client, APILimitsConfig{})))
}

func TestClientProfileLimitsRespectConfiguredServerBounds(t *testing.T) {
	tests := []struct {
		mutate func(*ClientProfileConfig)
		name   string
		path   string
	}{
		{
			name: "negative concurrency",
			path: "policy.api.clients[0].max_concurrency",
			mutate: func(client *ClientProfileConfig) {
				client.MaxConcurrency = -1
			},
		},
		{
			name: "concurrency exceeds server",
			path: "policy.api.clients[0].max_concurrency",
			mutate: func(client *ClientProfileConfig) {
				client.MaxConcurrency = 5
			},
		},
		{
			name: "negative request rate",
			path: "policy.api.clients[0].requests_per_second",
			mutate: func(client *ClientProfileConfig) {
				client.RequestsPerSecond = -1
			},
		},
		{
			name: "request rate exceeds server",
			path: "policy.api.clients[0].requests_per_second",
			mutate: func(client *ClientProfileConfig) {
				client.RequestsPerSecond = 9
			},
		},
	}

	limits := APILimitsConfig{PerClientConcurrency: 4, PerClientRequestsPerSecond: 8}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := validClientProfile()
			test.mutate(&client)

			err := Validate(clientProfileDocument(client, limits))

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestClientProfileLimitsPreserveZeroInheritance(t *testing.T) {
	client := validClientProfile()
	limits := APILimitsConfig{PerClientConcurrency: 4, PerClientRequestsPerSecond: 8}

	requireNoError(t, Validate(clientProfileDocument(client, limits)))

	client.MaxConcurrency = 2
	client.RequestsPerSecond = 3

	requireNoError(t, Validate(clientProfileDocument(client, APILimitsConfig{})))
}

func TestClientProfileTargetsRejectDuplicateGrantsAndActions(t *testing.T) {
	tests := []struct {
		targets []ClientTargetConfig
		name    string
		path    string
	}{
		{
			name: "duplicate target grant",
			path: "policy.api.clients[0].targets[1].namespace",
			targets: []ClientTargetConfig{
				{Namespace: "authn", Actions: []string{"password"}},
				{Namespace: "authn", Actions: []string{"webauthn"}},
			},
		},
		{
			name: "duplicate action within grant",
			path: "policy.api.clients[0].targets[0].actions[1]",
			targets: []ClientTargetConfig{
				{Namespace: "authn", Actions: []string{"password", "password"}},
			},
		},
		{
			name: "duplicate action across grants",
			path: "policy.api.clients[0].targets[1].actions[0]",
			targets: []ClientTargetConfig{
				{Namespace: "authn", Actions: []string{"password"}},
				{Namespace: "authn", Actions: []string{"password", "webauthn"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := validClientProfile()
			client.Targets = test.targets

			requireClientProfilePathError(t, client, test.path)
		})
	}
}

func TestClientProfileTargetsAllowSameActionInDifferentNamespaces(t *testing.T) {
	client := validClientProfile()
	client.Targets = []ClientTargetConfig{
		{Namespace: "authn", Actions: []string{"evaluate"}},
		{Namespace: "dkim2", Actions: []string{"evaluate"}},
	}

	requireNoError(t, Validate(clientProfileDocument(client, APILimitsConfig{})))
}

// clientAttributeAllowlists returns each caller-controlled category and its profile field.
func clientAttributeAllowlists() []clientAttributeAllowlist {
	return []clientAttributeAllowlist{
		{
			category: "subject",
			field:    "allowed_subject_attributes",
			set: func(client *ClientProfileConfig, values []string) {
				client.AllowedSubjectAttributes = values
			},
		},
		{
			category: "resource",
			field:    "allowed_resource_attributes",
			set: func(client *ClientProfileConfig, values []string) {
				client.AllowedResourceAttributes = values
			},
		},
		{
			category: "environment",
			field:    "allowed_environment_attributes",
			set: func(client *ClientProfileConfig, values []string) {
				client.AllowedEnvironmentAttributes = values
			},
		},
		{
			category: "input",
			field:    "allowed_input_attributes",
			set: func(client *ClientProfileConfig, values []string) {
				client.AllowedInputAttributes = values
			},
		},
	}
}

// validClientProfile creates the smallest valid Bearer-owned admission profile.
func validClientProfile() ClientProfileConfig {
	return ClientProfileConfig{
		Principal:           "policy-client",
		AuthenticationKinds: []string{"oidc_bearer"},
	}
}

// clientProfileDocument binds one profile and its global admission bounds.
func clientProfileDocument(client ClientProfileConfig, limits APILimitsConfig) Document {
	return Document{Policy: PolicyConfig{API: APIConfig{Clients: []ClientProfileConfig{client}, Limits: limits}}}
}

// requireClientProfilePathError verifies profile validation fails at one exact field path.
func requireClientProfilePathError(t *testing.T, client ClientProfileConfig, path string) {
	t.Helper()

	err := Validate(clientProfileDocument(client, APILimitsConfig{}))

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, path, pathError.Path)
}
