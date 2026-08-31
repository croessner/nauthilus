// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/secret"
)

func TestPolicyCallerAuthRequiresNonEmptyUniqueKinds(t *testing.T) {
	tests := []struct {
		name  string
		kinds []string
		path  string
	}{
		{
			name: "missing kinds",
			path: "policy.api.clients[0].authentication_kinds",
		},
		{
			name:  "duplicate Bearer kind",
			kinds: []string{"oidc_bearer", "oidc_bearer"},
			path:  "policy.api.clients[0].authentication_kinds[1]",
		},
		{
			name:  "duplicate Basic kind",
			kinds: []string{"basic", "basic"},
			path:  "policy.api.clients[0].authentication_kinds[1]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := policyCallerAuthClient("policy-client", test.kinds...)
			if contains(test.kinds, "basic") {
				client.Authentication.Basic = policyBasicCredentials("policy-client", "dedicated-secret")
			}

			err := Validate(policyCallerAuthDocument(client))

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestPolicyBasicAuthenticationRequiresBidirectionalOwnership(t *testing.T) {
	tests := []struct {
		name   string
		client ClientProfileConfig
		path   string
	}{
		{
			name:   "kind without dedicated credentials",
			client: policyCallerAuthClient("policy-client", "basic"),
			path:   "policy.api.clients[0].authentication.basic",
		},
		{
			name: "credentials without Basic kind",
			client: func() ClientProfileConfig {
				client := policyCallerAuthClient("policy-client", "oidc_bearer")
				client.Authentication.Basic = policyBasicCredentials("policy-client", "dedicated-secret")

				return client
			}(),
			path: "policy.api.clients[0].authentication.basic",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(policyCallerAuthDocument(test.client))

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestPolicyBasicAuthenticationAcceptsDedicatedCredentials(t *testing.T) {
	client := policyCallerAuthClient("policy-client", "oidc_bearer", "basic")
	client.Authentication.Basic = policyBasicCredentials("policy-client", "dedicated-secret")

	requireNoError(t, Validate(policyCallerAuthDocument(client)))
}

func TestPolicyBasicAuthenticationUsernameOwnershipIsExact(t *testing.T) {
	first := policyCallerAuthClient("first-client", "basic")
	first.Authentication.Basic = policyBasicCredentials("Policy-Client", "first-secret")
	second := policyCallerAuthClient("second-client", "basic")
	second.Authentication.Basic = policyBasicCredentials("policy-client", "second-secret")

	requireNoError(t, Validate(policyCallerAuthDocument(first, second)))

	second.Authentication.Basic = policyBasicCredentials("Policy-Client", "second-secret")
	err := Validate(policyCallerAuthDocument(first, second))

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.api.clients[1].authentication.basic.username", pathError.Path)
}

func TestPolicyCallerAuthPrincipalsRemainCaseSensitive(t *testing.T) {
	clients := []ClientProfileConfig{
		policyCallerAuthClient("Policy-Client", "oidc_bearer"),
		policyCallerAuthClient("policy-client", "oidc_bearer"),
	}

	requireNoError(t, Validate(policyCallerAuthDocument(clients...)))

	clients[1].Principal = "Policy-Client"
	err := Validate(policyCallerAuthDocument(clients...))

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.api.clients[1].principal", pathError.Path)
}

func TestPolicyCallerAuthRejectsMTLSAsAuthenticationKind(t *testing.T) {
	err := Validate(policyCallerAuthDocument(policyCallerAuthClient("policy-client", "mtls")))

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.api.clients[0].authentication_kinds[0]", pathError.Path)
}

func TestPolicyBasicAuthenticationValidationRedactsSecret(t *testing.T) {
	const password = "must-not-appear-in-validation"

	client := policyCallerAuthClient("policy-client", "oidc_bearer")
	client.Authentication.Basic = policyBasicCredentials("policy-client", password)

	err := Validate(policyCallerAuthDocument(client))
	if err == nil {
		t.Fatal("expected invalid Policy-Basic ownership")
	}

	if strings.Contains(err.Error(), password) {
		t.Fatal("Policy-Basic validation exposed secret material")
	}
}

// policyCallerAuthDocument builds the minimal standalone API document for authentication validation.
func policyCallerAuthDocument(clients ...ClientProfileConfig) Document {
	return Document{Policy: PolicyConfig{API: APIConfig{Clients: clients}}}
}

// policyCallerAuthClient builds one exact principal-owned caller profile.
func policyCallerAuthClient(principal string, kinds ...string) ClientProfileConfig {
	return ClientProfileConfig{
		Principal:           principal,
		AuthenticationKinds: kinds,
	}
}

// policyBasicCredentials creates profile-owned Policy-Basic material for validation tests.
func policyBasicCredentials(username string, password string) *BasicAuthenticationConfig {
	return &BasicAuthenticationConfig{
		Username: username,
		Password: secret.New(password),
	}
}
