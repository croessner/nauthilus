// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
)

const callerAdmissionProjectionFixture = `policy:
  api:
    limits:
      max_request_bytes: 1048576
      max_facts: 512
      per_client_concurrency: 8
      per_client_requests_per_second: 25
    clients:
      - principal: Policy.Client-Case
        authentication_kinds: [oidc_bearer, basic]
        authentication:
          basic:
            username: Policy.Admission.User
            password: private-basic-secret
        targets:
          - namespace: dkim2
            actions: [sign-message-instance]
          - namespace: authn
            actions: [authenticate]
        allowed_schemas: [dkim2/sign-message-instance/v1, authn/authenticate/v1]
        allowed_subject_attributes: [account, groups]
        allowed_resource_attributes: [mail_from]
        allowed_environment_attributes: [network.risk]
        allowed_input_attributes: [request_id]
        max_request_bytes: 262144
        max_facts: 128
        max_concurrency: 3
        requests_per_second: 7
        diagnostics: true
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts: []
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: dkim2/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`

func TestPolicyCallerAdmissionProjectionCapturesNormalizedProfiles(t *testing.T) {
	document := decodePolicy(t, callerAdmissionProjectionFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	requireCallerAdmissionProjection(t, input.CallerAdmission())
}

func TestPolicyCallerAdmissionProjectionReturnsDetachedCopies(t *testing.T) {
	document := decodePolicy(t, callerAdmissionProjectionFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	document.Policy.API.Clients[0].Principal = "mutated-source"
	document.Policy.API.Clients[0].AuthenticationKinds[0] = "mutated-source-kind"
	document.Policy.API.Clients[0].AllowedSubjectAttributes[0] = "mutated.source"
	document.Policy.API.Limits.MaxRequestBytes = 1

	input.Policy.API.Clients[0].Principal = "mutated-public-policy"
	input.Policy.API.Clients[0].AuthenticationKinds[0] = "mutated-public-kind"
	input.Policy.API.Clients[0].AllowedResourceAttributes[0] = "mutated.public"
	input.Policy.API.Limits.MaxFacts = 1
	input.AdmissionProfiles[0].Principal = "mutated-public-profile"
	input.AdmissionProfiles[0].References = nil

	callerAuthentication := input.CallerAuthentication()
	callerAuthentication.ExternalProfiles[0].AuthenticationKinds[0] = "mutated-auth-kind"
	callerAuthentication.ExternalProfiles[0].Basic.Username = "mutated-auth-user"
	callerAuthentication.ExternalProfiles[0].Basic.Password = secret.New("mutated-auth-secret")

	first := input.CallerAdmission()
	replacement, replacementErr := registry.NewClientAdmissionReference(
		"replacement", "authn", "lookup_identity", "authn/lookup_identity/v1",
	)
	requireNoError(t, replacementErr)

	first.GlobalLimits.MaxRequestBytes = 2
	first.Profiles[0].Principal = "mutated-return"
	first.Profiles[0].AuthenticationKinds[0] = "mutated-return-kind"
	first.Profiles[0].AllowedSubjectAttributes[0] = "mutated.return"
	first.Profiles[0].AllowedResourceAttributes[0] = "mutated.return"
	first.Profiles[0].AllowedEnvironmentAttributes[0] = "mutated.return"
	first.Profiles[0].AllowedInputAttributes[0] = "mutated.return"
	first.Profiles[0].References[0] = replacement
	first.Profiles[0].Limits.MaxFacts = 2
	first.Profiles[0].Diagnostics = false
	first.Profiles[0].Internal = true
	first.Profiles = append(first.Profiles, first.Profiles[0])

	requireCallerAdmissionProjection(t, input.CallerAdmission())
}

func TestPolicyCallerAdmissionOmittedLimitsRemainPreparable(t *testing.T) {
	document := decodePolicy(t, exactGenericTargetFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	credentials, err := policyruntime.NewCredentialProfiles([]string{"dkim2-client"})
	requireNoError(t, err)

	prepared, err := admission.Prepare(input.CallerAdmission(), catalog, credentials)
	requireNoError(t, err)

	if prepared.Authority == nil {
		t.Fatal("omitted standalone limits produced no admission authority")
	}
}

// requireCallerAdmissionProjection verifies the exact detached external admission contract.
func requireCallerAdmissionProjection(t *testing.T, configuration admission.Configuration) {
	t.Helper()

	wantGlobal := admission.Limits{
		MaxRequestBytes:   1048576,
		MaxFacts:          512,
		MaxConcurrency:    8,
		RequestsPerSecond: 25,
	}
	if configuration.GlobalLimits != wantGlobal {
		t.Fatalf("global limits = %+v, want %+v", configuration.GlobalLimits, wantGlobal)
	}

	if len(configuration.Profiles) != 1 {
		t.Fatalf("profiles = %d, want one external profile", len(configuration.Profiles))
	}

	profile := configuration.Profiles[0]
	if profile.Principal != "Policy.Client-Case" {
		t.Fatalf("principal = %q, want exact configured case", profile.Principal)
	}

	assertStringSlice(t, "authentication kinds", profile.AuthenticationKinds, []string{"oidc_bearer", "basic"})
	assertStringSlice(t, "subject allowlist", profile.AllowedSubjectAttributes, []string{"account", "groups"})
	assertStringSlice(t, "resource allowlist", profile.AllowedResourceAttributes, []string{"mail_from"})
	assertStringSlice(t, "environment allowlist", profile.AllowedEnvironmentAttributes, []string{"network.risk"})
	assertStringSlice(t, "input allowlist", profile.AllowedInputAttributes, []string{"request_id"})

	wantProfileLimits := admission.Limits{
		MaxRequestBytes:   262144,
		MaxFacts:          128,
		MaxConcurrency:    3,
		RequestsPerSecond: 7,
	}
	if profile.Limits != wantProfileLimits {
		t.Fatalf("profile limits = %+v, want %+v", profile.Limits, wantProfileLimits)
	}

	if !profile.Diagnostics {
		t.Fatal("diagnostics permission was not projected")
	}

	if profile.Internal {
		t.Fatal("external configuration profile was projected as code-owned internal")
	}

	requireAdmissionReferences(t, profile.References)
}

// assertStringSlice compares one ordered detached profile list.
func assertStringSlice(t *testing.T, name string, actual []string, expected []string) {
	t.Helper()

	if !slices.Equal(actual, expected) {
		t.Fatalf("%s = %v, want %v", name, actual, expected)
	}
}

// requireAdmissionReferences verifies normalized exact target, schema, and source-path ownership.
func requireAdmissionReferences(t *testing.T, references []registry.ClientAdmissionReference) {
	t.Helper()

	want := []struct {
		target string
		schema string
		path   string
	}{
		{
			target: "dkim2/sign-message-instance",
			schema: "dkim2/sign-message-instance/v1",
			path:   "policy.api.clients[0].targets[0].actions[0]",
		},
		{
			target: "authn/authenticate",
			schema: "authn/authenticate/v1",
			path:   "policy.api.clients[0].targets[1].actions[0]",
		},
	}

	if len(references) != len(want) {
		t.Fatalf("references = %d, want %d exact references", len(references), len(want))
	}

	for index, expected := range want {
		if got := references[index].Target().String(); got != expected.target {
			t.Fatalf("reference %d target = %q, want %q", index, got, expected.target)
		}

		if got := references[index].Schema().String(); got != expected.schema {
			t.Fatalf("reference %d schema = %q, want %q", index, got, expected.schema)
		}

		if got := references[index].Path(); got != expected.path {
			t.Fatalf("reference %d path = %q, want %q", index, got, expected.path)
		}
	}
}
