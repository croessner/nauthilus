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

package admission

import (
	"errors"
	"slices"
	"testing"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestPrepareReturnsExactSortedAdmissionProfiles(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	second := configuration.Profiles[0]
	second.Principal = "Another.Policy.Client"
	configuration.Profiles = append(configuration.Profiles, second)
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal, second.Principal})

	prepared, err := Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	want := []string{second.Principal, admissionTestPrincipal}
	if got := prepared.Profiles.IDs(); !slices.Equal(got, want) {
		t.Fatalf("admission profile IDs = %v, want %v", got, want)
	}

	if prepared.Authority == nil {
		t.Fatal("prepared authority is nil")
	}

	if len(prepared.Resources) != 0 {
		t.Fatalf("prepared resources = %d, want none", len(prepared.Resources))
	}
}

func TestPrepareRejectsCredentialProfileMismatch(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	credentials := admissionTestCredentials(t, []string{"different-credential-profile"})

	prepared, err := Prepare(configuration, catalog, credentials)
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
	}

	if prepared.Authority != nil || len(prepared.Profiles.IDs()) != 0 || len(prepared.Resources) != 0 {
		t.Fatalf("failed preparation returned partial authority: %+v", prepared)
	}
}

type admissionConfigurationMutation func(*Configuration)

func TestPrepareRejectsInvalidProfileIdentityAndKinds(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	base := admissionTestConfiguration(t, reference)

	mutations := map[string]admissionConfigurationMutation{
		"duplicate principal": func(configuration *Configuration) {
			configuration.Profiles = append(configuration.Profiles, configuration.Profiles[0])
		},
		"trimmed principal mismatch": func(configuration *Configuration) {
			configuration.Profiles[0].Principal = " leading-space"
		},
		"missing authentication kind": func(configuration *Configuration) {
			configuration.Profiles[0].AuthenticationKinds = nil
		},
		"unsupported authentication kind": func(configuration *Configuration) {
			configuration.Profiles[0].AuthenticationKinds = []string{"management-basic"}
		},
		"duplicate authentication kind": func(configuration *Configuration) {
			configuration.Profiles[0].AuthenticationKinds = []string{
				policy.CallerAuthenticationKindBearer, policy.CallerAuthenticationKindBearer,
			}
		},
		"external profile claims internal kind": func(configuration *Configuration) {
			configuration.Profiles[0].AuthenticationKinds = []string{policy.CallerAuthenticationKindInternal}
		},
		"internal profile claims external kind": func(configuration *Configuration) {
			configuration.Profiles[0].Internal = true
			configuration.Profiles[0].AuthenticationKinds = []string{policy.CallerAuthenticationKindBasic}
		},
	}

	assertAdmissionConfigurationsInvalid(t, catalog, base, mutations)
}

func TestPrepareRejectsInvalidProfileReferencesAndFields(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	base := admissionTestConfiguration(t, reference)
	mutations := map[string]admissionConfigurationMutation{
		"missing target reference": func(configuration *Configuration) {
			configuration.Profiles[0].References = nil
		},
		"duplicate target reference": func(configuration *Configuration) {
			configuration.Profiles[0].References = append(
				configuration.Profiles[0].References, configuration.Profiles[0].References[0],
			)
		},
		"duplicate allowlisted field": func(configuration *Configuration) {
			configuration.Profiles[0].AllowedInputAttributes = []string{"request_id", "request_id"}
		},
		"invalid relative field": func(configuration *Configuration) {
			configuration.Profiles[0].AllowedInputAttributes = []string{"bad field"}
		},
		"trusted-shaped relative field": func(configuration *Configuration) {
			configuration.Profiles[0].AllowedInputAttributes = []string{"caller.principal"}
		},
		"undeclared allowlisted field": func(configuration *Configuration) {
			configuration.Profiles[0].AllowedInputAttributes = []string{"undeclared"}
		},
	}

	assertAdmissionConfigurationsInvalid(t, catalog, base, mutations)
}

func TestPrepareRejectsInvalidProfileLimits(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	base := admissionTestConfiguration(t, reference)
	mutations := map[string]admissionConfigurationMutation{
		"negative profile limit": func(configuration *Configuration) {
			configuration.Profiles[0].Limits.MaxFacts = -1
		},
		"profile limit exceeds global": func(configuration *Configuration) {
			configuration.Profiles[0].Limits.MaxConcurrency = configuration.GlobalLimits.MaxConcurrency + 1
		},
	}

	assertAdmissionConfigurationsInvalid(t, catalog, base, mutations)
}

// assertAdmissionConfigurationsInvalid verifies one mutation set against the same detached base.
func assertAdmissionConfigurationsInvalid(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	base Configuration,
	mutations map[string]admissionConfigurationMutation,
) {
	t.Helper()

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			configuration := cloneAdmissionTestConfiguration(base)
			mutate(&configuration)

			credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

			_, err := Prepare(configuration, catalog, credentials)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestPrepareRejectsInvalidGlobalLimitsAndCatalog(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	limits := []struct {
		name   string
		mutate func(*Limits)
	}{
		{name: "request bytes", mutate: func(value *Limits) { value.MaxRequestBytes = 0 }},
		{name: "fact count", mutate: func(value *Limits) { value.MaxFacts = 0 }},
		{name: "concurrency", mutate: func(value *Limits) { value.MaxConcurrency = 0 }},
		{name: "request rate", mutate: func(value *Limits) { value.RequestsPerSecond = 0 }},
	}

	for _, test := range limits {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneAdmissionTestConfiguration(configuration)
			test.mutate(&candidate.GlobalLimits)

			_, err := Prepare(candidate, catalog, credentials)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
			}
		})
	}

	if _, err := Prepare(configuration, nil, credentials); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Prepare(nil catalog) error = %v, want ErrConfiguration", err)
	}
}

func TestPrepareRejectsUnknownAndWrongSchemaReferences(t *testing.T) {
	t.Parallel()

	catalog, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	unknown, err := registry.NewClientAdmissionReference(
		"policy.api.clients[0].targets[0]",
		"other",
		"submit",
		"other/submit/v1",
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference(unknown) error = %v", err)
	}

	wrongSchema, err := registry.NewClientAdmissionReference(
		"policy.api.clients[0].targets[0]",
		admissionTestNamespace,
		admissionTestAction,
		"mail/submit/v2",
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference(wrong schema) error = %v", err)
	}

	for name, candidate := range map[string]registry.ClientAdmissionReference{
		"unknown target": unknown,
		"wrong schema":   wrongSchema,
		"zero reference": {},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := admissionTestConfiguration(t, reference)
			configuration.Profiles[0].References = []registry.ClientAdmissionReference{candidate}

			_, err := Prepare(configuration, catalog, credentials)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestPrepareRejectsProfileFieldWithWrongSchemaAuthorityOrCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fact registry.FactSchema
		name string
	}{
		{
			name: "wrong source",
			fact: admissionTestFactSchema(
				t,
				"input.request_id",
				decision.FactCategoryEnvironment,
				decision.ValueKindString,
				decision.FactSourceToken,
				64,
				0,
				0,
			),
		},
		{
			name: "wrong category",
			fact: admissionTestFactSchema(
				t,
				"input.request_id",
				decision.FactCategorySubject,
				decision.ValueKindString,
				decision.FactSourceCaller,
				64,
				0,
				0,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := admissionTestSchemaFacts(t)
			facts[3] = test.fact
			catalog, _, reference := admissionTestCatalog(t, facts)
			configuration := admissionTestConfiguration(t, reference)
			credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

			_, err := Prepare(configuration, catalog, credentials)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestPreparedAuthorityDetachesConfiguration(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	prepared, err := Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	configuration.GlobalLimits.MaxFacts = 1
	configuration.Profiles[0].Principal = "mutated-principal"
	configuration.Profiles[0].AuthenticationKinds[0] = policy.CallerAuthenticationKindInternal
	configuration.Profiles[0].AllowedInputAttributes[0] = "mutated"
	configuration.Profiles[0].References[0] = registry.ClientAdmissionReference{}
	configuration.Profiles[0].Internal = true

	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		input: map[string]decision.Value{
			"request_id": admissionTestStringValue(t, "owned"),
		},
	})

	permit := admissionTestPermit(t, prepared.Authority, caller, request)
	defer permit.Release()

	if _, exists := permit.Facts().Get("input.request_id"); !exists {
		t.Fatal("detached authority lost the original input allowlist")
	}
}

// cloneAdmissionTestConfiguration deeply detaches mutable test profile containers.
func cloneAdmissionTestConfiguration(input Configuration) Configuration {
	cloned := Configuration{GlobalLimits: input.GlobalLimits, Profiles: make([]Profile, len(input.Profiles))}
	for index, profile := range input.Profiles {
		cloned.Profiles[index] = Profile{
			Principal:                    profile.Principal,
			AuthenticationKinds:          append([]string(nil), profile.AuthenticationKinds...),
			References:                   append([]registry.ClientAdmissionReference(nil), profile.References...),
			AllowedSubjectAttributes:     append([]string(nil), profile.AllowedSubjectAttributes...),
			AllowedResourceAttributes:    append([]string(nil), profile.AllowedResourceAttributes...),
			AllowedEnvironmentAttributes: append([]string(nil), profile.AllowedEnvironmentAttributes...),
			AllowedInputAttributes:       append([]string(nil), profile.AllowedInputAttributes...),
			Limits:                       profile.Limits,
			Diagnostics:                  profile.Diagnostics,
			Internal:                     profile.Internal,
		}
	}

	return cloned
}
