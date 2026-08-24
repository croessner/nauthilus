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
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestAdmissionRejectsUnregisteredPrincipal(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestCaller(t, admissionTestCallerInput{
		principal: "unregistered-client",
		scopes:    []string{definitions.ScopePolicyEvaluate},
	})
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})

	permit, err := prepared.Authority.Admit(context.Background(), caller, request)
	if !errors.Is(err, ErrAdmission) || !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Admit() error = %v, want admission permission denial", err)
	}

	if permit != nil {
		t.Fatal("rejected principal received a permit")
	}
}

func TestAdmissionRejectsWrongAuthenticationKindAndInternalStatus(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))

	tests := []struct {
		profileKinds []string
		callerKind   string
		name         string
		profileInner bool
		callerInner  bool
	}{
		{
			name:         "wrong external authentication kind",
			profileKinds: []string{policy.CallerAuthenticationKindBearer},
			callerKind:   policy.CallerAuthenticationKindBasic,
		},
		{
			name:         "external caller cannot use internal profile",
			profileKinds: []string{policy.CallerAuthenticationKindInternal},
			callerKind:   policy.CallerAuthenticationKindInternal,
			profileInner: true,
		},
		{
			name:         "internal caller cannot use external profile",
			profileKinds: []string{policy.CallerAuthenticationKindBearer},
			callerKind:   policy.CallerAuthenticationKindBearer,
			callerInner:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := admissionTestConfiguration(t, reference)
			configuration.Profiles[0].AuthenticationKinds = test.profileKinds
			configuration.Profiles[0].Internal = test.profileInner
			credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

			prepared, err := Prepare(configuration, catalog, credentials)
			if err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}

			caller := admissionTestCaller(t, admissionTestCallerInput{
				authenticationKind: test.callerKind,
				scopes:             []string{definitions.ScopePolicyEvaluate},
				internal:           test.callerInner,
			})
			request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})

			permit, err := prepared.Authority.Admit(context.Background(), caller, request)
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("Admit() error = %v, want ErrPermissionDenied", err)
			}

			if permit != nil {
				t.Fatal("mismatched caller received a permit")
			}
		})
	}
}

func TestAdmissionRejectsTargetOutsideExactProfileGrant(t *testing.T) {
	t.Parallel()

	_, _, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestBearerCaller(t)

	for name, target := range map[string]decision.Target{
		"wrong namespace": admissionTestTarget(t, "other", admissionTestAction),
		"wrong action":    admissionTestTarget(t, admissionTestNamespace, "other"),
	} {
		t.Run(name, func(t *testing.T) {
			request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})

			permit, err := prepared.Authority.Admit(context.Background(), caller, request)
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("Admit() error = %v, want ErrPermissionDenied", err)
			}

			if permit != nil {
				t.Fatal("ungranted target received a permit")
			}
		})
	}
}

func TestNamedInternalProfileRemainsTargetConstrained(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.Profiles[0].AuthenticationKinds = []string{policy.CallerAuthenticationKindInternal}
	configuration.Profiles[0].Internal = true

	prepared, err := Prepare(
		configuration,
		catalog,
		admissionTestCredentials(t, []string{admissionTestPrincipal}),
	)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	caller := admissionTestCaller(t, admissionTestCallerInput{
		authenticationKind: policy.CallerAuthenticationKindInternal,
		internal:           true,
	})
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})
	permit := admissionTestPermit(t, prepared.Authority, caller, request)
	permit.Release()

	wrongTarget := admissionTestTarget(t, admissionTestNamespace, "other")
	rejected := admissionTestRequest(t, caller, admissionTestRequestInput{target: wrongTarget})

	permit, err = prepared.Authority.Admit(context.Background(), caller, rejected)
	if !errors.Is(err, ErrPermissionDenied) || permit != nil {
		t.Fatalf("internal wrong-target admission = %v/%v, want permission denial", permit, err)
	}
}

func TestAdmissionRejectsDisallowedSubmittedFields(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestBearerCaller(t)

	tests := []struct {
		request admissionTestRequestInput
		name    string
	}{
		{
			name: "subject",
			request: admissionTestRequestInput{
				subject: map[string]decision.Value{"other": admissionTestStringValue(t, "value")},
			},
		},
		{
			name: "resource",
			request: admissionTestRequestInput{
				resource: map[string]decision.Value{"other": admissionTestStringValue(t, "value")},
			},
		},
		{
			name: "environment",
			request: admissionTestRequestInput{
				environment: map[string]decision.Value{"other": admissionTestStringValue(t, "value")},
			},
		},
		{
			name: "input",
			request: admissionTestRequestInput{
				input: map[string]decision.Value{"other": admissionTestStringValue(t, "value")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.request.target = target
			request := admissionTestRequest(t, caller, test.request)

			permit, err := prepared.Authority.Admit(context.Background(), caller, request)
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("Admit() error = %v, want ErrPermissionDenied", err)
			}

			if permit != nil {
				t.Fatal("disallowed field received a permit")
			}
		})
	}
}

func TestAdmissionRejectsEveryTrustedShapedSubmittedKey(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.Profiles[0].AllowedInputAttributes = nil
	prepared := admissionTestPreparation(t, configuration)
	caller := admissionTestBearerCaller(t)

	for _, family := range []string{"caller", "token", "transport", "nauthilus", "backend", "lua", "plugin"} {
		t.Run(family, func(t *testing.T) {
			request := admissionTestRequest(t, caller, admissionTestRequestInput{
				target: target,
				input: map[string]decision.Value{
					family + ".forged": admissionTestStringValue(t, "must-not-appear"),
				},
			})

			permit, err := prepared.Authority.Admit(context.Background(), caller, request)
			if !errors.Is(err, ErrInvalidRequest) || !errors.Is(err, ErrAdmission) {
				t.Fatalf("Admit() error = %v, want invalid admission request", err)
			}

			if permit != nil {
				t.Fatal("trusted-shaped field received a permit")
			}
		})
	}
}

func TestAdmissionAppliesExactSchemaTypeAndBounds(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestBearerCaller(t)

	tests := []struct {
		value decision.Value
		name  string
	}{
		{name: "wrong type", value: admissionTestIntegerValue(t, 7)},
		{name: "string bound", value: admissionTestStringValue(t, strings.Repeat("x", 65))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := admissionTestRequest(t, caller, admissionTestRequestInput{
				target: target,
				input:  map[string]decision.Value{"request_id": test.value},
			})

			permit, err := prepared.Authority.Admit(context.Background(), caller, request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Admit() error = %v, want ErrInvalidRequest", err)
			}

			if permit != nil {
				t.Fatal("schema-invalid fact received a permit")
			}
		})
	}
}

func TestAdmissionRejectsCallerAndRequestIdentityMismatch(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	requestCaller := admissionTestBearerCaller(t)
	presentedCaller := admissionTestCaller(t, admissionTestCallerInput{
		authenticationKind: policy.CallerAuthenticationKindBasic,
	})
	request := admissionTestRequest(t, requestCaller, admissionTestRequestInput{target: target})

	permit, err := prepared.Authority.Admit(context.Background(), presentedCaller, request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Admit() error = %v, want ErrInvalidRequest", err)
	}

	if permit != nil {
		t.Fatal("caller/request mismatch received a permit")
	}
}

func TestAdmissionBuildsCallerAndTrustedFactsWithExactProvenance(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		subject: map[string]decision.Value{
			"account": admissionTestStringValue(t, "alice"),
		},
		resource: map[string]decision.Value{
			"mail_from": admissionTestStringValue(t, "alice@example.test"),
		},
		environment: map[string]decision.Value{
			"network.risk": admissionTestIntegerValue(t, 3),
		},
		input: map[string]decision.Value{
			"request_id": admissionTestStringValue(t, "request-44"),
		},
	})

	permit := admissionTestPermit(t, prepared.Authority, caller, request)
	defer permit.Release()

	assertAdmissionFactProvenance(t, permit.Facts(), admissionExpectedFactSources())
	assertAdmissionScopesFact(t, permit.Facts())
}

// admissionExpectedFactSources returns every submitted and present trusted source expectation.
func admissionExpectedFactSources() map[string]decision.FactSource {
	return map[string]decision.FactSource{
		"subject.account":                     decision.FactSourceCaller,
		"resource.mail_from":                  decision.FactSourceCaller,
		"environment.network.risk":            decision.FactSourceCaller,
		"input.request_id":                    decision.FactSourceCaller,
		decision.FactCallerPrincipal:          decision.FactSourceNauthilus,
		decision.FactCallerClientID:           decision.FactSourceNauthilus,
		decision.FactCallerAuthenticationKind: decision.FactSourceNauthilus,
		decision.FactCallerScopes:             decision.FactSourceNauthilus,
		decision.FactTokenSubject:             decision.FactSourceToken,
		decision.FactTokenIssuer:              decision.FactSourceToken,
		decision.FactTransportKind:            decision.FactSourceTransport,
		decision.FactTransportListener:        decision.FactSourceTransport,
		decision.FactTransportHTTPRoute:       decision.FactSourceTransport,
		decision.FactTransportMTLSIdentity:    decision.FactSourceTransport,
		decision.FactTransportSourceIP:        decision.FactSourceTransport,
	}
}

// assertAdmissionFactProvenance verifies exact source, authority, component, and absence semantics.
func assertAdmissionFactProvenance(
	t *testing.T,
	facts decision.FactSet,
	wantSources map[string]decision.FactSource,
) {
	t.Helper()

	if facts.Len() != len(wantSources) {
		t.Fatalf("admitted fact count = %d, want %d", facts.Len(), len(wantSources))
	}

	for id, source := range wantSources {
		fact, exists := facts.Get(id)
		if !exists {
			t.Fatalf("admitted fact %q missing", id)
		}

		if fact.Provenance().Source() != source || fact.Provenance().Authority() != admissionTestPrincipal {
			t.Fatalf("fact %q provenance = %q/%q", id, fact.Provenance().Source(), fact.Provenance().Authority())
		}

		wantComponent := "authenticator"
		if source == decision.FactSourceCaller {
			wantComponent = "request"
		}

		if fact.Provenance().Component() != wantComponent {
			t.Fatalf("fact %q component = %q, want %q", id, fact.Provenance().Component(), wantComponent)
		}
	}

	if _, exists := facts.Get(decision.FactTransportGRPCMethod); exists {
		t.Fatal("unset gRPC method was projected")
	}
}

// assertAdmissionScopesFact verifies deterministic normalized trusted scope values.
func assertAdmissionScopesFact(t *testing.T, facts decision.FactSet) {
	t.Helper()

	scopesFact, exists := facts.Get(decision.FactCallerScopes)
	if !exists {
		t.Fatal("caller scopes fact missing")
	}

	scopes, ok := scopesFact.Value().Strings()
	if !ok || !slices.Equal(scopes, []string{definitions.ScopePolicyDiagnostics, definitions.ScopePolicyEvaluate}) {
		t.Fatalf("caller scopes = %v, want deterministic Policy scopes", scopes)
	}
}

func TestAdmissionProjectsOnlySchemaDeclaredTrustedFacts(t *testing.T) {
	t.Parallel()

	facts := admissionTestSchemaFacts(t)

	declarations := make([]registry.FactSchema, 0, len(facts))
	for _, fact := range facts {
		if fact.ID() == decision.FactTokenIssuer {
			continue
		}

		declarations = append(declarations, fact)
	}

	catalog, target, reference := admissionTestCatalog(t, declarations)
	configuration := admissionTestConfiguration(t, reference)

	prepared, err := Prepare(
		configuration,
		catalog,
		admissionTestCredentials(t, []string{admissionTestPrincipal}),
	)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})

	permit := admissionTestPermit(t, prepared.Authority, caller, request)
	defer permit.Release()

	if _, exists := permit.Facts().Get(decision.FactTokenIssuer); exists {
		t.Fatal("schema-undeclared trusted token issuer was projected")
	}
}

func TestAdmissionPropagatesCanceledContextWithoutPermit(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	permit, err := prepared.Authority.Admit(ctx, caller, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Admit() error = %v, want context.Canceled", err)
	}

	if permit != nil {
		t.Fatal("canceled admission received a permit")
	}
}
