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
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

type admissionDiagnosticsCase struct {
	name        string
	kind        string
	scopes      []string
	profile     bool
	internal    bool
	wantAllowed bool
}

func TestAdmissionBearerDiagnosticsAuthorization(t *testing.T) {
	t.Parallel()

	tests := []admissionDiagnosticsCase{
		{
			name:        "Bearer profile and scope",
			kind:        policy.CallerAuthenticationKindBearer,
			scopes:      []string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics},
			profile:     true,
			wantAllowed: true,
		},
		{
			name:    "Bearer profile without diagnostics scope",
			kind:    policy.CallerAuthenticationKindBearer,
			scopes:  []string{definitions.ScopePolicyEvaluate},
			profile: true,
		},
		{
			name:   "Bearer scope without profile permission",
			kind:   policy.CallerAuthenticationKindBearer,
			scopes: []string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics},
		},
		{
			name:    "Bearer diagnostics scope never substitutes evaluate",
			kind:    policy.CallerAuthenticationKindBearer,
			scopes:  []string{definitions.ScopePolicyDiagnostics},
			profile: true,
		},
	}

	assertAdmissionDiagnosticsCases(t, tests)
}

func TestAdmissionBasicAndInternalDiagnosticsAuthorization(t *testing.T) {
	t.Parallel()

	tests := []admissionDiagnosticsCase{
		{name: "Basic profile permission", kind: policy.CallerAuthenticationKindBasic, profile: true, wantAllowed: true},
		{name: "Basic defaults diagnostics off", kind: policy.CallerAuthenticationKindBasic},
		{
			name:        "internal profile permission",
			kind:        policy.CallerAuthenticationKindInternal,
			profile:     true,
			internal:    true,
			wantAllowed: true,
		},
		{
			name:     "internal defaults diagnostics off",
			kind:     policy.CallerAuthenticationKindInternal,
			internal: true,
		},
	}

	assertAdmissionDiagnosticsCases(t, tests)
}

// assertAdmissionDiagnosticsCases verifies profile and scope permission combinations.
func assertAdmissionDiagnosticsCases(t *testing.T, tests []admissionDiagnosticsCase) {
	t.Helper()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := admissionTestConfiguration(t, reference)
			configuration.Profiles[0].AuthenticationKinds = []string{test.kind}
			configuration.Profiles[0].Diagnostics = test.profile
			configuration.Profiles[0].Internal = test.internal
			credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

			prepared, err := Prepare(configuration, catalog, credentials)
			if err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}

			caller := admissionTestCaller(t, admissionTestCallerInput{
				authenticationKind: test.kind,
				scopes:             test.scopes,
				internal:           test.internal,
			})
			request := admissionTestRequest(t, caller, admissionTestRequestInput{
				target:             target,
				includeDiagnostics: true,
			})

			permit, err := prepared.Authority.Admit(context.Background(), caller, request)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("Admit() error = %v", err)
				}

				permit.Release()

				return
			}

			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("Admit() error = %v, want ErrPermissionDenied", err)
			}

			if permit != nil {
				t.Fatal("unauthorized diagnostics received a permit")
			}
		})
	}
}

func TestAdmissionOmittedDiagnosticsNeedsNoDiagnosticsPermission(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))

	for _, kind := range []string{
		policy.CallerAuthenticationKindBearer,
		policy.CallerAuthenticationKindBasic,
		policy.CallerAuthenticationKindInternal,
	} {
		t.Run(kind, func(t *testing.T) {
			configuration := admissionTestConfiguration(t, reference)
			configuration.Profiles[0].AuthenticationKinds = []string{kind}
			configuration.Profiles[0].Diagnostics = false
			configuration.Profiles[0].Internal = kind == policy.CallerAuthenticationKindInternal
			credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

			prepared, err := Prepare(configuration, catalog, credentials)
			if err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}

			scopes := []string(nil)
			if kind == policy.CallerAuthenticationKindBearer {
				scopes = []string{definitions.ScopePolicyEvaluate}
			}

			caller := admissionTestCaller(t, admissionTestCallerInput{
				authenticationKind: kind,
				scopes:             scopes,
				internal:           configuration.Profiles[0].Internal,
			})
			request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})
			permit := admissionTestPermit(t, prepared.Authority, caller, request)
			permit.Release()
		})
	}
}

func TestAdmissionBearerAlwaysRequiresEvaluateScope(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))
	caller := admissionTestCaller(t, admissionTestCallerInput{
		scopes: []string{definitions.ScopePolicyDiagnostics},
	})
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})

	permit, err := prepared.Authority.Admit(context.Background(), caller, request)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Admit() error = %v, want ErrPermissionDenied", err)
	}

	if permit != nil {
		t.Fatal("Bearer caller without evaluate scope received a permit")
	}
}

func TestEquivalentBasicAndBearerPrincipalRetainDistinctKinds(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	prepared := admissionTestPreparation(t, admissionTestConfiguration(t, reference))

	tests := []struct {
		name   string
		kind   string
		scopes []string
	}{
		{
			name:   "Bearer",
			kind:   policy.CallerAuthenticationKindBearer,
			scopes: []string{definitions.ScopePolicyEvaluate},
		},
		{
			name: "Basic",
			kind: policy.CallerAuthenticationKindBasic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caller := admissionTestCaller(t, admissionTestCallerInput{
				authenticationKind: test.kind,
				scopes:             test.scopes,
			})
			request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})

			permit := admissionTestPermit(t, prepared.Authority, caller, request)
			defer permit.Release()

			fact, exists := permit.Facts().Get(decision.FactCallerAuthenticationKind)
			if !exists {
				t.Fatal("caller authentication kind fact missing")
			}

			kind, ok := fact.Value().StringValue()
			if !ok || kind != test.kind {
				t.Fatalf("authentication kind fact = %q/%t, want %q", kind, ok, test.kind)
			}
		})
	}
}
