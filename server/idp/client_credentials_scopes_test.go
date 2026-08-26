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

package idp

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
)

type clientCredentialsScopeCase struct {
	wantError error
	name      string
	scopes    []string
	want      clientCredentialsResource
}

type clientCredentialsScopeTransitionCase struct {
	wantError error
	name      string
	requested []string
	effective []string
}

func TestClassifyClientCredentialsScopes(t *testing.T) {
	t.Parallel()

	for _, testCase := range clientCredentialsScopeCases() {
		t.Run(testCase.name, testCase.run)
	}
}

func TestValidateClientCredentialsScopeTransition(t *testing.T) {
	t.Parallel()

	tests := []clientCredentialsScopeTransitionCase{
		{name: "policy family retained", requested: []string{definitions.ScopePolicyEvaluate}, effective: []string{definitions.ScopePolicyEvaluate}},
		{name: "backchannel family retained", requested: []string{definitions.ScopeAuthenticate}, effective: []string{definitions.ScopeAuthenticate}},
		{name: "empty request may receive implied policy scope", effective: []string{definitions.ScopePolicyEvaluate}},
		{name: "filtered policy family is rejected", requested: []string{definitions.ScopePolicyEvaluate}, wantError: ErrClientCredentialsResourceScopeMismatch},
		{name: "requested backchannel cannot become policy", requested: []string{definitions.ScopeAuthenticate}, effective: []string{definitions.ScopePolicyEvaluate}, wantError: ErrClientCredentialsResourceScopeMismatch},
		{name: "effective mixed family is rejected", requested: []string{definitions.ScopePolicyEvaluate}, effective: []string{definitions.ScopePolicyEvaluate, definitions.ScopeAuthenticate}, wantError: ErrClientCredentialsMixedResourceScopes},
		{name: "raw identity scope is rejected", requested: []string{definitions.ScopeOpenID}, wantError: ErrClientCredentialsOpenIDScope},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, testCase.run)
	}
}

// clientCredentialsScopeCases returns the complete resource-family classification contract.
func clientCredentialsScopeCases() []clientCredentialsScopeCase {
	return []clientCredentialsScopeCase{
		{name: "empty retains backchannel default", want: clientCredentialsResourceBackchannel},
		{
			name:   "blank entries retain backchannel default",
			scopes: []string{"", " ", "\t"},
			want:   clientCredentialsResourceBackchannel,
		},
		{
			name:   "backchannel scopes",
			scopes: []string{definitions.ScopeAuthenticate, definitions.ScopeSecurity},
			want:   clientCredentialsResourceBackchannel,
		},
		{
			name:   "duplicate backchannel scopes",
			scopes: []string{definitions.ScopeAuthenticate, definitions.ScopeAuthenticate},
			want:   clientCredentialsResourceBackchannel,
		},
		{
			name:   "custom scope remains backchannel",
			scopes: []string{"api.read"},
			want:   clientCredentialsResourceBackchannel,
		},
		{
			name:   "policy evaluate",
			scopes: []string{definitions.ScopePolicyEvaluate},
			want:   clientCredentialsResourcePolicy,
		},
		{
			name:   "policy scope surrounding whitespace",
			scopes: []string{" \t" + definitions.ScopePolicyEvaluate + "\n"},
			want:   clientCredentialsResourcePolicy,
		},
		{
			name:   "policy evaluate and diagnostics",
			scopes: []string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics},
			want:   clientCredentialsResourcePolicy,
		},
		{
			name:   "duplicate policy scopes",
			scopes: []string{definitions.ScopePolicyDiagnostics, definitions.ScopePolicyDiagnostics},
			want:   clientCredentialsResourcePolicy,
		},
		{
			name:      "mixed resource families",
			scopes:    []string{definitions.ScopePolicyEvaluate, definitions.ScopeAuthenticate},
			wantError: ErrClientCredentialsMixedResourceScopes,
		},
		{
			name:      "openid identity scope",
			scopes:    []string{definitions.ScopeOpenID},
			wantError: ErrClientCredentialsOpenIDScope,
		},
	}
}

// run verifies one scope set and its resource audience.
func (testCase clientCredentialsScopeCase) run(t *testing.T) {
	t.Parallel()

	resource, err := classifyClientCredentialsScopes(testCase.scopes)

	if testCase.wantError != nil {
		if !errors.Is(err, testCase.wantError) {
			t.Fatalf("classifyClientCredentialsScopes() error = %v, want %v", err, testCase.wantError)
		}

		return
	}

	if err != nil {
		t.Fatalf("classifyClientCredentialsScopes() error = %v", err)
	}

	if resource != testCase.want {
		t.Fatalf("classifyClientCredentialsScopes() = %v, want %v", resource, testCase.want)
	}

	wantAudience := definitions.AudienceBackchannelAPI

	if testCase.want == clientCredentialsResourcePolicy {
		wantAudience = definitions.AudiencePolicyAPI
	}

	if resource.audience() != wantAudience {
		t.Fatalf("resource audience = %q, want %q", resource.audience(), wantAudience)
	}
}

// run verifies one requested-to-effective resource-family transition.
func (testCase clientCredentialsScopeTransitionCase) run(t *testing.T) {
	t.Parallel()

	err := ValidateClientCredentialsScopeTransition(testCase.requested, testCase.effective)
	if !errors.Is(err, testCase.wantError) {
		t.Fatalf("ValidateClientCredentialsScopeTransition() error = %v, want %v", err, testCase.wantError)
	}
}
