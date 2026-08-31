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

package callerauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/golang-jwt/jwt/v5"
)

const (
	claimsAdapterIssuer = "https://issuer.example.test"
	claimsAdapterSecret = "opaque-policy-token-secret"
)

func TestPolicyClaimsAccessTokenValidatorReturnsDetachedEvidence(t *testing.T) {
	t.Parallel()

	audiences := jwt.ClaimStrings{definitions.AudiencePolicyAPI, "another-resource"}
	claims := jwt.MapClaims{
		"aud":                      audiences,
		"client_id":                "policy-client",
		"iss":                      claimsAdapterIssuer,
		"scope":                    "  nauthilus:policy_evaluate\tnauthilus:policy_diagnostics  ",
		"sub":                      "token-subject",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
	underlying := &claimsTokenValidatorStub{claims: claims}
	validator := mustClaimsAccessTokenValidator(t, underlying, claimsAdapterIssuer)

	token, err := validator.ValidateAccessToken(context.Background(), []byte(claimsAdapterSecret))
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if underlying.token != claimsAdapterSecret {
		t.Fatalf("underlying token = %q", underlying.token)
	}

	if token.ClientID != "policy-client" || token.Issuer != claimsAdapterIssuer || token.Subject != "token-subject" {
		t.Fatalf("validated identities = client_id %q, issuer %q, subject %q", token.ClientID, token.Issuer, token.Subject)
	}

	if token.TokenType != definitions.TokenTypeAccessToken {
		t.Fatalf("token type = %q", token.TokenType)
	}

	wantAudiences := []string{definitions.AudiencePolicyAPI, "another-resource"}
	if !slices.Equal(token.Audiences, wantAudiences) {
		t.Fatalf("audiences = %v, want %v", token.Audiences, wantAudiences)
	}

	wantScopes := []string{"nauthilus:policy_evaluate", "nauthilus:policy_diagnostics"}
	if !slices.Equal(token.Scopes, wantScopes) {
		t.Fatalf("scopes = %v, want %v", token.Scopes, wantScopes)
	}

	audiences[0] = "mutated-source"
	claims["scope"] = "mutated-source"

	if !slices.Equal(token.Audiences, wantAudiences) || !slices.Equal(token.Scopes, wantScopes) {
		t.Fatalf("validated token retained mutable claim storage: audiences %v, scopes %v", token.Audiences, token.Scopes)
	}
}

func TestPolicyClaimsAccessTokenValidatorAcceptsOnlySupportedAudienceShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		audience  any
		want      []string
		wantError bool
	}{
		{name: "string", audience: definitions.AudiencePolicyAPI, want: []string{definitions.AudiencePolicyAPI}},
		{name: "string slice", audience: []string{definitions.AudiencePolicyAPI, "second"}, want: []string{definitions.AudiencePolicyAPI, "second"}},
		{name: "claim strings", audience: jwt.ClaimStrings{definitions.AudiencePolicyAPI, "second"}, want: []string{definitions.AudiencePolicyAPI, "second"}},
		{name: "interface slice", audience: []any{definitions.AudiencePolicyAPI, "second"}, want: []string{definitions.AudiencePolicyAPI, "second"}},
		{name: "mixed interface slice", audience: []any{definitions.AudiencePolicyAPI, 42}, wantError: true},
		{name: "empty string", audience: "", wantError: true},
		{name: "empty slice", audience: []string{}, wantError: true},
		{name: "unsupported type", audience: map[string]any{"resource": definitions.AudiencePolicyAPI}, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			claims := validPolicyClaims()
			claims["aud"] = test.audience
			validator := mustClaimsAccessTokenValidator(t, &claimsTokenValidatorStub{claims: claims}, claimsAdapterIssuer)

			token, err := validator.ValidateAccessToken(context.Background(), []byte(claimsAdapterSecret))
			if test.wantError {
				assertClaimsAdapterRejected(t, err)

				return
			}

			if err != nil {
				t.Fatalf("ValidateAccessToken() error = %v", err)
			}

			if !slices.Equal(token.Audiences, test.want) {
				t.Fatalf("audiences = %v, want %v", token.Audiences, test.want)
			}
		})
	}
}

func TestPolicyClaimsAccessTokenValidatorRejectsMissingFallbackAndMalformedClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{
			name: "missing client id ignores fallback identities",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "client_id")
				claims["sub"] = "fallback-subject"
				claims["azp"] = "fallback-authorized-party"
				claims["name"] = "fallback-display-name"
			},
		},
		{name: "non-string client id", mutate: func(claims jwt.MapClaims) { claims["client_id"] = []string{"policy-client"} }},
		{name: "wrong issuer", mutate: func(claims jwt.MapClaims) { claims["iss"] = "https://other.example.test" }},
		{name: "non-string issuer", mutate: func(claims jwt.MapClaims) { claims["iss"] = []string{claimsAdapterIssuer} }},
		{name: "wrong token type", mutate: func(claims jwt.MapClaims) { claims[definitions.ClaimTokenType] = definitions.TokenTypeIDToken }},
		{name: "non-string token type", mutate: func(claims jwt.MapClaims) { claims[definitions.ClaimTokenType] = true }},
		{name: "missing audience", mutate: func(claims jwt.MapClaims) { delete(claims, "aud") }},
		{name: "missing scope", mutate: func(claims jwt.MapClaims) { delete(claims, "scope") }},
		{name: "empty scope", mutate: func(claims jwt.MapClaims) { claims["scope"] = " \t " }},
		{name: "non-string scope", mutate: func(claims jwt.MapClaims) { claims["scope"] = []string{definitions.ScopePolicyEvaluate} }},
		{name: "non-string optional subject", mutate: func(claims jwt.MapClaims) { claims["sub"] = 42 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			claims := validPolicyClaims()
			test.mutate(claims)
			validator := mustClaimsAccessTokenValidator(t, &claimsTokenValidatorStub{claims: claims}, claimsAdapterIssuer)

			_, err := validator.ValidateAccessToken(context.Background(), []byte(claimsAdapterSecret))
			assertClaimsAdapterRejected(t, err)
		})
	}
}

func TestPolicyClaimsAccessTokenValidatorSanitizesUnderlyingFailure(t *testing.T) {
	t.Parallel()

	secretFailure := errors.New("validator exposed " + claimsAdapterSecret)
	validator := mustClaimsAccessTokenValidator(t, &claimsTokenValidatorStub{err: secretFailure}, claimsAdapterIssuer)

	_, err := validator.ValidateAccessToken(context.Background(), []byte(claimsAdapterSecret))
	assertClaimsAdapterRejected(t, err)

	if strings.Contains(err.Error(), claimsAdapterSecret) || strings.Contains(err.Error(), secretFailure.Error()) {
		t.Fatalf("error exposed secret validator detail: %v", err)
	}
}

func TestPolicyClaimsAccessTokenValidatorDoesNotMutateInputClaims(t *testing.T) {
	t.Parallel()

	audiences := []any{definitions.AudiencePolicyAPI, "second"}
	claims := validPolicyClaims()
	claims["aud"] = audiences
	validator := mustClaimsAccessTokenValidator(t, &claimsTokenValidatorStub{claims: claims}, claimsAdapterIssuer)

	if _, err := validator.ValidateAccessToken(context.Background(), []byte(claimsAdapterSecret)); err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if got, ok := claims["aud"].([]any); !ok || len(got) != 2 || got[0] != definitions.AudiencePolicyAPI || got[1] != "second" {
		t.Fatalf("input audience claim mutated: %#v", claims["aud"])
	}

	if claims["scope"] != definitions.ScopePolicyEvaluate {
		t.Fatalf("input scope claim mutated: %#v", claims["scope"])
	}
}

func TestPolicyClaimsAccessTokenValidatorRequiresConfiguration(t *testing.T) {
	t.Parallel()

	var typedNilUnderlying *claimsTokenValidatorStub

	tests := []struct {
		name       string
		underlying ClaimsTokenValidator
		issuer     string
	}{
		{name: "missing underlying", issuer: claimsAdapterIssuer},
		{name: "missing issuer", underlying: &claimsTokenValidatorStub{}},
		{name: "blank issuer", underlying: &claimsTokenValidatorStub{}, issuer: " \t "},
		{name: "non-exact issuer", underlying: &claimsTokenValidatorStub{}, issuer: " " + claimsAdapterIssuer},
		{name: "typed nil underlying", underlying: typedNilUnderlying, issuer: claimsAdapterIssuer},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator, err := NewClaimsAccessTokenValidator(test.underlying, test.issuer)
			if validator != nil || !errors.Is(err, ErrConfiguration) {
				t.Fatalf("NewClaimsAccessTokenValidator() = %T, %v", validator, err)
			}
		})
	}
}

type claimsTokenValidatorStub struct {
	claims jwt.MapClaims
	err    error
	token  string
}

// ValidateToken records the opaque token and returns configured issuer-validated claims.
func (v *claimsTokenValidatorStub) ValidateToken(_ context.Context, token string) (jwt.MapClaims, error) {
	v.token = token

	return v.claims, v.err
}

// validPolicyClaims returns one detached complete access-token claim map.
func validPolicyClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"aud":                      definitions.AudiencePolicyAPI,
		"client_id":                "policy-client",
		"iss":                      claimsAdapterIssuer,
		"scope":                    definitions.ScopePolicyEvaluate,
		"sub":                      "token-subject",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
}

// mustClaimsAccessTokenValidator constructs one adapter or stops the test.
func mustClaimsAccessTokenValidator(t testing.TB, underlying ClaimsTokenValidator, issuer string) AccessTokenValidator {
	t.Helper()

	validator, err := NewClaimsAccessTokenValidator(underlying, issuer)
	if err != nil {
		t.Fatalf("NewClaimsAccessTokenValidator() error = %v", err)
	}

	return validator
}

// assertClaimsAdapterRejected verifies one generic secret-free authentication failure.
func assertClaimsAdapterRejected(t testing.TB, err error) {
	t.Helper()

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error = %v, want ErrAuthentication", err)
	}
}
