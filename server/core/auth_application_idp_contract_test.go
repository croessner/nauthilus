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

package core

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/report"
)

func TestAuthIDPContextOwnsDetachedBoundedValues(t *testing.T) {
	requestedScopes := []string{"openid", "profile"}
	attributeNames := []string{"displayName", "entryUUID"}
	backendRef := RemoteBackendRef{
		Type: "ldap", Name: "primary", Protocol: "oidc",
		Authority: "authority.example.test", OpaqueToken: "opaque-affinity",
	}

	idpContext := NewAuthIDPContext(
		IDPRequestContext{
			GrantType: "authorization_code", RedirectURI: "https://client.example.test/callback",
			RequestedScopes: requestedScopes, MFACompleted: true, MFAMethod: "webauthn",
		},
		&IdentityAttributeRequest{
			Names: attributeNames, IncludeStandardIdentity: true, IncludeGroups: true, ReportMissing: true,
		},
		backendRef,
	)

	requestedScopes[0] = "mutated-source"
	attributeNames[0] = "mutated-source"

	input := AuthInput{IDP: idpContext}
	normalized := normalizeAuthInput(input, AuthModeLookupIdentity)
	input.IDP.Request.RequestedScopes[0] = "mutated-input"
	input.IDP.IdentityAttributeRequest.Names[0] = "mutated-input"

	if got := normalized.IDP.Request.RequestedScopes; !reflect.DeepEqual(got, []string{"openid", "profile"}) {
		t.Fatalf("normalized IDP scopes = %v, want detached original values", got)
	}

	if got := normalized.IDP.IdentityAttributeRequest.Names; !reflect.DeepEqual(got, []string{"displayName", "entryUUID"}) {
		t.Fatalf("normalized identity attributes = %v, want detached original values", got)
	}

	if normalized.IDP.ExistingBackendRef != backendRef {
		t.Fatalf("normalized backend reference = %#v, want %#v", normalized.IDP.ExistingBackendRef, backendRef)
	}
}

func TestAuthIDPContextContainsNoBrowserStateCarrier(t *testing.T) {
	typeOf := reflect.TypeOf(AuthIDPContext{})
	want := map[string]reflect.Type{
		"Request":                  reflect.TypeOf(AuthIDPRequestContext{}),
		"IdentityAttributeRequest": reflect.TypeOf((*IdentityAttributeRequest)(nil)),
		"ExistingBackendRef":       reflect.TypeOf(RemoteBackendRef{}),
	}

	if typeOf.NumField() != len(want) {
		t.Fatalf("AuthIDPContext field count = %d, want exact bounded fields %v", typeOf.NumField(), want)
	}

	for index := range typeOf.NumField() {
		field := typeOf.Field(index)
		wantType, ok := want[field.Name]

		if !ok {
			t.Fatalf("AuthIDPContext contains browser/protocol-state field %q", field.Name)
		}

		if field.Type != wantType {
			t.Fatalf("AuthIDPContext.%s type = %v, want %v", field.Name, field.Type, wantType)
		}
	}

	requestType := reflect.TypeOf(AuthIDPRequestContext{})
	requestFields := map[string]reflect.Type{
		"GrantType":       reflect.TypeOf(""),
		"RedirectURI":     reflect.TypeOf(""),
		"RequestedScopes": reflect.TypeOf([]string(nil)),
	}

	if requestType.NumField() != len(requestFields) {
		t.Fatalf("AuthIDPRequestContext field count = %d, want exact protocol facts %v", requestType.NumField(), requestFields)
	}

	for index := range requestType.NumField() {
		field := requestType.Field(index)
		wantType, ok := requestFields[field.Name]

		if !ok || field.Type != wantType {
			t.Fatalf("AuthIDPRequestContext contains non-protocol field %q of type %v", field.Name, field.Type)
		}
	}
}

func TestAuthIDPContextDoesNotEnterGenericFacts(t *testing.T) {
	builder, err := newAuthnFactBuilder()
	if err != nil {
		t.Fatalf("newAuthnFactBuilder() error = %v", err)
	}

	base := AuthInput{
		Credentials: NewCredentials(WithUsername("alice@example.test")),
		Context: NewAuthContext(
			WithProtocol(definitions.ProtoOIDC),
			WithOIDCCID("client-one"),
		),
		Mode: AuthModeLookupIdentity, Service: definitions.ServIDP,
	}
	withIDP := base
	withIDP.IDP = NewAuthIDPContext(
		IDPRequestContext{
			GrantType: "authorization_code", RequestedScopes: []string{"openid", "profile"},
			MFACompleted: true, MFAMethod: "webauthn",
		},
		&IdentityAttributeRequest{Names: []string{"displayName"}, IncludeStandardIdentity: true},
		RemoteBackendRef{OpaqueToken: "must-not-become-a-fact"},
	)

	baseAttributes, err := builder.RequestAttributes(base)
	if err != nil {
		t.Fatalf("base RequestAttributes() error = %v", err)
	}

	idpAttributes, err := builder.RequestAttributes(withIDP)
	if err != nil {
		t.Fatalf("IDP RequestAttributes() error = %v", err)
	}

	if !reflect.DeepEqual(idpAttributes, baseAttributes) {
		t.Fatalf("IDP application context changed generic request facts\nbase: %#v\nidp:  %#v", baseAttributes, idpAttributes)
	}

	emptyFacts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	result := authnApplicationResult{auth: &AuthOutcome{Decision: AuthDecisionOK}}

	baseFacts, err := builder.Build(base, policy.OperationLookupIdentity, result, emptyFacts)
	if err != nil {
		t.Fatalf("base Build() error = %v", err)
	}

	idpFacts, err := builder.Build(withIDP, policy.OperationLookupIdentity, result, emptyFacts)
	if err != nil {
		t.Fatalf("IDP Build() error = %v", err)
	}

	if !reflect.DeepEqual(idpFacts.Facts(), baseFacts.Facts()) {
		t.Fatalf("IDP application context changed generic host/result facts\nbase: %#v\nidp:  %#v", baseFacts.Facts(), idpFacts.Facts())
	}
}

func TestLegacyAuthApplicationAppliesDetachedIDPContext(t *testing.T) {
	idpContext := NewAuthIDPContext(
		IDPRequestContext{
			GrantType:       "urn:ietf:params:oauth:grant-type:device_code",
			RequestedScopes: []string{"openid", "email"},
			MFACompleted:    true,
			MFAMethod:       definitions.MFAMethodWebAuthn,
		},
		&IdentityAttributeRequest{Names: []string{"mail"}, IncludeStandardIdentity: true},
		RemoteBackendRef{Type: "remote", OpaqueToken: "authority-handle"},
	)
	auth := &AuthState{}

	applyAuthIDPContext(auth, idpContext)
	idpContext.Request.RequestedScopes[0] = "mutated"
	idpContext.IdentityAttributeRequest.Names[0] = "mutated"

	if auth.Runtime.IDPContext == nil ||
		!reflect.DeepEqual(auth.Runtime.IDPContext.RequestedScopes, []string{"openid", "email"}) {
		t.Fatalf("AuthState IDP context = %#v, want detached scopes", auth.Runtime.IDPContext)
	}

	if auth.Runtime.IdentityAttributeRequest == nil ||
		!reflect.DeepEqual(auth.Runtime.IdentityAttributeRequest.Names, []string{"mail"}) {
		t.Fatalf("AuthState identity attribute request = %#v, want detached names", auth.Runtime.IdentityAttributeRequest)
	}

	if got := auth.Runtime.RemoteBackendRef.OpaqueToken; got != "authority-handle" {
		t.Fatalf("AuthState backend reference token = %q, want authority-handle", got)
	}

	if auth.Runtime.IDPContext.MFACompleted || auth.Runtime.IDPContext.MFAMethod != "" {
		t.Fatalf("generic host retained browser MFA state: %#v", auth.Runtime.IDPContext)
	}
}

func TestAuthOutcomeCapturesCompleteDetachedIDPProjection(t *testing.T) {
	auth, ctx, _ := newCaptureWriterTestState(t, "/api/v1/auth/json", NewCaptureResponseWriter(nil))
	auth.SetAccount("alice@example.test")
	auth.Runtime.AccountField = "uid"
	auth.Runtime.DisplayNameField = "displayName"
	auth.Runtime.UniqueUserIDField = "entryUUID"
	auth.Runtime.TOTPSecretField = "totpSecret"
	auth.Runtime.TOTPRecoveryField = "recoveryCodes"
	auth.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	auth.Runtime.BackendName = "primary"
	auth.Runtime.RemoteBackendRef = RemoteBackendRef{
		Type: "ldap", Name: "primary", Protocol: "oidc",
		Authority: "authority.example.test", OpaqueToken: "authority-handle",
	}
	auth.ReplaceAllAttributes(bktype.AttributeMapping{
		"uid":         {"alice@example.test"},
		"displayName": {"Alice Example"},
		"entryUUID":   {"identity-42"},
	})
	auth.SetResolvedGroups(
		[]string{"employees"},
		[]string{"cn=employees,dc=example,dc=test"},
	)
	storeConfiguredAuthDecision(ctx, &report.FinalDecision{
		PolicyName: "idp-subject-deny", Stage: policy.StageAuthDecision,
		Effect: policy.DecisionDeny, OutcomeMarker: "auth.outcome.subject_denied",
	})

	outcome := authOutcomeFromState(
		ctx, auth, AuthDecisionTempFail, string(authFSMStateAuthTempFail),
		"temporary failure", http.StatusInternalServerError, AuthResponseSettings{},
	)
	if outcome.DisplayName != "Alice Example" || outcome.UniqueUserID != "identity-42" {
		t.Fatalf("identity values = %q/%q, want Alice Example/identity-42", outcome.DisplayName, outcome.UniqueUserID)
	}

	if outcome.BackendName != "primary" || outcome.RemoteBackendRef != auth.Runtime.RemoteBackendRef {
		t.Fatalf("backend projection = %q/%#v, want primary/%#v", outcome.BackendName, outcome.RemoteBackendRef, auth.Runtime.RemoteBackendRef)
	}

	if !outcome.PolicyTerminal {
		t.Fatal("configured terminal policy decision was not classified")
	}

	if outcome.Decision != AuthDecisionTempFail {
		t.Fatalf("decision = %q, want distinct tempfail", outcome.Decision)
	}

	captured := capturedAuthOutcomeFromAuthOutcome(outcome, CapturedAuthDecisionTempFail)
	roundTrip := authOutcomeFromCaptured(captured)
	roundTrip.Attributes["displayName"][0] = "mutated"
	roundTrip.Groups[0] = "mutated"

	if got := captured.Attributes["displayName"][0]; got != "Alice Example" {
		t.Fatalf("captured attributes aliased round-trip outcome: %v", got)
	}

	if got := captured.Groups[0]; got != "employees" {
		t.Fatalf("captured groups aliased round-trip outcome: %v", got)
	}
}

func TestAuthOutcomeClassifiesIDPDelayedResponseAndPolicyTerminal(t *testing.T) {
	tests := []struct {
		final       *report.FinalDecision
		name        string
		decision    AuthDecision
		wantDelayed bool
		wantPolicy  bool
	}{
		{
			name: "ordinary unconfigured password failure", decision: AuthDecisionFail,
			wantDelayed: true,
		},
		{
			name: "configured ordinary password fallback", decision: AuthDecisionFail,
			final: &report.FinalDecision{
				PolicyName: "standard_auth_failure", Stage: policy.StageAuthDecision,
				Effect: policy.DecisionDeny, OutcomeMarker: policy.OutcomeMarkerAuthFailure,
				ResponseMarker: policy.ResponseMarkerFail,
			},
			wantDelayed: true, wantPolicy: true,
		},
		{
			name: "configured subject denial", decision: AuthDecisionFail,
			final: &report.FinalDecision{
				PolicyName: "idp-subject-deny", Stage: policy.StageAuthDecision,
				Effect: policy.DecisionDeny, OutcomeMarker: "auth.outcome.subject_denied",
			},
			wantPolicy: true,
		},
		{
			name: "temporary failure", decision: AuthDecisionTempFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth, ctx, _ := newCaptureWriterTestState(t, "/login", NewCaptureResponseWriter(nil))
			auth.Request.Service = definitions.ServIDP
			auth.SetMethod(definitions.AuthMethodPassword)
			auth.SetNoAuth(false)

			if test.final != nil {
				storeConfiguredAuthDecision(ctx, test.final)
			}

			outcome := authOutcomeFromState(
				ctx, auth, test.decision, authTerminalState(test.decision), "", http.StatusUnauthorized,
				AuthResponseSettings{},
			)
			if outcome.DelayedResponseEligible != test.wantDelayed || outcome.PolicyTerminal != test.wantPolicy {
				t.Fatalf(
					"delayed/policy classification = %t/%t, want %t/%t",
					outcome.DelayedResponseEligible, outcome.PolicyTerminal, test.wantDelayed, test.wantPolicy,
				)
			}
		})
	}
}

func TestAuthOutcomeConfiguredFallbackStillRequiresIDPPasswordRequest(t *testing.T) {
	tests := []struct {
		mutate func(*AuthState)
		name   string
	}{
		{name: "non-IDP service", mutate: func(auth *AuthState) { auth.Request.Service = definitions.ServJSON }},
		{name: "non-password method", mutate: func(auth *AuthState) { auth.SetMethod(definitions.MFAMethodWebAuthn) }},
		{name: "no-auth request", mutate: func(auth *AuthState) { auth.SetNoAuth(true) }},
		{name: "list-accounts request", mutate: func(auth *AuthState) { auth.Request.ListAccounts = true }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth, ctx, _ := newCaptureWriterTestState(t, "/login", NewCaptureResponseWriter(nil))
			auth.Request.Service = definitions.ServIDP
			auth.SetMethod(definitions.AuthMethodPassword)
			test.mutate(auth)
			storeConfiguredAuthDecision(ctx, &report.FinalDecision{
				PolicyName: "standard_auth_failure", Stage: policy.StageAuthDecision,
				Effect: policy.DecisionDeny, OutcomeMarker: policy.OutcomeMarkerAuthFailure,
				ResponseMarker: policy.ResponseMarkerFail,
			})

			outcome := authOutcomeFromState(
				ctx, auth, AuthDecisionFail, authTerminalState(AuthDecisionFail), "", http.StatusUnauthorized,
				AuthResponseSettings{},
			)
			if outcome.DelayedResponseEligible || !outcome.PolicyTerminal {
				t.Fatalf(
					"delayed/policy classification = %t/%t, want false/true",
					outcome.DelayedResponseEligible, outcome.PolicyTerminal,
				)
			}
		})
	}
}

func TestAuthnCandidateTempFailClearsIDPDelayedEligibility(t *testing.T) {
	current := authnApplicationResult{
		auth: &AuthOutcome{
			Decision:                AuthDecisionFail,
			DelayedResponseEligible: true,
		},
	}

	result, err := current.mapEffect(decision.EffectIndeterminate)
	if err != nil {
		t.Fatalf("mapEffect() error = %v", err)
	}

	if result.auth == nil || result.auth.Decision != AuthDecisionTempFail {
		t.Fatalf("mapped outcome = %#v, want tempfail", result.auth)
	}

	if result.auth.DelayedResponseEligible {
		t.Fatal("candidate tempfail retained delayed-response eligibility")
	}

	if !result.auth.PolicyTerminal {
		t.Fatal("candidate tempfail was not classified as policy-terminal")
	}
}

func TestAuthnCandidateDenyClearsUnprovenIDPDelayedEligibility(t *testing.T) {
	current := authnApplicationResult{
		auth: &AuthOutcome{
			Decision:                AuthDecisionFail,
			DelayedResponseEligible: true,
		},
	}

	result, err := current.mapEffect(decision.EffectDeny)
	if err != nil {
		t.Fatalf("mapEffect() error = %v", err)
	}

	if result.auth == nil || result.auth.Decision != AuthDecisionFail || !result.auth.PolicyTerminal {
		t.Fatalf("mapped outcome = %#v, want policy-terminal failure", result.auth)
	}

	if result.auth.DelayedResponseEligible {
		t.Fatal("candidate deny retained unproven delayed-response eligibility")
	}
}

func TestAuthnCandidateEarlyTerminalResultClassifiesPolicyDecision(t *testing.T) {
	for _, effect := range []decision.Effect{decision.EffectDeny, decision.EffectIndeterminate} {
		result, err := newAuthnTerminalResult(policy.OperationAuthenticate, effect)
		if err != nil {
			t.Fatalf("newAuthnTerminalResult(%q) error = %v", effect, err)
		}

		if result.auth == nil || !result.auth.PolicyTerminal {
			t.Fatalf("newAuthnTerminalResult(%q) = %#v, want policy-terminal auth outcome", effect, result.auth)
		}

		if result.auth.DelayedResponseEligible {
			t.Fatalf("newAuthnTerminalResult(%q) retained delayed-response eligibility", effect)
		}
	}
}
