// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
)

func TestNewIDPSpecializedAuthStateMaterializesDetachedSuccessfulOutcome(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/webauthn/finish", nil)
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	ctx.Set(definitions.CtxGUIDKey, "idp-specialized-guid")

	input := newIDPSpecializedAuthInput()
	outcome := newIDPSpecializedAuthOutcome()

	auth, err := NewIDPSpecializedAuthState(ctx, setupAuthDeps(), input, outcome)
	if err != nil {
		t.Fatalf("NewIDPSpecializedAuthState() error = %v", err)
	}

	assertIDPSpecializedAuthState(t, auth, outcome)

	input.IDP.Request.RequestedScopes[0] = "mutated"
	input.IDP.IdentityAttributeRequest.Names[0] = "mutated"
	outcome.Attributes["displayName"][0] = "mutated"
	outcome.Groups[0] = "mutated"

	if got := auth.Runtime.IDPContext.RequestedScopes[0]; got != "openid" {
		t.Fatalf("specialized IDP scopes aliased input: %q", got)
	}

	if got := auth.Runtime.IdentityAttributeRequest.Names[0]; got != "displayName" {
		t.Fatalf("specialized attribute request aliased input: %q", got)
	}

	if got := auth.GetDisplayName(); got != "Alice Example" {
		t.Fatalf("specialized attributes aliased outcome: %q", got)
	}

	if got := auth.GetGroups(); !reflect.DeepEqual(got, []string{"employees"}) {
		t.Fatalf("specialized groups aliased outcome: %v", got)
	}

	if !auth.GetPassword().IsZero() {
		t.Fatal("specialized AuthState retained a password")
	}

	if ctx.IsAborted() || len(ctx.Errors) != 0 || recorder.Body.Len() != 0 {
		t.Fatalf("specialized materialization changed HTTP state: aborted=%t errors=%v body=%q", ctx.IsAborted(), ctx.Errors, recorder.Body.String())
	}
}

func TestNewIDPSpecializedAuthStateMaterializesTransportNeutralOutcome(t *testing.T) {
	setupMinimalTestConfig(t)

	input := newIDPSpecializedAuthInput()
	input.Service = definitions.ServGRPC
	input.Context.Transport = AuthTransportContext{
		Kind:       "grpc",
		Listener:   "grpc.authority",
		GRPCMethod: "/nauthilus.identity.v1.IdentityBackendService/GetMFAState",
		Protected:  true,
	}
	outcome := newIDPSpecializedAuthOutcome()

	auth, err := NewIDPSpecializedAuthState(nil, setupAuthDeps(), input, outcome)
	if err != nil {
		t.Fatalf("NewIDPSpecializedAuthState(nil) error = %v", err)
	}

	assertIDPSpecializedAuthState(t, auth, outcome)

	if auth.Request.Service != definitions.ServGRPC {
		t.Fatalf("specialized service = %q, want %q", auth.Request.Service, definitions.ServGRPC)
	}

	if auth.Request.Transport != input.Context.Transport {
		t.Fatalf("specialized transport = %#v, want %#v", auth.Request.Transport, input.Context.Transport)
	}

	if auth.Request.HTTPClientContext == nil || auth.Request.HTTPClientRequest == nil {
		t.Fatal("transport-neutral specialized state did not retain isolated compatibility context")
	}
}

func TestNewIDPSpecializedAuthStateRejectsNonSuccessfulOutcome(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	ctx.Request = httptest.NewRequest(http.MethodGet, "/login/mfa", nil)

	for _, outcome := range []*AuthOutcome{nil, {Decision: AuthDecisionFail}, {Decision: AuthDecisionTempFail}} {
		if _, err := NewIDPSpecializedAuthState(ctx, setupAuthDeps(), AuthInput{}, outcome); err == nil {
			t.Fatalf("NewIDPSpecializedAuthState(%#v) error = nil, want rejection", outcome)
		}
	}
}

func TestIDPSpecializedAuthStateCannotInvokeAuthenticationOrPolicy(t *testing.T) {
	parsed, err := parser.ParseFile(
		token.NewFileSet(), "idp_specialized_auth_state.go", nil, parser.SkipObjectResolution,
	)
	if err != nil {
		t.Fatalf("parse specialized state materializer: %v", err)
	}

	forbiddenCalls := map[string]struct{}{
		"FinishSetup": {}, "HandlePassword": {}, "HandleAuthentication": {}, "PreproccessAuthRequest": {},
		"ApplyConfiguredPreAuthDecision": {}, "ApplyConfiguredPreAuthControl": {}, "Evaluate": {},
		"AuthOK": {}, "AuthFail": {}, "AuthTempFail": {},
	}
	foundFunction := false

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}

		if function.Name.Name == "NewIDPSpecializedAuthState" {
			foundFunction = true
		}

		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			name := authnCandidateCallName(call.Fun)
			if _, forbidden := forbiddenCalls[name]; forbidden {
				t.Fatalf("%s calls forbidden authentication/policy function %s", function.Name.Name, name)
			}

			return true
		})
	}

	if !foundFunction {
		t.Fatal("NewIDPSpecializedAuthState function not found")
	}
}

// newIDPSpecializedAuthInput returns detached application input for specialized-state tests.
func newIDPSpecializedAuthInput() AuthInput {
	return AuthInput{
		Credentials: NewCredentials(WithUsername("alice@example.test")),
		Context: NewAuthContext(
			WithProtocol(definitions.ProtoOIDC),
			WithOIDCCID("client-one"),
			WithRequestMetadata(map[string][]string{"x-request-id": {"request-42"}}),
		),
		CorrelationID: "idp-specialized-guid",
		Mode:          AuthModeLookupIdentity,
		Service:       definitions.ServIDP,
		IDP: NewAuthIDPContext(
			IDPRequestContext{
				GrantType: "authorization_code", RequestedScopes: []string{"openid"},
				MFACompleted: true, MFAMethod: definitions.MFAMethodWebAuthn,
			},
			&IdentityAttributeRequest{Names: []string{"displayName", "entryUUID"}, IncludeStandardIdentity: true},
			RemoteBackendRef{Type: "ldap", Name: "existing", OpaqueToken: "existing-handle"},
		),
	}
}

// newIDPSpecializedAuthOutcome returns successful identity and backend data for specialized-state tests.
func newIDPSpecializedAuthOutcome() *AuthOutcome {
	return &AuthOutcome{
		Attributes: bktype.AttributeMapping{
			"uid":         {"alice@example.test"},
			"displayName": {"Alice Example"},
			"entryUUID":   {"identity-42"},
		},
		Decision:     AuthDecisionOK,
		Account:      "alice@example.test",
		AccountField: "uid", DisplayName: "Alice Example", DisplayNameField: "displayName",
		UniqueUserID: "identity-42", UniqueUserIDField: "entryUUID",
		TOTPSecretField: "totpSecret", TOTPRecoveryField: "recoveryCodes",
		Groups:                  []string{"employees"},
		GroupDistinguishedNames: []string{"cn=employees,dc=example,dc=test"},
		Protocol:                definitions.ProtoOIDC,
		Backend:                 definitions.BackendLDAP,
		BackendName:             "primary",
		RemoteBackendRef: RemoteBackendRef{
			Type: "ldap", Name: "primary", Protocol: "oidc",
			Authority: "authority.example.test", OpaqueToken: "returned-handle",
		},
	}
}

// assertIDPSpecializedAuthState verifies the identity/backend projection needed by factor operations.
func assertIDPSpecializedAuthState(t *testing.T, auth *AuthState, outcome *AuthOutcome) {
	t.Helper()

	if auth == nil {
		t.Fatal("specialized AuthState is nil")
	}

	assertIDPSpecializedIdentity(t, auth, outcome)
	assertIDPSpecializedBackend(t, auth, outcome)
	assertIDPSpecializedRuntime(t, auth)
}

// assertIDPSpecializedIdentity verifies the detached account and field projection.
func assertIDPSpecializedIdentity(t *testing.T, auth *AuthState, outcome *AuthOutcome) {
	t.Helper()

	if auth.GetUsername() != outcome.Account || auth.GetAccount() != outcome.Account {
		t.Fatalf("specialized identity = %q/%q, want %q", auth.GetUsername(), auth.GetAccount(), outcome.Account)
	}

	if auth.Runtime.AccountField != "uid" || auth.Runtime.DisplayNameField != "displayName" ||
		auth.Runtime.UniqueUserIDField != "entryUUID" || auth.Runtime.TOTPSecretField != "totpSecret" ||
		auth.Runtime.TOTPRecoveryField != "recoveryCodes" {
		t.Fatalf("specialized field mapping = %#v", auth.Runtime)
	}
}

// assertIDPSpecializedBackend verifies protocol and authoritative backend projection.
func assertIDPSpecializedBackend(t *testing.T, auth *AuthState, outcome *AuthOutcome) {
	t.Helper()

	if auth.GetProtocol().Get() != definitions.ProtoOIDC || auth.Request.OIDCCID != "client-one" {
		t.Fatalf("specialized protocol/client = %q/%q", auth.GetProtocol().Get(), auth.Request.OIDCCID)
	}

	if auth.Runtime.SourcePassDBBackend != definitions.BackendLDAP ||
		auth.Runtime.UsedPassDBBackend != definitions.BackendLDAP || auth.Runtime.BackendName != "primary" {
		t.Fatalf(
			"specialized backend = %v/%v/%q",
			auth.Runtime.SourcePassDBBackend, auth.Runtime.UsedPassDBBackend, auth.Runtime.BackendName,
		)
	}

	if auth.Runtime.RemoteBackendRef != outcome.RemoteBackendRef {
		t.Fatalf("specialized backend reference = %#v, want %#v", auth.Runtime.RemoteBackendRef, outcome.RemoteBackendRef)
	}
}

// assertIDPSpecializedRuntime verifies runtime readiness and detached request metadata.
func assertIDPSpecializedRuntime(t *testing.T, auth *AuthState) {
	t.Helper()

	if !auth.Runtime.Authenticated || !auth.Runtime.UserFound || !auth.Runtime.Authorized || auth.Runtime.Context == nil {
		t.Fatalf(
			"specialized runtime flags/context = authenticated:%t found:%t authorized:%t context:%p",
			auth.Runtime.Authenticated, auth.Runtime.UserFound, auth.Runtime.Authorized, auth.Runtime.Context,
		)
	}

	if auth.Request.RequestMetadata["x-request-id"][0] != "request-42" {
		t.Fatalf("specialized request metadata = %#v", auth.Request.RequestMetadata)
	}

	if auth.Runtime.IDPContext == nil || auth.Runtime.IDPContext.MFACompleted || auth.Runtime.IDPContext.MFAMethod != "" {
		t.Fatalf("specialized state retained browser MFA state: %#v", auth.Runtime.IDPContext)
	}

	protocolName := ""
	if auth.Request.Protocol != nil {
		protocolName = auth.Request.Protocol.Get()
	}

	if protocolName != definitions.ProtoOIDC {
		t.Fatalf("specialized protocol = %q", protocolName)
	}
}
