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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const (
	applicationBoundaryClientID       = "application-client"
	applicationBoundarySAMLEntityID   = "https://sp.example.test/metadata"
	applicationBoundaryRequestID      = "application-request-42"
	applicationBoundaryCookieMarker   = "browser-cookie-aggregate"
	applicationBoundaryFlowMarker     = "browser-flow-aggregate"
	applicationBoundarySessionMarker  = "browser-session-aggregate"
	applicationBoundaryCeremonyMarker = "browser-ceremony-aggregate"
	applicationBoundaryPeer           = "192.0.2.44"
	applicationBoundaryPassword       = "application-password"
)

type applicationBoundaryResult struct {
	outcome *core.AuthOutcome
	err     error
}

type recordingIDPAuthApplication struct {
	authenticateResults []applicationBoundaryResult
	lookupResults       []applicationBoundaryResult
	authenticateInputs  []core.AuthInput
	lookupInputs        []core.AuthInput
	mutateInput         bool
}

type expectedIDPApplicationInput struct {
	attributeRequest *core.IdentityAttributeRequest
	backendRef       core.RemoteBackendRef
	request          core.IDPRequestContext
	transport        core.AuthTransportContext
	entryPoint       core.AuthnEntryPoint
	protocol         string
	username         string
	oidcClientID     string
	samlEntityID     string
	wantPassword     bool
}

type applicationAuthenticationEntryCase struct {
	name         string
	route        string
	oidcClientID string
	samlEntityID string
	protocol     string
	grantType    string
	entryPoint   core.AuthnEntryPoint
}

func TestNauthilusIDPAuthenticationUsesExactApplicationEntry(t *testing.T) {
	for _, testCase := range applicationAuthenticationEntryCases() {
		t.Run(testCase.name, testCase.run)
	}
}

// applicationAuthenticationEntryCases returns every supported IdP authentication entry contract.
func applicationAuthenticationEntryCases() []applicationAuthenticationEntryCase {
	return []applicationAuthenticationEntryCase{
		{
			name: "OIDC authorization code", route: "/oidc/authorize",
			oidcClientID: applicationBoundaryClientID, protocol: definitions.ProtoOIDC,
			grantType: definitions.OIDCFlowAuthorizationCode, entryPoint: core.AuthnEntryIDPOIDCAuthorizationCode,
		},
		{
			name: "OIDC device code", route: "/oidc/device/verify",
			oidcClientID: applicationBoundaryClientID, protocol: definitions.ProtoOIDC,
			grantType: definitions.OIDCFlowDeviceCode, entryPoint: core.AuthnEntryIDPOIDCDeviceCode,
		},
		{
			name: "SAML", route: "/saml/sso", samlEntityID: applicationBoundarySAMLEntityID,
			protocol: definitions.ProtoSAML, grantType: "saml_sso", entryPoint: core.AuthnEntryIDPSAML,
		},
		{
			name: "internal IDP", route: "/mfa/register/home", protocol: definitions.ProtoIDP,
			grantType: "internal", entryPoint: core.AuthnEntryIDPInternal,
		},
	}
}

// run verifies one authentication entry without duplicating the shared boundary assertions.
func (testCase applicationAuthenticationEntryCase) run(t *testing.T) {
	backendRef := applicationBoundaryBackendRef("target")
	outcome := applicationBoundarySuccessOutcome(
		"alice@example.test", "identity-alice", "Alice Example", testCase.protocol, backendRef,
	)
	application := &recordingIDPAuthApplication{
		authenticateResults: []applicationBoundaryResult{{outcome: outcome}},
	}
	idp, _ := newApplicationBoundaryIDP(t, application, false)
	ctx := newApplicationBoundaryContext(t, http.MethodPost, testCase.route)
	scopes := []string{definitions.ScopeOpenID, definitions.ScopeEmail}
	requestContext := core.IDPRequestContext{
		GrantType: testCase.grantType, RedirectURI: "https://client.example.test/callback",
		RequestedScopes: scopes, MFACompleted: true, MFAMethod: definitions.MFAMethodWebAuthn,
	}

	result, err := idp.AuthenticateWithBackend(
		ctx,
		"alice@example.test",
		applicationBoundaryPassword,
		testCase.oidcClientID,
		testCase.samlEntityID,
		requestContext,
	)
	if err != nil {
		t.Fatalf("AuthenticateWithBackend() error = %v", err)
	}

	assertIDPApplicationCalls(t, application, 1, 0)
	assertIDPApplicationInput(t, application.authenticateInputs[0], expectedIDPApplicationInput{
		request: requestContext, transport: applicationBoundaryTransport(http.MethodPost, testCase.route),
		entryPoint: testCase.entryPoint, protocol: testCase.protocol, username: "alice@example.test",
		oidcClientID: testCase.oidcClientID, samlEntityID: testCase.samlEntityID, wantPassword: true,
	})
	assertPasswordAuthenticationFromOutcome(t, result, outcome, true)
	assertDetachedPasswordAuthentication(t, result, outcome)

	scopes[0] = "caller-mutated"

	if got := application.authenticateInputs[0].IDP.Request.RequestedScopes[0]; got != definitions.ScopeOpenID {
		t.Fatalf("recorded application scopes aliased caller state: %q", got)
	}
}

func TestNauthilusIDPDelayedHydrationAndMasterFactorUseDistinctLookupEntries(t *testing.T) {
	application, targetRef, masterRef := newDelayedMasterRecordingApplication()
	idp, cfg := newApplicationBoundaryIDP(t, application, true)
	ctx := newApplicationBoundaryContext(t, http.MethodPost, "/oidc/authorize")
	requestContext := core.IDPRequestContext{
		GrantType: definitions.OIDCFlowAuthorizationCode, RequestedScopes: applicationBoundaryOIDCScopes(),
	}

	result, err := idp.AuthenticateWithBackend(
		ctx,
		"alice@example.test*admin@example.test",
		applicationBoundaryPassword,
		applicationBoundaryClientID,
		"",
		requestContext,
	)

	assertDelayedApplicationFailure(t, err)
	assertIDPApplicationCalls(t, application, 1, 2)

	client := &cfg.IDP.OIDC.Clients[0]
	wantAttributes := core.NewOIDCIdentityAttributeRequest(
		client, requestContext.RequestedScopes, cfg.IDP.OIDC.GetEffectiveCustomScopes(client),
	)
	assertIDPApplicationInput(t, application.lookupInputs[0], expectedIDPApplicationInput{
		attributeRequest: wantAttributes, request: requestContext,
		transport:  applicationBoundaryTransport(http.MethodPost, "/oidc/authorize"),
		entryPoint: core.AuthnEntryIDPDelayedIdentity, protocol: definitions.ProtoOIDC,
		username: "alice@example.test*admin@example.test", oidcClientID: applicationBoundaryClientID,
	})
	assertIDPApplicationInput(t, application.lookupInputs[1], expectedIDPApplicationInput{
		attributeRequest: wantAttributes, request: requestContext,
		transport:  applicationBoundaryTransport(http.MethodPost, "/oidc/authorize"),
		entryPoint: core.AuthnEntryIDPMasterFactor, protocol: definitions.ProtoOIDC,
		username: "admin@example.test", oidcClientID: applicationBoundaryClientID,
	})
	assertDelayedMasterAuthentication(t, result, targetRef, masterRef)
}

// newDelayedMasterRecordingApplication builds the ordered authentication and identity outcomes for delayed login.
func newDelayedMasterRecordingApplication() (*recordingIDPAuthApplication, core.RemoteBackendRef, core.RemoteBackendRef) {
	targetRef := applicationBoundaryBackendRef("target")
	masterRef := applicationBoundaryBackendRef("master")
	authenticationFailure := &core.AuthOutcome{
		Decision: core.AuthDecisionFail, Error: "invalid credentials",
		StatusMessage: "Invalid credentials", StatusMessageI18NKey: "auth.invalid_credentials",
		ResponseLanguage: "en", DelayedResponseEligible: true,
	}
	application := &recordingIDPAuthApplication{
		authenticateResults: []applicationBoundaryResult{{outcome: authenticationFailure}},
		lookupResults: []applicationBoundaryResult{
			{outcome: applicationBoundarySuccessOutcome(
				"alice@example.test", "identity-alice", "Alice Example", definitions.ProtoOIDC, targetRef,
			)},
			{outcome: applicationBoundarySuccessOutcome(
				"admin@example.test", "identity-admin", "Admin Example", definitions.ProtoOIDC, masterRef,
			)},
		},
	}

	return application, targetRef, masterRef
}

// assertDelayedApplicationFailure verifies that delayed hydration retains an ordinary authentication failure.
func assertDelayedApplicationFailure(t *testing.T, err error) {
	t.Helper()

	var failure *AuthFailureError

	if !errors.As(err, &failure) {
		t.Fatalf("AuthenticateWithBackend() error = %T %v, want *AuthFailureError", err, err)
	}

	if !failure.Status.DelayedResponseEligible || failure.Status.PolicyTerminal {
		t.Fatalf("delayed failure status = %#v, want delayed ordinary failure", failure.Status)
	}
}

// assertDelayedMasterAuthentication verifies detached target and master-factor identities.
func assertDelayedMasterAuthentication(
	t *testing.T,
	result PasswordAuthentication,
	targetRef core.RemoteBackendRef,
	masterRef core.RemoteBackendRef,
) {
	t.Helper()

	if result.User == nil || result.User.Name != "alice@example.test" || result.BackendRef != targetRef ||
		result.MFAUser == nil || result.MFAUser.Name != "admin@example.test" || result.MFABackendRef != masterRef {
		t.Fatalf("delayed master-user result = %#v, want detached target and factor identities", result)
	}
}

type applicationClaimLookupCase struct {
	name       string
	route      string
	grantType  string
	protocol   string
	entryPoint core.AuthnEntryPoint
	saml       bool
}

type applicationClaimLookupResult struct {
	user             *backend.User
	attributeRequest *core.IdentityAttributeRequest
	oidcClientID     string
	samlEntityID     string
}

func TestNauthilusIDPClaimLookupUsesExactApplicationContext(t *testing.T) {
	for _, testCase := range applicationClaimLookupCases() {
		t.Run(testCase.name, testCase.run)
	}
}

// applicationClaimLookupCases returns each OIDC and SAML claim-lookup entry contract.
func applicationClaimLookupCases() []applicationClaimLookupCase {
	return []applicationClaimLookupCase{
		{
			name: "OIDC authorization code", route: "/oidc/claims/code",
			grantType: definitions.OIDCFlowAuthorizationCode, protocol: definitions.ProtoOIDC,
			entryPoint: core.AuthnEntryIDPOIDCAuthorizationCode,
		},
		{
			name: "OIDC device code", route: "/oidc/claims/device",
			grantType: definitions.OIDCFlowDeviceCode, protocol: definitions.ProtoOIDC,
			entryPoint: core.AuthnEntryIDPOIDCDeviceCode,
		},
		{
			name: "SAML", route: "/saml/claims", grantType: "saml_sso",
			protocol: definitions.ProtoSAML, entryPoint: core.AuthnEntryIDPSAML, saml: true,
		},
	}
}

// run verifies one claim-lookup adapter and its detached identity result.
func (testCase applicationClaimLookupCase) run(t *testing.T) {
	incomingRef := applicationBoundaryBackendRef("incoming")
	outcome := applicationBoundarySuccessOutcome(
		"claims@example.test", "identity-claims", "Claims User", testCase.protocol,
		applicationBoundaryBackendRef("returned"),
	)
	application := &recordingIDPAuthApplication{
		lookupResults: []applicationBoundaryResult{{outcome: outcome}},
	}
	idp, cfg := newApplicationBoundaryIDP(t, application, false)
	ctx := newApplicationBoundaryContext(t, http.MethodGet, testCase.route)
	requestContext := core.IDPRequestContext{
		GrantType: testCase.grantType, RedirectURI: "https://client.example.test/callback",
		RequestedScopes: applicationBoundaryOIDCScopes(), MFACompleted: true, MFAMethod: definitions.MFAMethodWebAuthn,
	}

	lookupResult, err := testCase.lookup(idp, cfg, ctx, incomingRef, requestContext)
	if err != nil {
		t.Fatalf("canonical claim lookup error = %v", err)
	}

	assertIDPApplicationCalls(t, application, 0, 1)
	assertIDPApplicationInput(t, application.lookupInputs[0], expectedIDPApplicationInput{
		attributeRequest: lookupResult.attributeRequest, backendRef: incomingRef, request: requestContext,
		transport: applicationBoundaryTransport(http.MethodGet, testCase.route), entryPoint: testCase.entryPoint,
		protocol: testCase.protocol, username: "claims@example.test",
		oidcClientID: lookupResult.oidcClientID, samlEntityID: lookupResult.samlEntityID,
	})
	assertBackendUserFromOutcome(t, lookupResult.user, outcome)
	assertDetachedBackendUser(t, lookupResult.user, outcome)
}

// lookup invokes the protocol-specific claim lookup and returns its expected client metadata.
func (testCase applicationClaimLookupCase) lookup(
	idp *NauthilusIDP,
	cfg *config.FileSettings,
	ctx *gin.Context,
	incomingRef core.RemoteBackendRef,
	requestContext core.IDPRequestContext,
) (applicationClaimLookupResult, error) {
	if testCase.saml {
		serviceProvider := &cfg.IDP.SAML2.ServiceProviders[0]
		attributeRequest := core.NewSAMLIdentityAttributeRequest(serviceProvider)
		user, err := idp.GetUserByUsernameForSAMLCanonical(
			ctx, "claims@example.test", serviceProvider, incomingRef, requestContext,
		)

		return applicationClaimLookupResult{
			user: user, attributeRequest: attributeRequest,
			samlEntityID: serviceProvider.EntityID,
		}, err
	}

	client := &cfg.IDP.OIDC.Clients[0]
	attributeRequest := core.NewOIDCIdentityAttributeRequest(
		client, requestContext.RequestedScopes, cfg.IDP.OIDC.GetEffectiveCustomScopes(client),
	)
	user, err := idp.GetUserByUsernameForOIDCClaimsCanonical(
		ctx,
		"claims@example.test",
		client,
		requestContext.RequestedScopes,
		incomingRef,
		requestContext,
	)

	return applicationClaimLookupResult{
		user: user, attributeRequest: attributeRequest, oidcClientID: client.ClientID,
	}, err
}

type applicationFailureMappingCase struct {
	outcome     *core.AuthOutcome
	name        string
	wantDelayed bool
	wantPolicy  bool
}

func TestNauthilusIDPApplicationFailureMappingPreservesTerminalDistinctions(t *testing.T) {
	for _, testCase := range applicationFailureMappingCases() {
		t.Run(testCase.name, testCase.run)
	}
}

// applicationFailureMappingCases returns ordinary, temporary, and policy-terminal failure contracts.
func applicationFailureMappingCases() []applicationFailureMappingCase {
	return []applicationFailureMappingCase{
		{
			name: "ordinary password failure",
			outcome: &core.AuthOutcome{
				Decision: core.AuthDecisionFail, Error: "invalid credentials",
				StatusMessage: "Invalid credentials", StatusMessageI18NKey: "auth.invalid_credentials",
				ResponseLanguage: "en", DelayedResponseEligible: true,
			},
			wantDelayed: true,
		},
		{
			name: "temporary failure",
			outcome: &core.AuthOutcome{
				Decision: core.AuthDecisionTempFail, Error: "backend temporarily unavailable",
				StatusMessage: "Temporary failure", StatusMessageI18NKey: "auth.tempfail",
				ResponseLanguage: "de",
			},
		},
		{
			name: "configured policy terminal failure",
			outcome: &core.AuthOutcome{
				Decision: core.AuthDecisionFail, Error: "policy denied authentication",
				StatusMessage: "Authentication denied", StatusMessageI18NKey: "auth.policy_denied",
				ResponseLanguage: "en", PolicyTerminal: true,
			},
			wantPolicy: true,
		},
		{
			name: "configured policy delayed fallback",
			outcome: &core.AuthOutcome{
				Decision: core.AuthDecisionFail, Error: "configured ordinary password failure",
				StatusMessage: "Invalid credentials", StatusMessageI18NKey: "auth.invalid_credentials",
				ResponseLanguage: "en", PolicyTerminal: true, DelayedResponseEligible: true,
			},
			wantDelayed: true, wantPolicy: true,
		},
	}
}

// run verifies one application failure projection without duplicating the authentication setup.
func (testCase applicationFailureMappingCase) run(t *testing.T) {
	application := &recordingIDPAuthApplication{
		authenticateResults: []applicationBoundaryResult{{outcome: testCase.outcome}},
	}
	idp, _ := newApplicationBoundaryIDP(t, application, false)
	result, err := authenticateApplicationBoundary(t, idp)

	var failure *AuthFailureError

	if !errors.As(err, &failure) {
		t.Fatalf("AuthenticateWithBackend() error = %T %v, want *AuthFailureError", err, err)
	}

	assertApplicationFailureMapping(t, failure, testCase)

	if result != (PasswordAuthentication{}) {
		t.Fatalf("failed application authentication returned identity: %#v", result)
	}

	assertIDPApplicationCalls(t, application, 1, 0)
}

// assertApplicationFailureMapping verifies the complete failure status projected from an application outcome.
func assertApplicationFailureMapping(
	t *testing.T,
	failure *AuthFailureError,
	testCase applicationFailureMappingCase,
) {
	t.Helper()

	if !strings.Contains(failure.Error(), string(testCase.outcome.Decision)) ||
		failure.Status.StatusMessage != testCase.outcome.StatusMessage ||
		failure.Status.I18NKey != testCase.outcome.StatusMessageI18NKey ||
		failure.Status.ResponseLanguage != testCase.outcome.ResponseLanguage ||
		failure.Status.DelayedResponseEligible != testCase.wantDelayed ||
		failure.Status.PolicyTerminal != testCase.wantPolicy {
		t.Fatalf("application failure = %q/%#v, want outcome %#v", failure.Error(), failure.Status, testCase.outcome)
	}
}

func TestNauthilusIDPApplicationInputMutationCannotAliasBrowserSourceState(t *testing.T) {
	application := &recordingIDPAuthApplication{
		lookupResults: []applicationBoundaryResult{{outcome: applicationBoundarySuccessOutcome(
			"claims@example.test", "identity-claims", "Claims User", definitions.ProtoOIDC,
			applicationBoundaryBackendRef("returned"),
		)}},
		mutateInput: true,
	}
	idp, cfg := newApplicationBoundaryIDP(t, application, false)
	ctx := newApplicationBoundaryContext(t, http.MethodGet, "/oidc/claims/code")
	scopes := applicationBoundaryOIDCScopes()
	requestContext := core.IDPRequestContext{
		GrantType: definitions.OIDCFlowAuthorizationCode, RequestedScopes: scopes,
	}
	client := &cfg.IDP.OIDC.Clients[0]

	_, err := idp.GetUserByUsernameForOIDCClaimsCanonical(
		ctx,
		"claims@example.test",
		client,
		scopes,
		applicationBoundaryBackendRef("incoming"),
		requestContext,
	)
	if err != nil {
		t.Fatalf("GetUserByUsernameForOIDCClaimsCanonical() error = %v", err)
	}

	if scopes[0] != definitions.ScopeOpenID || requestContext.RequestedScopes[0] != definitions.ScopeOpenID {
		t.Fatalf("application input mutation aliased requested scopes: %v/%v", scopes, requestContext.RequestedScopes)
	}

	if got := ctx.Request.Header.Values("X-Request-ID"); !reflect.DeepEqual(got, []string{applicationBoundaryRequestID}) {
		t.Fatalf("application input mutation aliased request headers: %v", got)
	}

	if got := client.IDTokenClaims.Mappings[0].Attribute; got != "mail" {
		t.Fatalf("application input mutation aliased OIDC claim configuration: %q", got)
	}
}

type applicationBoundaryFailureCase struct {
	application       core.AuthApplicationService
	wantError         error
	name              string
	authenticateCalls int
	lookupCalls       int
	lookup            bool
}

func TestNauthilusIDPApplicationBoundaryFailsClosedWithoutDirectFallback(t *testing.T) {
	applicationErr := errors.New("recorded application failure")

	for _, testCase := range applicationBoundaryFailureCases(applicationErr) {
		t.Run(testCase.name, testCase.run)
	}
}

// applicationBoundaryFailureCases returns missing dependency, missing outcome, and application error contracts.
func applicationBoundaryFailureCases(applicationErr error) []applicationBoundaryFailureCase {
	return []applicationBoundaryFailureCase{
		{
			name:      "missing authenticate application",
			wantError: core.ErrAuthApplicationDependencyMissing,
		},
		{
			application: &recordingIDPAuthApplication{
				authenticateResults: []applicationBoundaryResult{{err: applicationErr}},
			},
			wantError: applicationErr, name: "authenticate application error", authenticateCalls: 1,
		},
		{
			application: &recordingIDPAuthApplication{
				authenticateResults: []applicationBoundaryResult{{}},
			},
			wantError: core.ErrAuthOutcomeMissing, name: "missing authenticate outcome", authenticateCalls: 1,
		},
		{
			wantError: core.ErrAuthApplicationDependencyMissing, name: "missing lookup application", lookup: true,
		},
		{
			application: &recordingIDPAuthApplication{
				lookupResults: []applicationBoundaryResult{{err: applicationErr}},
			},
			wantError: applicationErr, name: "lookup application error", lookupCalls: 1, lookup: true,
		},
	}
}

// run verifies that one application boundary failure does not fall back to a direct backend call.
func (testCase applicationBoundaryFailureCase) run(t *testing.T) {
	idp, cfg := newApplicationBoundaryIDP(t, testCase.application, false)
	err := testCase.invoke(t, idp, cfg)

	if !errors.Is(err, testCase.wantError) {
		t.Fatalf("%s error = %v, want %v", testCase.name, err, testCase.wantError)
	}

	if application, ok := testCase.application.(*recordingIDPAuthApplication); ok {
		assertIDPApplicationCalls(t, application, testCase.authenticateCalls, testCase.lookupCalls)
	}
}

// invoke selects the authentication or identity lookup boundary for one failure case.
func (testCase applicationBoundaryFailureCase) invoke(
	t *testing.T,
	idp *NauthilusIDP,
	cfg *config.FileSettings,
) error {
	if testCase.lookup {
		return lookupApplicationBoundary(t, idp, cfg)
	}

	_, err := authenticateApplicationBoundary(t, idp)

	return err
}

// authenticateApplicationBoundary invokes the shared OIDC authentication fixture.
func authenticateApplicationBoundary(t *testing.T, idp *NauthilusIDP) (PasswordAuthentication, error) {
	t.Helper()

	ctx := newApplicationBoundaryContext(t, http.MethodPost, "/oidc/authorize")

	return idp.AuthenticateWithBackend(
		ctx,
		"alice@example.test",
		applicationBoundaryPassword,
		applicationBoundaryClientID,
		"",
		core.IDPRequestContext{GrantType: definitions.OIDCFlowAuthorizationCode},
	)
}

// lookupApplicationBoundary invokes the shared OIDC claim-lookup fixture.
func lookupApplicationBoundary(t *testing.T, idp *NauthilusIDP, cfg *config.FileSettings) error {
	t.Helper()

	ctx := newApplicationBoundaryContext(t, http.MethodGet, "/oidc/claims/code")
	_, err := idp.GetUserByUsernameForOIDCClaimsCanonical(
		ctx,
		"claims@example.test",
		&cfg.IDP.OIDC.Clients[0],
		applicationBoundaryOIDCScopes(),
		core.RemoteBackendRef{},
		core.IDPRequestContext{GrantType: definitions.OIDCFlowAuthorizationCode},
	)

	return err
}

// Authenticate records one detached IdP application input before returning the configured outcome.
func (a *recordingIDPAuthApplication) Authenticate(_ context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	authInput := cloneApplicationBoundaryInput(input)
	a.authenticateInputs = append(a.authenticateInputs, authInput)
	a.mutateApplicationInput(input)

	return a.nextApplicationResult(&a.authenticateResults, "authenticate")
}

// LookupIdentity records one detached IdP application input before returning the configured outcome.
func (a *recordingIDPAuthApplication) LookupIdentity(_ context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	authInput := cloneApplicationBoundaryInput(input)
	a.lookupInputs = append(a.lookupInputs, authInput)
	a.mutateApplicationInput(input)

	return a.nextApplicationResult(&a.lookupResults, "lookup identity")
}

// ListAccounts rejects the operation because no IdP path in this contract may invoke it.
func (a *recordingIDPAuthApplication) ListAccounts(context.Context, core.AuthInput) (*core.ListAccountsOutcome, error) {
	return nil, fmt.Errorf("unexpected IdP list-accounts application call")
}

// nextApplicationResult consumes one configured recording result.
func (a *recordingIDPAuthApplication) nextApplicationResult(
	results *[]applicationBoundaryResult,
	operation string,
) (*core.AuthOutcome, error) {
	if len(*results) == 0 {
		return nil, fmt.Errorf("unexpected IdP %s application call", operation)
	}

	result := (*results)[0]
	*results = (*results)[1:]

	return result.outcome, result.err
}

// mutateApplicationInput verifies that the application cannot mutate caller-owned browser state.
func (a *recordingIDPAuthApplication) mutateApplicationInput(input core.AuthInput) {
	if !a.mutateInput {
		return
	}

	if len(input.IDP.Request.RequestedScopes) > 0 {
		input.IDP.Request.RequestedScopes[0] = "application-mutated"
	}

	if input.IDP.IdentityAttributeRequest != nil && len(input.IDP.IdentityAttributeRequest.Names) > 0 {
		input.IDP.IdentityAttributeRequest.Names[0] = "application-mutated"
	}

	if values := input.Context.RequestMetadata["x-request-id"]; len(values) > 0 {
		values[0] = "application-mutated"
	}
}

// cloneApplicationBoundaryInput detaches mutable recording values from later assertions.
func cloneApplicationBoundaryInput(input core.AuthInput) core.AuthInput {
	result := input
	result.IDP = input.IDP.Clone()
	result.Context.RequestMetadata = make(map[string][]string, len(input.Context.RequestMetadata))

	for key, values := range input.Context.RequestMetadata {
		result.Context.RequestMetadata[key] = append([]string(nil), values...)
	}

	return result
}

// newApplicationBoundaryIDP constructs the smallest IdP fixture with an injected application boundary.
func newApplicationBoundaryIDP(
	t *testing.T,
	application core.AuthApplicationService,
	masterUser bool,
) (*NauthilusIDP, *config.FileSettings) {
	t.Helper()

	cfg := applicationBoundaryConfig(masterUser)
	db, _ := redismock.NewClientMock()
	idp := NewNauthilusIDP(&deps.Deps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(), Logger: slog.Default(),
		Redis: rediscli.NewTestClient(db), AuthApplication: application,
	})

	return idp, cfg
}

// applicationBoundaryConfig returns client and service-provider claim mappings for exact request assertions.
func applicationBoundaryConfig(masterUser bool) *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "test:idp-application:"},
			MasterUser: config.MasterUser{
				Enabled: masterUser, UserFormat: config.DefaultMasterUserFormat,
			},
		},
		IDP: &config.IDPSection{
			OIDC: config.OIDCConfig{Clients: []config.OIDCClient{{
				ClientID: applicationBoundaryClientID,
				Scopes:   applicationBoundaryOIDCScopes(),
				IDTokenClaims: config.IDTokenClaims{Mappings: []config.OIDCClaimMapping{
					{Claim: definitions.ClaimEmail, Attribute: "mail", Type: definitions.ClaimTypeString},
					{Claim: definitions.ClaimGroups, From: definitions.ClaimGroups, Type: definitions.ClaimTypeStringArray},
				}},
				AccessTokenClaims: config.AccessTokenClaims{Mappings: []config.OIDCClaimMapping{{
					Claim: "department", Attribute: "departmentNumber", Type: definitions.ClaimTypeString,
				}}},
				CustomScopes: []config.Oauth2CustomScope{{
					Name: "resource", Claims: []config.OIDCCustomClaim{{Name: "department", Type: definitions.ClaimTypeString}},
				}},
				DelayedResponse: masterUser,
			}}},
			SAML2: config.SAML2Config{ServiceProviders: []config.SAML2ServiceProvider{{
				EntityID: applicationBoundarySAMLEntityID,
				AllowedAttributes: []string{
					"mail", "employeeNumber", definitions.ClaimGroups,
					definitions.LuaBackendResultGroupDistinguishedNames,
				},
			}},
			},
		},
	}
}

// applicationBoundaryOIDCScopes returns the exact granted scopes used by claim lookup tests.
func applicationBoundaryOIDCScopes() []string {
	return []string{definitions.ScopeOpenID, definitions.ScopeEmail, definitions.ScopeGroups, "resource"}
}

// newApplicationBoundaryContext creates protected IdP HTTP evidence plus browser-only state sentinels.
func newApplicationBoundaryContext(t *testing.T, method string, route string) *gin.Context {
	t.Helper()

	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(method, "https://idp.example.test"+route, nil)
	ctx.Request.RemoteAddr = applicationBoundaryPeer + ":4242"
	ctx.Request.Header.Set("X-Request-ID", applicationBoundaryRequestID)
	ctx.Request.Header.Set("Authorization", "Bearer must-not-cross-idp-boundary")
	ctx.Request.Header.Set("Cookie", "nauthilus_secure_data="+applicationBoundaryCookieMarker)
	ctx.Set(definitions.CtxGUIDKey, applicationBoundaryRequestID)
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
	ctx.Set(definitions.CtxSecureDataKey, applicationBoundaryCookieMarker)
	ctx.Set(definitions.CtxExternalSessionKey, applicationBoundarySessionMarker)
	ctx.Set(definitions.SessionKeyIDPFlowID, applicationBoundaryFlowMarker)
	ctx.Set(definitions.SessionKeyWebAuthnCeremony, applicationBoundaryCeremonyMarker)

	return ctx
}

// applicationBoundaryTransport returns exact trusted HTTP facts expected from every IdP adapter.
func applicationBoundaryTransport(method string, route string) core.AuthTransportContext {
	return core.AuthTransportContext{
		Kind: "idp", Listener: "http.idp", HTTPMethod: method,
		HTTPRoute: route, Peer: applicationBoundaryPeer, Protected: true,
	}
}

// applicationBoundaryBackendRef returns one stable incoming or returned backend-affinity reference.
func applicationBoundaryBackendRef(name string) core.RemoteBackendRef {
	return core.RemoteBackendRef{
		Type: "remote", Name: name, Protocol: definitions.ProtoOIDC,
		Authority: "authority.example.test", OpaqueToken: "authority-" + name,
	}
}

// applicationBoundarySuccessOutcome returns complete identity and backend data for mapping assertions.
func applicationBoundarySuccessOutcome(
	account string,
	uniqueID string,
	displayName string,
	protocol string,
	backendRef core.RemoteBackendRef,
) *core.AuthOutcome {
	return &core.AuthOutcome{
		Decision: core.AuthDecisionOK, Account: account, AccountField: "uid",
		DisplayName: displayName, DisplayNameField: "displayName",
		UniqueUserID: uniqueID, UniqueUserIDField: "entryUUID",
		TOTPSecretField: "totpSecret", TOTPRecoveryField: "recoveryCodes",
		Attributes: bktype.AttributeMapping{
			"uid": {account}, "displayName": {displayName}, "entryUUID": {uniqueID},
			"mail": {account},
		},
		Groups:                  []string{"employees"},
		GroupDistinguishedNames: []string{"cn=employees,dc=example,dc=test"},
		Protocol:                protocol, Backend: definitions.BackendRemote,
		BackendName: backendRef.Name, RemoteBackendRef: backendRef,
	}
}

// assertIDPApplicationCalls verifies the exact application operations performed by an IdP adapter.
func assertIDPApplicationCalls(
	t *testing.T,
	application *recordingIDPAuthApplication,
	wantAuthenticate int,
	wantLookup int,
) {
	t.Helper()

	if len(application.authenticateInputs) != wantAuthenticate || len(application.lookupInputs) != wantLookup {
		t.Fatalf(
			"application authenticate/lookup calls = %d/%d, want %d/%d",
			len(application.authenticateInputs), len(application.lookupInputs), wantAuthenticate, wantLookup,
		)
	}
}

// assertIDPApplicationInput verifies exact routing, credentials, and bounded IdP values.
func assertIDPApplicationInput(t *testing.T, input core.AuthInput, want expectedIDPApplicationInput) {
	t.Helper()

	assertIDPApplicationRouting(t, input, want)
	assertIDPApplicationCredentials(t, input, want)
	assertIDPApplicationPayload(t, input, want)
	assertNoBrowserAggregateInApplicationInput(t, input)
}

// assertIDPApplicationRouting verifies entry, transport, protocol, and client routing facts.
func assertIDPApplicationRouting(t *testing.T, input core.AuthInput, want expectedIDPApplicationInput) {
	t.Helper()

	if input.EntryPoint != want.entryPoint || input.Service != definitions.ServIDP ||
		input.CorrelationID != applicationBoundaryRequestID {
		t.Fatalf(
			"entry/service/correlation = %s/%q/%q, want %s/%q/%q",
			input.EntryPoint.String(), input.Service, input.CorrelationID,
			want.entryPoint.String(), definitions.ServIDP, applicationBoundaryRequestID,
		)
	}

	if input.Context.Transport != want.transport {
		t.Fatalf("transport = %#v, want %#v", input.Context.Transport, want.transport)
	}

	if input.Context.Protocol != want.protocol || input.Context.OIDCCID != want.oidcClientID ||
		input.Context.SAMLEntityID != want.samlEntityID {
		t.Fatalf(
			"protocol/client/SP = %q/%q/%q, want %q/%q/%q",
			input.Context.Protocol, input.Context.OIDCCID, input.Context.SAMLEntityID,
			want.protocol, want.oidcClientID, want.samlEntityID,
		)
	}

	if input.Context.OIDCCID != "" && input.Context.SAMLEntityID != "" {
		t.Fatal("application input carried both OIDC client and SAML service-provider identity")
	}
}

// assertIDPApplicationCredentials verifies username, password presence, and authentication method.
func assertIDPApplicationCredentials(t *testing.T, input core.AuthInput, want expectedIDPApplicationInput) {
	t.Helper()

	passwordPresent := !input.Credentials.Password.IsZero()

	if input.Credentials.Username != want.username || passwordPresent != want.wantPassword {
		t.Fatalf(
			"credentials username/password-present = %q/%t, want %q/%t",
			input.Credentials.Username, passwordPresent, want.username, want.wantPassword,
		)
	}

	wantMethod := ""
	if want.wantPassword {
		wantMethod = definitions.AuthMethodPassword
	}

	if input.Context.Method != wantMethod {
		t.Fatalf("authentication method = %q, want %q", input.Context.Method, wantMethod)
	}
}

// assertIDPApplicationPayload verifies the bounded protocol request, attributes, affinity, and safe metadata.
func assertIDPApplicationPayload(t *testing.T, input core.AuthInput, want expectedIDPApplicationInput) {
	t.Helper()

	wantRequest := core.NewAuthIDPContext(want.request, nil, core.RemoteBackendRef{}).Request

	if !reflect.DeepEqual(input.IDP.Request, wantRequest) ||
		!reflect.DeepEqual(input.IDP.IdentityAttributeRequest, want.attributeRequest) ||
		input.IDP.ExistingBackendRef != want.backendRef {
		t.Fatalf("bounded IdP context = %#v, want request=%#v attributes=%#v ref=%#v", input.IDP, wantRequest, want.attributeRequest, want.backendRef)
	}

	if got := input.Context.RequestMetadata["x-request-id"]; !reflect.DeepEqual(got, []string{applicationBoundaryRequestID}) {
		t.Fatalf("safe request metadata = %v, want request id", got)
	}
}

// assertNoBrowserAggregateInApplicationInput rejects browser-only state and credential headers.
func assertNoBrowserAggregateInApplicationInput(t *testing.T, input core.AuthInput) {
	t.Helper()

	for _, name := range []string{"authorization", "cookie", "proxy-authorization", "set-cookie"} {
		if _, exists := input.Context.RequestMetadata[name]; exists {
			t.Fatalf("application input retained credential-bearing metadata %q", name)
		}
	}

	assertExactApplicationBoundaryFields(t, input.IDP, "AuthIDPContext", map[string]struct{}{
		"Request": {}, "IdentityAttributeRequest": {}, "ExistingBackendRef": {},
	})
	assertExactApplicationBoundaryFields(t, input.IDP.Request, "AuthIDPRequestContext", map[string]struct{}{
		"GrantType": {}, "RedirectURI": {}, "RequestedScopes": {},
	})

	serialized := fmt.Sprintf("%#v", input)

	for _, marker := range []string{
		applicationBoundaryCookieMarker,
		applicationBoundaryFlowMarker,
		applicationBoundarySessionMarker,
		applicationBoundaryCeremonyMarker,
	} {
		if strings.Contains(serialized, marker) {
			t.Fatalf("application input retained browser aggregate marker %q", marker)
		}
	}
}

// assertExactApplicationBoundaryFields rejects any field outside the explicitly bounded application shape.
func assertExactApplicationBoundaryFields(
	t *testing.T,
	value any,
	typeName string,
	allowedFields map[string]struct{},
) {
	t.Helper()

	valueType := reflect.TypeOf(value)

	if valueType.NumField() != len(allowedFields) {
		t.Fatalf("%s has %d fields, want exact bounded set %v", typeName, valueType.NumField(), allowedFields)
	}

	for index := range valueType.NumField() {
		field := valueType.Field(index)

		if _, allowed := allowedFields[field.Name]; !allowed {
			t.Fatalf("%s retained out-of-bound field %q", typeName, field.Name)
		}
	}
}

// assertPasswordAuthenticationFromOutcome verifies complete target and factor mapping.
func assertPasswordAuthenticationFromOutcome(
	t *testing.T,
	result PasswordAuthentication,
	outcome *core.AuthOutcome,
	wantDefaultFactor bool,
) {
	t.Helper()

	assertBackendUserFromOutcome(t, result.User, outcome)

	if result.BackendRef != outcome.RemoteBackendRef {
		t.Fatalf("password backend ref = %#v, want %#v", result.BackendRef, outcome.RemoteBackendRef)
	}

	if wantDefaultFactor {
		assertBackendUserFromOutcome(t, result.MFAUser, outcome)

		if result.MFABackendRef != outcome.RemoteBackendRef {
			t.Fatalf("MFA backend ref = %#v, want %#v", result.MFABackendRef, outcome.RemoteBackendRef)
		}
	}
}

// assertBackendUserFromOutcome verifies every safe identity projection.
func assertBackendUserFromOutcome(t *testing.T, user *backend.User, outcome *core.AuthOutcome) {
	t.Helper()

	if user == nil {
		t.Fatal("application outcome mapped to nil backend user")
	}

	if user.Name != outcome.Account || user.ID != outcome.UniqueUserID || user.DisplayName != outcome.DisplayName ||
		user.TOTPSecretField != outcome.TOTPSecretField || user.TOTPRecoveryField != outcome.TOTPRecoveryField ||
		!reflect.DeepEqual(user.Attributes, outcome.Attributes) || !reflect.DeepEqual(user.Groups, outcome.Groups) ||
		!reflect.DeepEqual(user.GroupDistinguishedNames, outcome.GroupDistinguishedNames) {
		t.Fatalf("backend user = %#v, want complete outcome projection %#v", user, outcome)
	}
}

// assertDetachedPasswordAuthentication proves result identity does not alias application outcome state.
func assertDetachedPasswordAuthentication(t *testing.T, result PasswordAuthentication, outcome *core.AuthOutcome) {
	t.Helper()

	assertDetachedBackendUser(t, result.User, outcome)

	if result.MFAUser != result.User {
		assertDetachedBackendUser(t, result.MFAUser, outcome)
	}
}

// assertDetachedBackendUser mutates the source outcome and verifies the mapped user remains stable.
func assertDetachedBackendUser(t *testing.T, user *backend.User, outcome *core.AuthOutcome) {
	t.Helper()

	outcome.Attributes["mail"][0] = "mutated@example.test"
	outcome.Groups[0] = "mutated"
	outcome.GroupDistinguishedNames[0] = "mutated"

	if user.Attributes["mail"][0] != outcome.Account || user.Groups[0] != "employees" ||
		user.GroupDistinguishedNames[0] != "cn=employees,dc=example,dc=test" {
		t.Fatalf("backend user aliased application outcome: %#v", user)
	}
}
