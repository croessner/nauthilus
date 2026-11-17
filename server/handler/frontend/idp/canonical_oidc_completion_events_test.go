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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	domainidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/gin-gonic/gin"
)

// completionFlowRefPattern is the shape of the non-authorizing flow reference.
var completionFlowRefPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// newCompletionEventHandler builds a miniredis-backed OIDC handler that records step events.
func newCompletionEventHandler(t *testing.T) (*OIDCHandler, *recordingAuthEventEmitter) {
	t.Helper()

	handler := newResourceIndicatorHandler(t)
	emitter := &recordingAuthEventEmitter{}
	handler.canonicalAuthEventEmitter = emitter

	return handler, emitter
}

// completionAuthorizeQuery is an authorization request without resource indicators.
func completionAuthorizeQuery() url.Values {
	return url.Values{
		oidcParamClientID: {resourceTestClientID}, oidcParamRedirectURI: {resourceTestRedirectURI},
		oidcParamScope: {"openid offline_access"}, oidcParamState: {"state-c"}, oidcParamResponseType: {oidcResponseTypeCode},
	}
}

// authorizeWithExistingSession sends an authorization request for an already authenticated browser session and
// returns the issued code: /authorize starts a fresh flow and issues immediately (SSO reuse, no login in this flow).
func authorizeWithExistingSession(t *testing.T, handler *OIDCHandler) string {
	t.Helper()

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+completionAuthorizeQuery().Encode(), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Query().Get(oidcParamCode) == "" {
		t.Fatalf("SSO authorize = %d %q, err = %v", response.Code, response.Header().Get("Location"), err)
	}

	return location.Query().Get(oidcParamCode)
}

// exchangeCode redeems one code as the issuing client.
func exchangeCode(t *testing.T, handler *OIDCHandler, code string) map[string]any {
	t.Helper()

	return postResourceTokenRequest(t, handler, url.Values{
		oidcParamGrantType: {definitions.OIDCFlowAuthorizationCode}, oidcParamCode: {code},
		oidcParamRedirectURI: {resourceTestRedirectURI},
	})
}

// assertSecretFree fails when an encoded event contains any of the given secret values.
func assertSecretFree(t *testing.T, event pluginapi.AuthEvent, secrets ...string) {
	t.Helper()

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	for _, value := range secrets {
		if value != "" && strings.Contains(string(encoded), value) {
			t.Fatalf("event %s leaks a secret value", encoded)
		}
	}
}

// assertCompletionEvent checks the shared shape of one OIDC completion event.
func assertCompletionEvent(t *testing.T, event pluginapi.AuthEvent, eventType pluginapi.AuthEventType,
	result pluginapi.AuthEventResult, reason string, effect pluginapi.AuthEventFlowEffect) {
	t.Helper()

	if event.Type != eventType || event.Version != pluginapi.AuthEventOIDCCodeVersion || event.Result != result ||
		event.Reason != reason || event.FlowEffect != effect {
		t.Fatalf("event = %+v, want %s %s/%s/%s", event, eventType, result, reason, effect)
	}

	assertCompletionIdentity(t, event)
}

// assertCompletionIdentity checks the correlation and identity fields shared by every OIDC completion event.
func assertCompletionIdentity(t *testing.T, event pluginapi.AuthEvent) {
	t.Helper()

	if event.Protocol != "oidc" || event.ClientID != resourceTestClientID || event.Account != "alice" ||
		len(event.EventID) != 32 || !completionFlowRefPattern.MatchString(event.FlowRef) {
		t.Fatalf("event = %+v, want the OIDC client, the account, and a flow reference", event)
	}

	if event.FactorRole != "" || event.Method != "" || event.FailLatched || event.ObservedAt.IsZero() {
		t.Fatalf("event = %+v, want no factor fields and an observation time", event)
	}
}

// TestSSOAuthorizationRecordsIssuanceAndRedemptionOnce pins the complete authorization-code path of a reused
// session: one issuance event naming the existing session, one successful redemption with the same flow reference,
// and no further event for a replayed code.
func TestSSOAuthorizationRecordsIssuanceAndRedemptionOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, emitter := newCompletionEventHandler(t)
	code := authorizeWithExistingSession(t, handler)
	tokens := exchangeCode(t, handler, code)
	replayed := exchangeCode(t, handler, code)

	if replayed[definitions.LogKeyError] != oidcErrorInvalidGrant {
		t.Fatalf("replay = %v, want invalid_grant", replayed)
	}

	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("events = %+v, want issuance and one redemption; a replay is never attributable", events)
	}

	issued, redeemed := events[0], events[1]
	assertCompletionEvent(t, issued, pluginapi.AuthEventOIDCCodeIssuance, pluginapi.AuthEventSuccess,
		sessionstate.OIDCFlowExistingSession, pluginapi.AuthEventFlowCodeIssued)
	assertCompletionEvent(t, redeemed, pluginapi.AuthEventOIDCCodeRedemption, pluginapi.AuthEventSuccess,
		"tokens_issued", pluginapi.AuthEventFlowTokensIssued)

	if redeemed.FlowRef != issued.FlowRef || issued.ClientIP == "" || redeemed.ClientIP != "" ||
		redeemed.RequestID == issued.RequestID && issued.RequestID != "" {
		t.Fatalf("issued = %+v, redeemed = %+v, want one flow reference, a browser address only on issuance", issued, redeemed)
	}

	access, _ := tokens[oidcJSONFieldAccessToken].(string)
	refresh, _ := tokens[oidcParamRefreshToken].(string)
	idToken, _ := tokens["id_token"].(string)

	for _, event := range events {
		assertSecretFree(t, event, code, access, refresh, idToken)
	}
}

// TestFlowLoginIssuanceNamesTheRecordedAuthenticationSource pins that the issuance reason follows the persisted flow
// field and never guesses one for flow records an older release wrote.
func TestFlowLoginIssuanceNamesTheRecordedAuthenticationSource(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := map[string]string{
		sessionstate.OIDCFlowAuthenticatedInFlow: sessionstate.OIDCFlowAuthenticatedInFlow,
		"":                                       "not_recorded",
	}

	for stored, want := range cases {
		handler, emitter := newCompletionEventHandler(t)
		authorizeThroughFlowLogin(t, handler, completionAuthorizeQuery(), func(state *flow.State) {
			state.Metadata[flow.FlowMetadataAuthentication] = stored
		})

		events := emitter.snapshot()
		if len(events) != 1 {
			t.Fatalf("stored %q: events = %+v, want one issuance", stored, events)
		}

		assertCompletionEvent(t, events[0], pluginapi.AuthEventOIDCCodeIssuance, pluginapi.AuthEventSuccess, want,
			pluginapi.AuthEventFlowCodeIssued)
	}
}

// storeRedeemableCode stores one authorization-code session directly, as issuance would.
func storeRedeemableCode(t *testing.T, handler *OIDCHandler, code, flowRef, challenge string) {
	t.Helper()

	err := handler.storage.StoreSession(context.Background(), code, &domainidp.OIDCSession{
		ClientID: resourceTestClientID, UserID: "identity-42", Username: "alice", RedirectURI: resourceTestRedirectURI,
		Scopes: []string{definitions.ScopeOpenID}, CodeChallenge: challenge, CodeChallengeMethod: oidcPKCEChallengeMethodS256,
		DiagnosticFlowRef: flowRef,
	}, canonicalOIDCAuthorizationCodeTTL)
	if err != nil {
		t.Fatalf("StoreSession() error = %v", err)
	}
}

// TestRejectedRedemptionsReportTheConsumedCode pins one rejection event per consumed code with the stable reason,
// and that a code session without flow reference is never reported.
func TestRejectedRedemptionsReportTheConsumedCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	verifier := strings.Repeat("v", 43)
	challenge := pkceS256Challenge(verifier)
	flowRef := strings.Repeat("a", 32)

	cases := []struct {
		name, client, redirect, verifier, flowRef, reason string
	}{
		{"client mismatch", "mail-rs", resourceTestRedirectURI, verifier, flowRef, "client_mismatch"},
		{"redirect mismatch", resourceTestClientID, "https://evil.example/cb", verifier, flowRef, "redirect_uri_mismatch"},
		{"pkce mismatch", resourceTestClientID, resourceTestRedirectURI, strings.Repeat("w", 43), flowRef, "pkce_mismatch"},
		{"older code session", resourceTestClientID, "https://evil.example/cb", verifier, "", ""},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			handler, emitter := newCompletionEventHandler(t)
			storeRedeemableCode(t, handler, "code-"+strings.ReplaceAll(testCase.name, " ", "-"), testCase.flowRef, challenge)

			answer := postTokenRequestAs(t, handler, testCase.client, url.Values{
				oidcParamGrantType:   {definitions.OIDCFlowAuthorizationCode},
				oidcParamCode:        {"code-" + strings.ReplaceAll(testCase.name, " ", "-")},
				oidcParamRedirectURI: {testCase.redirect}, oidcParamCodeVerifier: {testCase.verifier},
			})
			if answer[definitions.LogKeyError] != oidcErrorInvalidGrant {
				t.Fatalf("answer = %v, want unchanged invalid_grant", answer)
			}

			events := emitter.snapshot()
			if testCase.reason == "" {
				if len(events) != 0 {
					t.Fatalf("events = %+v, want none for a code session without flow reference", events)
				}

				return
			}

			if len(events) != 1 || events[0].FlowRef != flowRef {
				t.Fatalf("events = %+v, want one event of flow %s", events, flowRef)
			}

			assertCompletionEvent(t, events[0], pluginapi.AuthEventOIDCCodeRedemption, pluginapi.AuthEventRejected,
				testCase.reason, pluginapi.AuthEventFlowCodeConsumed)
		})
	}
}

// TestCodeRedemptionDetachesTheFlowReferenceFromTokenState pins that the diagnostic reference leaves the consumed
// code session before token issuance, so access and refresh token state never carries it.
func TestCodeRedemptionDetachesTheFlowReferenceFromTokenState(t *testing.T) {
	handler := &OIDCHandler{}
	session := &domainidp.OIDCSession{DiagnosticFlowRef: strings.Repeat("b", 32)}

	redemption := handler.newOIDCCodeRedemption(nil, session)
	if session.DiagnosticFlowRef != "" || redemption.flowRef != strings.Repeat("b", 32) {
		t.Fatalf("session ref = %q, redemption ref = %q, want the reference moved out", session.DiagnosticFlowRef,
			redemption.flowRef)
	}
}

// TestTokenIssueFailuresAreClassified pins the redemption outcome of failed token issuance after the consume.
func TestTokenIssueFailuresAreClassified(t *testing.T) {
	if got := oidcTokenIssueFailure(domainidp.ErrInvalidTarget); got != oidcRedemptionInvalidTarget {
		t.Fatalf("invalid target = %+v", got)
	}

	if got := oidcTokenIssueFailure(errors.New("signing failed")); got != oidcRedemptionTokenIssueError ||
		got.result != pluginapi.AuthEventError {
		t.Fatalf("issue error = %+v", got)
	}
}

// TestCodeTTLMatchesTheIssuanceEventContract pins the stored code lifetime to the lifetime the history assumes for
// the emitted issuance version; changing the TTL without a new event version would misdate old events.
func TestCodeTTLMatchesTheIssuanceEventContract(t *testing.T) {
	lifetime, ok := supporthistory.CodeLifetimeOfIssuanceVersion(int(pluginapi.AuthEventOIDCCodeVersion))
	if !ok || lifetime != canonicalOIDCAuthorizationCodeTTL {
		t.Fatalf("history lifetime = %v %v, stored code TTL = %v", lifetime, ok, canonicalOIDCAuthorizationCodeTTL)
	}
}
