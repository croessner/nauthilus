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
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/idp"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/sessionstate"

	"github.com/gin-gonic/gin"
)

// canonicalOIDCAuthorizationCodeTTL is the lifetime of one stored authorization code. Version 1 of the
// oidc.code_issuance event contract pins it to ten minutes after the observed issuance; a change requires a new
// pluginapi.AuthEventOIDCCodeVersion.
const canonicalOIDCAuthorizationCodeTTL = 10 * time.Minute

const (
	// oidcCompletionProtocol is the protocol of every OIDC completion event.
	oidcCompletionProtocol = "oidc"
	// oidcIssuanceAuthenticationNotRecorded marks a flow record written by a release without the source field.
	oidcIssuanceAuthenticationNotRecorded = "not_recorded"
)

// oidcCodeRedemptionOutcome is the bounded classification of one consumed authorization code.
type oidcCodeRedemptionOutcome struct {
	result     pluginapi.AuthEventResult
	reason     string
	flowEffect pluginapi.AuthEventFlowEffect
}

var (
	oidcRedemptionTokensIssued = oidcCodeRedemptionOutcome{
		result: pluginapi.AuthEventSuccess, reason: "tokens_issued", flowEffect: pluginapi.AuthEventFlowTokensIssued,
	}
	oidcRedemptionClientMismatch   = newOIDCRedemptionFailure(pluginapi.AuthEventRejected, "client_mismatch")
	oidcRedemptionRedirectMismatch = newOIDCRedemptionFailure(pluginapi.AuthEventRejected, "redirect_uri_mismatch")
	oidcRedemptionPKCEMismatch     = newOIDCRedemptionFailure(pluginapi.AuthEventRejected, "pkce_mismatch")
	oidcRedemptionInvalidTarget    = newOIDCRedemptionFailure(pluginapi.AuthEventRejected, "invalid_target")
	oidcRedemptionTokenIssueError  = newOIDCRedemptionFailure(pluginapi.AuthEventError, "token_issue_error")
	oidcRedemptionClientStateError = newOIDCRedemptionFailure(pluginapi.AuthEventError, "client_state_error")
)

// newOIDCRedemptionFailure builds the outcome of a consumed code that produced no tokens.
func newOIDCRedemptionFailure(result pluginapi.AuthEventResult, reason string) oidcCodeRedemptionOutcome {
	return oidcCodeRedemptionOutcome{result: result, reason: reason, flowEffect: pluginapi.AuthEventFlowCodeConsumed}
}

// oidcTokenIssueFailure classifies a failed token issuance after the code was consumed.
func oidcTokenIssueFailure(err error) oidcCodeRedemptionOutcome {
	if errors.Is(err, idp.ErrInvalidTarget) {
		return oidcRedemptionInvalidTarget
	}

	return oidcRedemptionTokenIssueError
}

// authenticationEventEmitter returns the step-event emitter of the OIDC handler: the test override, otherwise the
// emitter of the frontend handler that owns the browser flows.
func (h *OIDCHandler) authenticationEventEmitter() canonicalAuthEventEmitter {
	if h == nil {
		return nil
	}

	if h.canonicalAuthEventEmitter != nil {
		return h.canonicalAuthEventEmitter
	}

	return h.frontendHandler().authEventEmitter()
}

// frontendHandler returns the configured frontend handler, or a dependency-only one for shared browser-flow helpers.
func (h *OIDCHandler) frontendHandler() *FrontendHandler {
	if h.frontend != nil {
		return h.frontend
	}

	return &FrontendHandler{deps: h.deps}
}

// oidcIssuanceAuthentication maps the persisted authentication source of a flow onto the issuance reason; it never
// guesses a source for records an older release wrote.
func oidcIssuanceAuthentication(state *flowdomain.State) string {
	switch source := state.Metadata[flowdomain.FlowMetadataAuthentication]; source {
	case sessionstate.OIDCFlowAuthenticatedInFlow, sessionstate.OIDCFlowExistingSession:
		return source
	default:
		return oidcIssuanceAuthenticationNotRecorded
	}
}

// emitOIDCCodeIssued records that the browser is redirected to the client with an authorization code. It runs only
// after the code, the client bookkeeping, and the callback URL succeeded, and never carries the code itself.
func (h *OIDCHandler) emitOIDCCodeIssued(
	ctx *gin.Context,
	state *flowdomain.State,
	account string,
	client *config.OIDCClient,
) {
	emitter := h.authenticationEventEmitter()
	if emitter == nil || ctx == nil || ctx.Request == nil || state == nil || client == nil {
		return
	}

	event := newCanonicalAuthEvent(ctx, pluginapi.AuthEventOIDCCodeIssuance, pluginapi.AuthEventOIDCCodeVersion)
	event.FlowRef, event.Protocol, event.ClientID = flowdomain.DiagnosticFlowRef(state.FlowID), oidcCompletionProtocol,
		client.ClientID
	event.Account, event.ClientIP = account, ctx.ClientIP()
	event.Result, event.Reason, event.FlowEffect = pluginapi.AuthEventSuccess, oidcIssuanceAuthentication(state),
		pluginapi.AuthEventFlowCodeIssued

	emitter.EmitAuthEvent(ctx.Request.Context(), event)
}

// oidcCodeRedemption reports the result of one consumed authorization code. It carries the non-authorizing flow
// reference that the code session stored at issuance, detached from the session so it never reaches token state.
type oidcCodeRedemption struct {
	emitter canonicalAuthEventEmitter
	ctx     *gin.Context
	session *idp.OIDCSession
	flowRef string
}

// newOIDCCodeRedemption takes the diagnostic flow reference out of a consumed code session before token issuance.
func (h *OIDCHandler) newOIDCCodeRedemption(ctx *gin.Context, session *idp.OIDCSession) oidcCodeRedemption {
	redemption := oidcCodeRedemption{emitter: h.authenticationEventEmitter(), ctx: ctx, session: session}
	if session != nil {
		redemption.flowRef, session.DiagnosticFlowRef = session.DiagnosticFlowRef, ""
	}

	return redemption
}

// report emits one redemption event. A code session without flow reference (stored by an older release) cannot be
// attributed to a flow and is not reported. The token requester address is never recorded: it is the relying-party
// backend for confidential clients and would read as a user address.
func (r oidcCodeRedemption) report(outcome oidcCodeRedemptionOutcome) {
	if r.emitter == nil || r.ctx == nil || r.ctx.Request == nil || r.session == nil || r.flowRef == "" {
		return
	}

	event := newCanonicalAuthEvent(r.ctx, pluginapi.AuthEventOIDCCodeRedemption, pluginapi.AuthEventOIDCCodeVersion)
	event.FlowRef, event.Protocol, event.ClientID = r.flowRef, oidcCompletionProtocol, r.session.ClientID
	event.Account = r.session.Username
	event.Result, event.Reason, event.FlowEffect = outcome.result, outcome.reason, outcome.flowEffect

	r.emitter.EmitAuthEvent(r.ctx.Request.Context(), event)
}

// authorizationCodeRequestMismatch checks the token request against the consumed code session in the order the
// token endpoint always did; it reports the rejection outcome of the first mismatch.
func authorizationCodeRequestMismatch(
	ctx *gin.Context,
	clientID string,
	session *idp.OIDCSession,
) (oidcCodeRedemptionOutcome, bool) {
	switch {
	case session.ClientID != clientID:
		return oidcRedemptionClientMismatch, true
	case formValue(ctx, oidcParamRedirectURI) != session.RedirectURI:
		return oidcRedemptionRedirectMismatch, true
	case validatePKCEVerifier(session.CodeChallenge, session.CodeChallengeMethod,
		formValue(ctx, oidcParamCodeVerifier)) != nil:
		return oidcRedemptionPKCEMismatch, true
	default:
		return oidcCodeRedemptionOutcome{}, false
	}
}
