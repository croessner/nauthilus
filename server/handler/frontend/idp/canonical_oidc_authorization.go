// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/frontend"
	"github.com/croessner/nauthilus/v4/server/idp"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/middleware/csrf"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/ksuid"
)

const canonicalOIDCAuthorizationTTL = 10 * time.Minute

type canonicalOIDCAuthorizeSessionBuilder func(
	*gin.Context,
	*cookie.CanonicalSession,
	cookie.SessionIdentity,
	*config.OIDCClient,
	oidcAuthorizeRequest,
) (*idp.OIDCSession, []string, error)

type canonicalOIDCAuthorizeUserLoader func(
	*gin.Context,
	*cookie.CanonicalSession,
	cookie.SessionIdentity,
	*config.OIDCClient,
	[]string,
) (*backend.User, error)

type canonicalOIDCConsentSelection struct {
	session   *cookie.CanonicalSession
	identity  cookie.SessionIdentity
	state     *flowdomain.State
	pending   *idp.OIDCSession
	client    *config.OIDCClient
	challenge string
}

// AuthorizeCanonical validates a fresh OIDC request and starts only typed canonical state.
//
//nolint:gocyclo // Protocol entry keeps parse, validation, session creation, and response handling fail-closed.
func (h *OIDCHandler) AuthorizeCanonical(ctx *gin.Context) {
	if ctx == nil {
		return
	}

	if h == nil || h.deps == nil || h.idp == nil || ctx.Request == nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if rejectDuplicateOIDCAuthorizeParameters(ctx) {
		return
	}

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		return
	}

	client, ok := h.validateOIDCAuthorizeRequest(ctx, &request)
	if !ok {
		return
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	identity, authenticated := session.Identity()
	if !authenticated {
		if request.prompt == oidcClientAuthMethodNone {
			redirectOIDCAuthorizeError(ctx, request.redirectURI, request.state, "login_required")

			return
		}

		_, target, err := startCanonicalOIDCAuthorization(
			ctx.Request.Context(), session, request, ctx.Request.URL.RequestURI(),
		)
		if err != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		ctx.Redirect(http.StatusFound, target)

		return
	}

	resumed, err := resumeCanonicalPendingOIDCEnrollment(
		ctx, session, identity, request,
	)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if resumed {
		return
	}

	h.authorizeCanonicalAuthenticated(ctx, session, identity, client, request)
}

// resumeCanonicalPendingOIDCEnrollment keeps one interactive client on the
// original parent flow until its required enrollment chain is complete.
func resumeCanonicalPendingOIDCEnrollment(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	request oidcAuthorizeRequest,
) (bool, error) {
	if ctx == nil || ctx.Request == nil || session == nil || session.Stores == nil ||
		request.prompt == oidcClientAuthMethodNone ||
		strings.TrimSpace(ctx.Query(flowdomain.FlowTicketParameter)) != "" {
		return false, nil
	}

	for _, handle := range session.Anchor.Value.Enrollments {
		target, err := canonicalPendingOIDCEnrollmentTarget(
			ctx.Request.Context(), session, handle, identity, request,
		)
		if err != nil {
			return false, err
		}

		if target == "" {
			continue
		}

		ctx.Redirect(http.StatusFound, target)

		return true, nil
	}

	return false, nil
}

func canonicalPendingOIDCEnrollmentTarget(
	ctx context.Context,
	session *cookie.CanonicalSession,
	handle sessionstate.Handle,
	identity cookie.SessionIdentity,
	request oidcAuthorizeRequest,
) (string, error) {
	enrollment, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(ctx, handle)

	if errors.Is(err, sessionstate.ErrNotFound) || errors.Is(err, sessionstate.ErrExpired) {
		return "", nil
	}

	if err != nil {
		return "", err
	}

	if enrollment.Value.Completed || enrollment.Value.IdentityReference != identity.Reference ||
		enrollment.Value.AccountReference != identity.Account {
		return "", nil
	}

	parent, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(ctx, string(enrollment.Value.Flow))
	if errors.Is(err, flowdomain.ErrFlowNotFound) || errors.Is(err, sessionstate.ErrNotFound) {
		return "", nil
	}

	if err != nil {
		return "", err
	}

	if !canonicalOIDCEnrollmentParentBound(parent, request) {
		return "", nil
	}

	target := canonicalRequiredMFARegistrationTarget(enrollment.Value.CurrentStep)
	if target == "" {
		return "", sessionstate.ErrBindingMismatch
	}

	return flowdomain.AppendTicket(target, string(handle)), nil
}

func canonicalOIDCEnrollmentParentBound(parent *flowdomain.State, request oidcAuthorizeRequest) bool {
	return parent != nil && parent.Type == flowdomain.FlowTypeOIDCAuthorization &&
		parent.Protocol == flowdomain.FlowProtocolOIDC && parent.AuthOutcome == flowdomain.AuthOutcomeOK &&
		parent.Metadata[flowdomain.FlowMetadataClientID] == request.clientID &&
		parent.Metadata[flowdomain.FlowMetadataRedirectURI] == request.redirectURI
}

//nolint:gocyclo,funlen // Authenticated authorization binds policy, consent, claims, and single-use issuance.
func (h *OIDCHandler) authorizeCanonicalAuthenticated(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	client *config.OIDCClient,
	request oidcAuthorizeRequest,
) {
	state, err := h.canonicalAuthorizeState(ctx, session, request)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if !h.canonicalAuthorizePolicyReady(ctx, session, state, identity) {
		return
	}

	builder := h.canonicalAuthorizeSessionBuilder
	if builder == nil {
		builder = h.buildCanonicalOIDCAuthorizeSession
	}

	oidcSession, _, err := builder(ctx, session, identity, client, request)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	needsConsent, err := h.canonicalOIDCAuthorizeNeedsConsent(
		ctx.Request.Context(), session, identity, client, oidcSession.Scopes, request.prompt,
	)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if needsConsent {
		if request.prompt == oidcClientAuthMethodNone {
			if err = consumeCanonicalOIDCAuthorization(
				ctx.Request.Context(), session, state.FlowID,
			); err != nil {
				ctx.AbortWithStatus(http.StatusConflict)

				return
			}

			redirectOIDCAuthorizeError(ctx, request.redirectURI, request.state, "consent_required")

			return
		}

		challenge := ksuid.New().String()
		if err = h.storage.StoreSession(
			ctx.Request.Context(), "consent:"+challenge, oidcSession, canonicalOIDCAuthorizationTTL,
		); err != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		target, bindErr := bindCanonicalOIDCConsent(
			ctx.Request.Context(), session, state.FlowID, challenge,
		)
		if bindErr != nil {
			_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+challenge)
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		ctx.Redirect(http.StatusFound, target)

		return
	}

	if err = consumeCanonicalOIDCAuthorization(ctx.Request.Context(), session, state.FlowID); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	code := ksuid.New().String()
	if err = h.storage.StoreSession(
		ctx.Request.Context(), code, oidcSession, canonicalOIDCAuthorizationTTL,
	); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if err = h.idp.TouchDynamicClient(ctx.Request.Context(), client, "authorization"); err != nil {
		_ = h.storage.DeleteSession(ctx.Request.Context(), code)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if err = session.RecordOIDCClient(ctx.Request.Context(), identity, client.ClientID); err != nil {
		_ = h.storage.DeleteSession(ctx.Request.Context(), code)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	target, err := buildOIDCCallbackRedirectURL(request.redirectURI, code, request.state)
	if err != nil {
		_ = h.storage.DeleteSession(ctx.Request.Context(), code)
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("oidc", "success").Inc()
	ctx.Redirect(http.StatusFound, target)
}

//nolint:gocyclo // Consent choice combines explicit prompt rules with one typed remembered grant.
func (h *OIDCHandler) canonicalOIDCAuthorizeNeedsConsent(
	ctx context.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	client *config.OIDCClient,
	requestedScopes []string,
	prompt string,
) (bool, error) {
	if session == nil || session.Stores == nil || session.Stores.Consent == nil || client == nil {
		return false, sessionstate.ErrBindingMismatch
	}

	if prompt == "consent" || client.Dynamic {
		return true, nil
	}

	if client.SkipConsent {
		return false, nil
	}

	reference, err := sessionstate.ConsentGrantReference(identity.Reference, client.ClientID)
	if err != nil {
		return false, err
	}

	grant, err := session.Stores.Consent.Load(ctx, reference)
	if errors.Is(err, sessionstate.ErrNotFound) || errors.Is(err, sessionstate.ErrExpired) {
		return true, nil
	}

	if err != nil {
		return false, err
	}

	if !grant.Value.Covers(requestedScopes, session.EvaluationTime()) {
		return true, nil
	}

	return false, nil
}

//nolint:gocyclo,funlen // Session construction validates the complete typed identity, scope, and assurance projection.
func (h *OIDCHandler) buildCanonicalOIDCAuthorizeSession(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	client *config.OIDCClient,
	request oidcAuthorizeRequest,
) (*idp.OIDCSession, []string, error) {
	if h == nil || h.idp == nil || ctx == nil || session == nil || client == nil {
		return nil, nil, sessionstate.ErrBindingMismatch
	}

	filteredScopes := h.idp.FilterScopes(client, strings.Fields(request.scope))
	assurance, mfaCompleted := session.Assurance(session.EvaluationTime())

	mfaMethod := ""
	if mfaCompleted {
		mfaMethod = assurance.Method
	}

	loader := h.canonicalAuthorizeUserLoader
	if loader == nil {
		loader = func(
			requestCtx *gin.Context,
			canonical *cookie.CanonicalSession,
			canonicalIdentity cookie.SessionIdentity,
			oidcClient *config.OIDCClient,
			scopes []string,
		) (*backend.User, error) {
			return h.idp.GetUserByUsernameForOIDCClaimsCanonical(
				requestCtx,
				canonicalIdentity.Account,
				oidcClient,
				scopes,
				canonicalRemoteBackendRef(canonical),
				core.IDPRequestContext{
					GrantType: definitions.OIDCFlowAuthorizationCode, RedirectURI: request.redirectURI,
					RequestedScopes: append([]string(nil), scopes...),
					MFACompleted:    mfaCompleted, MFAMethod: mfaMethod,
				},
			)
		}
	}

	user, err := loader(ctx, session, identity, client, filteredScopes)
	if err != nil {
		return nil, nil, err
	}

	if user == nil || strings.TrimSpace(user.ID) != identity.Reference ||
		strings.TrimSpace(user.Name) != identity.Account {
		return nil, nil, sessionstate.ErrBindingMismatch
	}

	idTokenClaims, accessTokenClaims, err := h.idp.GetClaims(ctx, user, client, filteredScopes)
	if err != nil {
		return nil, nil, err
	}

	return &idp.OIDCSession{
		ClientID: request.clientID, UserID: user.ID, Username: user.Name, DisplayName: user.DisplayName,
		Scopes: filteredScopes, RedirectURI: request.redirectURI, AuthTime: session.Anchor.Value.CreatedAt,
		MFACompleted: mfaCompleted, MFAMethod: mfaMethod, Nonce: request.nonce,
		CodeChallenge: request.codeChallenge, CodeChallengeMethod: request.codeChallengeMethod,
		IDTokenClaims: idTokenClaims, AccessTokenClaims: accessTokenClaims,
		RequiredMFALevel: client.RequiredMFALevel,
	}, filteredScopes, nil
}

func startCanonicalOIDCAuthorization(
	ctx context.Context,
	session *cookie.CanonicalSession,
	request oidcAuthorizeRequest,
	resumeTarget string,
) (*flowdomain.State, string, error) {
	if session == nil || session.Stores == nil || session.Handle == "" ||
		strings.TrimSpace(request.clientID) == "" || strings.TrimSpace(request.redirectURI) == "" ||
		request.responseType != oidcResponseTypeCode || !validCanonicalOIDCResumeTarget(resumeTarget) {
		return nil, "", sessionstate.ErrBindingMismatch
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		return nil, "", err
	}

	state := &flowdomain.State{
		FlowID: string(handle), Type: flowdomain.FlowTypeOIDCAuthorization,
		Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepStart,
		AuthOutcome: flowdomain.AuthOutcomeUnknown, GrantType: definitions.OIDCFlowAuthorizationCode,
		ReturnTarget: frontendLoginPath,
		Metadata: map[string]string{
			flowdomain.FlowMetadataClientID:            request.clientID,
			flowdomain.FlowMetadataRedirectURI:         request.redirectURI,
			flowdomain.FlowMetadataScope:               request.scope,
			flowdomain.FlowMetadataState:               request.state,
			flowdomain.FlowMetadataNonce:               request.nonce,
			flowdomain.FlowMetadataResponseType:        request.responseType,
			flowdomain.FlowMetadataPrompt:              request.prompt,
			flowdomain.FlowMetadataCodeChallenge:       request.codeChallenge,
			flowdomain.FlowMetadataCodeChallengeMethod: request.codeChallengeMethod,
			flowdomain.FlowMetadataResumeTarget:        resumeTarget,
		},
	}
	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL,
	)

	decision, err := flowdomain.NewController(store).
		StartAtStep(ctx, state, flowdomain.FlowStepLogin, session.EvaluationTime())
	if err != nil {
		return nil, "", err
	}

	return state, decision.RedirectURI, nil
}

func bindCanonicalOIDCConsent(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
	challenge string,
) (string, error) {
	challenge = strings.TrimSpace(challenge)
	if challenge == "" || len(challenge) > 256 {
		return "", sessionstate.ErrBindingMismatch
	}

	store, state, err := loadCanonicalOIDCAuthorization(ctx, session, flowID)
	if err != nil {
		return "", err
	}

	if state.AuthOutcome != flowdomain.AuthOutcomeOK ||
		(state.CurrentStep != flowdomain.FlowStepLogin && state.CurrentStep != flowdomain.FlowStepMFA) {
		return "", sessionstate.ErrBindingMismatch
	}

	policy, err := flowdomain.PolicyForFlowType(state.Type)
	if err != nil || !policy.CanTransition(state.CurrentStep, flowdomain.FlowStepConsent) {
		return "", sessionstate.ErrBindingMismatch
	}

	state.CurrentStep = flowdomain.FlowStepConsent
	state.Metadata[flowdomain.FlowMetadataConsentChallenge] = challenge
	state.Normalize(session.EvaluationTime())

	if err = store.Save(ctx, state); err != nil {
		return "", err
	}

	query := url.Values{"consent_challenge": {challenge}}
	if protocolState := state.Metadata[flowdomain.FlowMetadataState]; protocolState != "" {
		query.Set(oidcParamState, protocolState)
	}

	return flowdomain.AppendTicket("/oidc/consent?"+query.Encode(), state.FlowID), nil
}

func loadCanonicalOIDCConsent(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
	challenge string,
) (*flowdomain.State, error) {
	_, state, err := loadCanonicalOIDCAuthorization(ctx, session, flowID)
	if err != nil {
		return nil, err
	}

	if state.CurrentStep != flowdomain.FlowStepConsent || state.AuthOutcome != flowdomain.AuthOutcomeOK ||
		strings.TrimSpace(challenge) == "" ||
		state.Metadata[flowdomain.FlowMetadataConsentChallenge] != strings.TrimSpace(challenge) {
		return nil, sessionstate.ErrBindingMismatch
	}

	return state, nil
}

func canonicalOIDCConsentParameters(ctx *gin.Context, requireDecision bool) (string, string, error) {
	if ctx == nil || ctx.Request == nil || ctx.Request.ParseForm() != nil ||
		len(ctx.Request.Form[flowdomain.FlowTicketParameter]) != 1 ||
		len(ctx.Request.Form["consent_challenge"]) != 1 {
		return "", "", sessionstate.ErrBindingMismatch
	}

	if requireDecision && len(ctx.Request.Form["submit"]) != 1 {
		return "", "", sessionstate.ErrBindingMismatch
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		return "", "", err
	}

	challenge := strings.TrimSpace(ctx.Request.Form.Get("consent_challenge"))
	if challenge == "" || len(challenge) > 256 {
		return "", "", sessionstate.ErrBindingMismatch
	}

	return string(ticket), challenge, nil
}

//nolint:gocyclo,funlen // Consent loading validates every browser ticket and typed flow binding before rendering.
func (h *OIDCHandler) loadCanonicalOIDCConsentSelection(
	ctx *gin.Context,
	consumePending bool,
) (canonicalOIDCConsentSelection, error) {
	var selection canonicalOIDCConsentSelection
	if h == nil || h.idp == nil || h.storage == nil || ctx == nil {
		return selection, sessionstate.ErrBindingMismatch
	}

	selection.session = cookie.GetCanonicalSession(ctx)
	if selection.session == nil {
		return selection, sessionstate.ErrBindingMismatch
	}

	var ok bool

	selection.identity, ok = selection.session.Identity()
	if !ok {
		return selection, sessionstate.ErrBindingMismatch
	}

	flowID, challenge, err := canonicalOIDCConsentParameters(ctx, consumePending)
	if err != nil {
		return selection, err
	}

	selection.challenge = challenge

	selection.state, err = loadCanonicalOIDCConsent(
		ctx.Request.Context(), selection.session, flowID, challenge,
	)
	if err != nil {
		return selection, err
	}

	if consumePending {
		selection.pending, err = h.storage.ConsumeSession(ctx.Request.Context(), "consent:"+challenge)
	} else {
		selection.pending, err = h.storage.GetSession(ctx.Request.Context(), "consent:"+challenge)
	}

	if err != nil {
		return selection, err
	}

	selection.client, err = h.idp.ResolveClient(
		ctx.Request.Context(), selection.state.Metadata[flowdomain.FlowMetadataClientID],
	)
	if err != nil {
		return selection, err
	}

	if err = h.validateCanonicalOIDCConsentSelection(selection); err != nil {
		if !consumePending {
			_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+challenge)
		}

		_ = discardCanonicalOIDCConsent(ctx.Request.Context(), selection.session, selection.state)

		return selection, err
	}

	return selection, nil
}

func (h *OIDCHandler) validateCanonicalOIDCConsentSelection(selection canonicalOIDCConsentSelection) error {
	if selection.state == nil || selection.pending == nil || selection.client == nil ||
		selection.pending.ClientID != selection.state.Metadata[flowdomain.FlowMetadataClientID] ||
		selection.pending.RedirectURI != selection.state.Metadata[flowdomain.FlowMetadataRedirectURI] ||
		selection.pending.UserID != selection.identity.Reference ||
		selection.pending.Username != selection.identity.Account ||
		selection.pending.Nonce != selection.state.Metadata[flowdomain.FlowMetadataNonce] ||
		selection.pending.CodeChallenge != selection.state.Metadata[flowdomain.FlowMetadataCodeChallenge] ||
		selection.pending.CodeChallengeMethod != selection.state.Metadata[flowdomain.FlowMetadataCodeChallengeMethod] {
		return sessionstate.ErrBindingMismatch
	}

	expectedScopes := h.idp.FilterScopes(
		selection.client, strings.Fields(selection.state.Metadata[flowdomain.FlowMetadataScope]),
	)
	if !slices.Equal(selection.pending.Scopes, expectedScopes) {
		return sessionstate.ErrBindingMismatch
	}

	return nil
}

func discardCanonicalOIDCConsent(
	ctx context.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
) error {
	if session == nil || state == nil {
		return sessionstate.ErrBindingMismatch
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL,
	)
	_, err := store.ConsumeOIDC(ctx, state.FlowID, state.Revision)

	return err
}

func canonicalOIDCConsentFailureStatus(err error) int {
	if errors.Is(err, redis.Nil) || errors.Is(err, sessionstate.ErrBindingMismatch) ||
		errors.Is(err, sessionstate.ErrNotFound) || errors.Is(err, flowdomain.ErrFlowNotFound) ||
		errors.Is(err, sessionstate.ErrRevisionConflict) {
		return http.StatusConflict
	}

	return http.StatusServiceUnavailable
}

func (h *OIDCHandler) canonicalOIDCConsentPageData(
	ctx *gin.Context,
	selection canonicalOIDCConsentSelection,
) gin.H {
	data := canonicalBasePageData(
		ctx, h.deps.Cfg, h.deps.LangManager, selection.identity,
		definitions.ProtoOIDC, selection.client.ClientID, "",
	)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Consent")
	data["Application"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Application")
	data["WantsToAccessYourAccount"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "wants to access your account",
	)
	data["RequestedPermissions"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "Requested permissions",
	)
	data["Allow"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Allow")
	data["Deny"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deny")
	data["ReturnTo"] = ctx.Request.URL.String()

	plan := buildConsentScopePlan(
		selection.client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), selection.pending.Scopes,
	)
	customScopes := h.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(selection.client)
	data["ClientID"] = selection.pending.ClientID
	data["Scopes"] = consentScopeDescriptions(
		ctx, h.deps.Cfg, h.deps.Logger, customScopes, plan.Required,
	)
	data["ConsentModeGranularOptional"] = plan.Mode == config.OIDCConsentModeGranularOptional
	data["OptionalScopeChoices"] = h.oidcConsentOptionalScopeChoices(ctx, selection.client, plan)
	data["NoAdditionalPermissions"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, consentMsgNoAdditional,
	)
	data["ConsentChallenge"] = selection.challenge
	data["State"] = selection.state.Metadata[flowdomain.FlowMetadataState]
	data["FlowTicket"] = selection.state.FlowID
	data["PostConsentEndpoint"] = ctx.Request.URL.Path
	data["CSRFToken"] = csrf.Token(ctx)

	return data
}

// ConsentGETCanonical renders only a consent record bound to this canonical session and typed flow.
func (h *OIDCHandler) ConsentGETCanonical(ctx *gin.Context) {
	selection, err := h.loadCanonicalOIDCConsentSelection(ctx, false)
	if err != nil {
		ctx.AbortWithStatus(canonicalOIDCConsentFailureStatus(err))

		return
	}

	ctx.HTML(http.StatusOK, "idp_consent.html", h.canonicalOIDCConsentPageData(ctx, selection))
}

func canonicalOIDCAuthorizeRequestFromState(state *flowdomain.State) oidcAuthorizeRequest {
	metadata := state.Metadata

	return oidcAuthorizeRequest{
		clientID:            metadata[flowdomain.FlowMetadataClientID],
		redirectURI:         metadata[flowdomain.FlowMetadataRedirectURI],
		scope:               metadata[flowdomain.FlowMetadataScope],
		state:               metadata[flowdomain.FlowMetadataState],
		nonce:               metadata[flowdomain.FlowMetadataNonce],
		responseType:        metadata[flowdomain.FlowMetadataResponseType],
		prompt:              metadata[flowdomain.FlowMetadataPrompt],
		codeChallenge:       metadata[flowdomain.FlowMetadataCodeChallenge],
		codeChallengeMethod: metadata[flowdomain.FlowMetadataCodeChallengeMethod],
	}
}

func (h *OIDCHandler) canonicalOIDCConsentPolicySatisfied(
	ctx *gin.Context,
	selection canonicalOIDCConsentSelection,
) bool {
	frontendHandler := h.frontend
	if frontendHandler == nil {
		frontendHandler = &FrontendHandler{deps: h.deps}
	}

	policy, ok := frontendHandler.canonicalFlowMFAPolicy(ctx.Request.Context(), selection.state)
	if !ok {
		return false
	}

	missing, ok := frontendHandler.canonicalMissingEnrollment(
		ctx, selection.session, selection.state, selection.identity, policy.required,
	)
	if !ok || len(missing) != 0 {
		return false
	}

	return canonicalSessionSatisfiesMFAPolicy(
		selection.session, policy, selection.session.EvaluationTime(),
	)
}

func (h *OIDCHandler) applyCanonicalOIDCConsentScopes(
	ctx *gin.Context,
	selection canonicalOIDCConsentSelection,
) (*idp.OIDCSession, error) {
	plan := buildConsentScopePlan(
		selection.client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), selection.pending.Scopes,
	)

	granted, err := plan.ResolveGranted(ctx.PostFormArray("optional_scope"))
	if err != nil {
		return nil, err
	}

	if slices.Equal(granted, selection.pending.Scopes) {
		return selection.pending, nil
	}

	request := canonicalOIDCAuthorizeRequestFromState(selection.state)
	request.scope = strings.Join(granted, " ")

	builder := h.canonicalAuthorizeSessionBuilder
	if builder == nil {
		builder = h.buildCanonicalOIDCAuthorizeSession
	}

	rebuilt, _, err := builder(ctx, selection.session, selection.identity, selection.client, request)
	if err != nil {
		return nil, err
	}

	return rebuilt, nil
}

func (h *OIDCHandler) persistCanonicalOIDCConsentGrant(
	ctx context.Context,
	selection canonicalOIDCConsentSelection,
	pending *idp.OIDCSession,
) error {
	if selection.session == nil || selection.session.Stores == nil ||
		selection.session.Stores.Consent == nil || pending == nil {
		return sessionstate.ErrBindingMismatch
	}

	reference, err := sessionstate.ConsentGrantReference(
		selection.identity.Reference, selection.client.ClientID,
	)
	if err != nil {
		return err
	}

	scopes, err := sessionstate.NormalizeConsentScopes(pending.Scopes)
	if err != nil {
		return err
	}

	ttl := consentTTLForClient(h.deps.Cfg, selection.client)
	if ttl <= 0 {
		return sessionstate.ErrInvalidTTL
	}

	now := selection.session.EvaluationTime()
	grant := sessionstate.ConsentGrant{
		Record:            sessionstate.Record{Handle: reference.Record},
		IdentityReference: selection.identity.Reference,
		ClientID:          selection.client.ClientID,
		Scopes:            scopes,
		GrantedAt:         now,
		GrantExpiresAt:    now.Add(ttl),
	}

	for range 2 {
		expected := sessionstate.Revision(0)

		current, loadErr := selection.session.Stores.Consent.Load(ctx, reference)
		switch {
		case loadErr == nil:
			expected = current.Revision
		case errors.Is(loadErr, sessionstate.ErrNotFound), errors.Is(loadErr, sessionstate.ErrExpired):
		default:
			return loadErr
		}

		_, err = selection.session.Stores.Consent.Commit(
			ctx,
			sessionstate.CommitRequest[sessionstate.ConsentGrant]{
				Reference: reference, ExpectedRevision: expected, Value: grant, TTL: ttl,
			},
		)
		if !errors.Is(err, sessionstate.ErrRevisionConflict) {
			return err
		}
	}

	return sessionstate.ErrRevisionConflict
}

func abortCanonicalOIDCConsent(
	ctx *gin.Context,
	selection canonicalOIDCConsentSelection,
	status int,
) {
	if err := discardCanonicalOIDCConsent(
		ctx.Request.Context(), selection.session, selection.state,
	); err != nil && !errors.Is(err, sessionstate.ErrNotFound) {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	ctx.AbortWithStatus(status)
}

// ConsentPOSTCanonical consumes one bound consent decision and issues at most one authorization code.
//
//nolint:funlen // Consent POST keeps scope resolution, grant publication, code issuance, and cleanup ordered.
func (h *OIDCHandler) ConsentPOSTCanonical(ctx *gin.Context) {
	selection, err := h.loadCanonicalOIDCConsentSelection(ctx, true)
	if err != nil {
		ctx.AbortWithStatus(canonicalOIDCConsentFailureStatus(err))

		return
	}

	if ctx.PostForm("submit") != oidcConsentDecisionAllow {
		if err = discardCanonicalOIDCConsent(
			ctx.Request.Context(), selection.session, selection.state,
		); err != nil {
			ctx.AbortWithStatus(canonicalOIDCConsentFailureStatus(err))

			return
		}

		stats.GetMetrics().GetIdpConsentTotal().
			WithLabelValues(oidcMetricClientID(selection.client.ClientID), "deny").Inc()
		ctx.String(http.StatusForbidden, "Consent denied")

		return
	}

	if !h.canonicalOIDCConsentPolicySatisfied(ctx, selection) {
		abortCanonicalOIDCConsent(ctx, selection, http.StatusConflict)

		return
	}

	pending, err := h.applyCanonicalOIDCConsentScopes(ctx, selection)
	if err != nil {
		abortCanonicalOIDCConsent(ctx, selection, http.StatusBadRequest)

		return
	}

	if err = h.persistCanonicalOIDCConsentGrant(ctx.Request.Context(), selection, pending); err != nil {
		abortCanonicalOIDCConsent(ctx, selection, http.StatusServiceUnavailable)

		return
	}

	code := ksuid.New().String()

	target, err := buildOIDCCallbackRedirectURL(
		pending.RedirectURI, code, selection.state.Metadata[flowdomain.FlowMetadataState],
	)
	if err != nil {
		abortCanonicalOIDCConsent(ctx, selection, http.StatusInternalServerError)

		return
	}

	if err = completeCanonicalOIDCAuthorization(
		ctx.Request.Context(), selection.session, selection.state.FlowID, selection.challenge,
	); err != nil {
		ctx.AbortWithStatus(canonicalOIDCConsentFailureStatus(err))

		return
	}

	if err = h.storage.StoreSession(
		ctx.Request.Context(), code, pending, canonicalOIDCAuthorizationTTL,
	); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if err = h.idp.TouchDynamicClient(
		ctx.Request.Context(), selection.client, "authorization",
	); err != nil {
		_ = h.storage.DeleteSession(ctx.Request.Context(), code)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if err = selection.session.RecordOIDCClient(
		ctx.Request.Context(), selection.identity, selection.client.ClientID,
	); err != nil {
		_ = h.storage.DeleteSession(ctx.Request.Context(), code)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	stats.GetMetrics().GetIdpConsentTotal().
		WithLabelValues(oidcMetricClientID(selection.client.ClientID), oidcConsentDecisionAllow).Inc()
	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("oidc", "success").Inc()
	ctx.Redirect(http.StatusFound, target)
}

func completeCanonicalOIDCAuthorization(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
	challenge string,
) error {
	store, state, err := loadCanonicalOIDCAuthorization(ctx, session, flowID)
	if err != nil {
		return err
	}

	if state.CurrentStep != flowdomain.FlowStepConsent || state.AuthOutcome != flowdomain.AuthOutcomeOK ||
		state.Metadata[flowdomain.FlowMetadataConsentChallenge] != strings.TrimSpace(challenge) {
		return sessionstate.ErrBindingMismatch
	}

	state.CurrentStep = flowdomain.FlowStepCallback
	state.Normalize(session.EvaluationTime())

	if err = store.Save(ctx, state); err != nil {
		return err
	}

	_, err = store.ConsumeOIDC(ctx, state.FlowID, state.Revision)

	return err
}

func loadCanonicalOIDCAuthorization(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
) (*flowdomain.TypedStore, *flowdomain.State, error) {
	if session == nil || session.Stores == nil || session.Handle == "" {
		return nil, nil, sessionstate.ErrBindingMismatch
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL,
	)

	state, err := store.Load(ctx, flowID)
	if err != nil {
		return nil, nil, err
	}

	if state.Type != flowdomain.FlowTypeOIDCAuthorization ||
		state.Protocol != flowdomain.FlowProtocolOIDC || state.Metadata == nil {
		return nil, nil, sessionstate.ErrBindingMismatch
	}

	return store, state, nil
}

func validCanonicalOIDCResumeTarget(target string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(target))
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return false
	}

	const authorizePath = "/oidc/authorize"
	if parsed.Path == authorizePath {
		return true
	}

	languageTag := strings.TrimPrefix(parsed.Path, authorizePath+"/")

	return languageTag != parsed.Path && languageTag != "" && len(languageTag) <= 64 &&
		!strings.ContainsAny(languageTag, "/\\")
}

func (h *OIDCHandler) canonicalAuthorizeState(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	request oidcAuthorizeRequest,
) (*flowdomain.State, error) {
	ticket, ticketErr := flowdomain.TicketFromRequest(ctx.Request)
	if ticketErr == nil {
		_, state, err := loadCanonicalOIDCAuthorization(ctx.Request.Context(), session, string(ticket))
		if err != nil {
			return nil, err
		}

		if !oidcAuthorizeRequestMatchesMetadata(state.Metadata, request) ||
			state.AuthOutcome != flowdomain.AuthOutcomeOK ||
			(state.CurrentStep != flowdomain.FlowStepLogin && state.CurrentStep != flowdomain.FlowStepMFA) {
			return nil, sessionstate.ErrBindingMismatch
		}

		return state, nil
	}

	if strings.TrimSpace(ctx.Query(flowdomain.FlowTicketParameter)) != "" {
		return nil, sessionstate.ErrBindingMismatch
	}

	state, _, err := startCanonicalOIDCAuthorization(
		ctx.Request.Context(), session, request, ctx.Request.URL.RequestURI(),
	)
	if err != nil {
		return nil, err
	}

	state.AuthOutcome = flowdomain.AuthOutcomeOK

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL,
	)
	if err = store.Save(ctx.Request.Context(), state); err != nil {
		return nil, err
	}

	return state, nil
}

//nolint:gocyclo // Policy readiness owns enrollment, step-up, and final assurance branching as one gate.
func (h *OIDCHandler) canonicalAuthorizePolicyReady(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
) bool {
	frontendHandler := h.frontend
	if frontendHandler == nil {
		frontendHandler = &FrontendHandler{deps: h.deps}
	}

	policy, ok := frontendHandler.canonicalFlowMFAPolicy(ctx.Request.Context(), state)
	if !ok {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	missing, ok := frontendHandler.canonicalMissingEnrollment(ctx, session, state, identity, policy.required)
	if !ok {
		return false
	}

	satisfied := canonicalSessionSatisfiesMFAPolicy(session, policy, session.EvaluationTime())
	if canonicalPromptNone(state) && (len(missing) > 0 || !satisfied) {
		store := flowdomain.NewTypedStore(
			session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL,
		)
		if err := store.Delete(ctx.Request.Context(), state.FlowID); err != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return false
		}

		redirectOIDCAuthorizeError(
			ctx, state.Metadata[flowdomain.FlowMetadataRedirectURI],
			state.Metadata[flowdomain.FlowMetadataState], "interaction_required",
		)

		return false
	}

	if len(missing) > 0 {
		if !frontendHandler.startCanonicalRequiredMFAEnrollment(ctx, session, state, identity, missing) &&
			!ctx.Writer.Written() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return false
	}

	if !satisfied {
		if !frontendHandler.startCanonicalMFAAssuranceStepUp(ctx, session, state, identity, policy) &&
			!ctx.Writer.Written() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return false
	}

	return true
}

func consumeCanonicalOIDCAuthorization(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
) error {
	store, state, err := loadCanonicalOIDCAuthorization(ctx, session, flowID)
	if err != nil {
		return err
	}

	if state.AuthOutcome != flowdomain.AuthOutcomeOK ||
		(state.CurrentStep != flowdomain.FlowStepLogin && state.CurrentStep != flowdomain.FlowStepMFA) {
		return sessionstate.ErrBindingMismatch
	}

	policy, err := flowdomain.PolicyForFlowType(state.Type)
	if err != nil || !policy.CanTransition(state.CurrentStep, flowdomain.FlowStepCallback) {
		return sessionstate.ErrBindingMismatch
	}

	state.CurrentStep = flowdomain.FlowStepCallback
	state.Normalize(session.EvaluationTime())

	if err = store.Save(ctx, state); err != nil {
		return err
	}

	_, err = store.ConsumeOIDC(ctx, state.FlowID, state.Revision)

	return err
}
