// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	domainidp "github.com/croessner/nauthilus/v3/server/idp"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

const canonicalOIDCDeviceTTL = definitions.OIDCDeviceCodeDefaultExpiry

const canonicalOIDCDeviceDigestNamespace = "oidc-device-user-code"

var errCanonicalOIDCDeviceTerminal = errors.New("canonical device authorization already terminal")

type canonicalOIDCDeviceTerminalError struct {
	stage string
	cause error
}

func (e canonicalOIDCDeviceTerminalError) Error() string {
	return fmt.Sprintf("canonical device authorization terminal at %s: %v", e.stage, e.cause)
}

func (e canonicalOIDCDeviceTerminalError) Unwrap() error { return e.cause }

func (e canonicalOIDCDeviceTerminalError) Is(target error) bool {
	return target == errCanonicalOIDCDeviceTerminal || errors.Is(e.cause, target)
}

type canonicalDeviceGrantPersister func(
	context.Context,
	canonicalOIDCConsentSelection,
	*domainidp.OIDCSession,
) error

type canonicalDeviceFlowConsumer func(
	context.Context,
	*flowdomain.TypedStore,
	*flowdomain.State,
) error

type canonicalOIDCDeviceStore interface {
	domainidp.DeviceCodeStore
	ClaimDeviceCodeByUserCode(context.Context, string) (string, *domainidp.DeviceCodeRequest, error)
	CompleteClaimedDeviceCode(context.Context, string, *domainidp.DeviceCodeRequest) error
}

type canonicalOIDCDeviceSelection struct {
	session    *cookie.CanonicalSession
	identity   cookie.SessionIdentity
	state      *flowdomain.State
	request    *domainidp.DeviceCodeRequest
	client     *config.OIDCClient
	deviceCode string
}

func canonicalOIDCDeviceFlowID(ctx *gin.Context, requireDecision bool) (string, error) {
	if ctx == nil || ctx.Request == nil || ctx.Request.ParseForm() != nil ||
		len(ctx.Request.Form[flowdomain.FlowTicketParameter]) != 1 {
		return "", sessionstate.ErrBindingMismatch
	}

	if requireDecision && len(ctx.Request.PostForm["submit"]) != 1 {
		return "", sessionstate.ErrBindingMismatch
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		return "", err
	}

	return string(ticket), nil
}

func canonicalOIDCDeviceConsentStateValid(state *flowdomain.State) bool {
	return state != nil && state.Type == flowdomain.FlowTypeOIDCDeviceCode &&
		state.GrantType == definitions.OIDCFlowDeviceCode &&
		state.CurrentStep == flowdomain.FlowStepConsent && state.AuthOutcome == flowdomain.AuthOutcomeOK &&
		state.Metadata[flowdomain.FlowMetadataResumeTarget] == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete
}

func canonicalOIDCDeviceRequestLive(request *domainidp.DeviceCodeRequest, now time.Time) bool {
	return request != nil && request.VerificationLocked &&
		request.Status == domainidp.DeviceCodeStatusPending && request.ExpiresAt.After(now)
}

func canonicalOIDCDeviceConsentBound(
	request *domainidp.DeviceCodeRequest,
	client *config.OIDCClient,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
	digest string,
) bool {
	return request.ClientID == client.ClientID &&
		slices.Equal(request.Scopes, strings.Fields(state.Metadata[flowdomain.FlowMetadataScope])) &&
		digest == state.Metadata[flowdomain.FlowMetadataDeviceUserCodeDigest] &&
		(request.UserID == "" || request.UserID == identity.Reference) &&
		(request.Username == "" || request.Username == identity.Account)
}

func canonicalOIDCDeviceConsentHandlerReady(
	handler *OIDCHandler,
	session *cookie.CanonicalSession,
) bool {
	return handler != nil && handler.idp != nil && session != nil
}

func (h *OIDCHandler) loadCanonicalOIDCDeviceConsent(
	ctx *gin.Context,
	flowID string,
) (canonicalOIDCDeviceSelection, error) {
	var selection canonicalOIDCDeviceSelection

	session := cookie.GetCanonicalSession(ctx)
	if !canonicalOIDCDeviceConsentHandlerReady(h, session) {
		return selection, sessionstate.ErrBindingMismatch
	}

	identity, authenticated := session.Identity()
	if !authenticated {
		return selection, sessionstate.ErrBindingMismatch
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCDeviceTTL,
	)

	state, err := store.Load(ctx.Request.Context(), flowID)
	if err != nil {
		return selection, err
	}

	if !canonicalOIDCDeviceConsentStateValid(state) {
		return selection, sessionstate.ErrBindingMismatch
	}

	deviceCode := strings.TrimSpace(state.Metadata[flowdomain.FlowMetadataDeviceCode])

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil {
		return selection, canonicalOIDCDeviceStoreError(err)
	}

	if request == nil {
		return selection, sessionstate.ErrBindingMismatch
	}

	client, err := h.idp.ResolveClient(ctx.Request.Context(), state.Metadata[flowdomain.FlowMetadataClientID])
	if err != nil {
		return selection, err
	}

	digest, digestErr := h.canonicalOIDCDeviceDigest(request.UserCode)
	if digestErr != nil || client == nil ||
		!canonicalOIDCDeviceRequestLive(request, session.EvaluationTime()) ||
		!canonicalOIDCDeviceConsentBound(request, client, state, identity, digest) {
		return selection, sessionstate.ErrBindingMismatch
	}

	return canonicalOIDCDeviceSelection{
		session: session, identity: identity, state: state, request: request,
		client: client, deviceCode: deviceCode,
	}, nil
}

func (h *OIDCHandler) canonicalOIDCDeviceConsentPageData(
	ctx *gin.Context,
	selection canonicalOIDCDeviceSelection,
) gin.H {
	pending := &domainidp.OIDCSession{
		ClientID: selection.request.ClientID, UserID: selection.identity.Reference,
		Username: selection.identity.Account, DisplayName: selection.identity.DisplayName,
		Scopes: append([]string(nil), selection.request.Scopes...),
	}
	data := h.canonicalOIDCConsentPageData(ctx, canonicalOIDCConsentSelection{
		session: selection.session, identity: selection.identity, state: selection.state,
		pending: pending, client: selection.client,
	})
	data["ConsentChallenge"] = ""
	data["State"] = ""
	data["PostConsentEndpoint"] = ctx.Request.URL.Path

	return data
}

func canonicalOIDCDeviceScopesBounded(granted []string, requested []string) bool {
	if len(granted) == 0 || len(granted) > len(requested) {
		return false
	}

	allowed := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		allowed[scope] = struct{}{}
	}

	seen := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		if _, ok := allowed[scope]; !ok {
			return false
		}

		if _, duplicate := seen[scope]; duplicate {
			return false
		}

		seen[scope] = struct{}{}
	}

	return true
}

//nolint:funlen // Claims hydration keeps selected-backend lookup and both token claim sets bound together.
func (h *OIDCHandler) hydrateCanonicalOIDCDeviceClaims(
	ctx *gin.Context,
	selection canonicalOIDCDeviceSelection,
) error {
	loader := h.canonicalAuthorizeUserLoader
	assurance, hasAssurance := selection.session.Assurance(selection.session.EvaluationTime())

	mfaMethod := ""
	if hasAssurance {
		mfaMethod = assurance.Method
	}

	if loader == nil {
		loader = func(
			requestCtx *gin.Context,
			canonical *cookie.CanonicalSession,
			identity cookie.SessionIdentity,
			client *config.OIDCClient,
			scopes []string,
		) (*backend.User, error) {
			return h.idp.GetUserByUsernameForOIDCClaimsCanonical(
				requestCtx, identity.Account, client, scopes, canonicalRemoteBackendRef(canonical),
				core.IDPRequestContext{
					GrantType:       definitions.OIDCFlowDeviceCode,
					RequestedScopes: append([]string(nil), scopes...),
					MFACompleted:    hasAssurance, MFAMethod: mfaMethod,
				},
			)
		}
	}

	user, err := loader(
		ctx, selection.session, selection.identity, selection.client, selection.request.Scopes,
	)
	if err != nil {
		return err
	}

	if user == nil || strings.TrimSpace(user.ID) != selection.identity.Reference ||
		strings.TrimSpace(user.Name) != selection.identity.Account {
		return sessionstate.ErrBindingMismatch
	}

	idTokenClaims, accessTokenClaims, err := h.idp.GetClaims(
		ctx, user, selection.client, selection.request.Scopes,
	)
	if err != nil {
		return err
	}

	if idTokenClaims == nil {
		idTokenClaims = make(map[string]any)
	}

	if accessTokenClaims == nil {
		accessTokenClaims = make(map[string]any)
	}

	selection.request.StoreUserSnapshot(user)
	selection.request.IDTokenClaims = idTokenClaims
	selection.request.AccessTokenClaims = accessTokenClaims

	return nil
}

func (h *OIDCHandler) prepareCanonicalOIDCDeviceApproval(
	ctx *gin.Context,
	selection canonicalOIDCDeviceSelection,
	store *flowdomain.TypedStore,
) error {
	plan := buildConsentScopePlan(
		selection.client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), selection.request.Scopes,
	)

	granted, err := plan.ResolveGranted(ctx.PostFormArray("optional_scope"))
	if err != nil || !canonicalOIDCDeviceScopesBounded(granted, selection.request.Scopes) {
		return sessionstate.ErrBindingMismatch
	}

	selection.request.Scopes = append([]string(nil), granted...)
	selection.state.Metadata[flowdomain.FlowMetadataScope] = strings.Join(granted, " ")
	selection.state.Normalize(selection.session.EvaluationTime())

	if err = store.Save(ctx.Request.Context(), selection.state); err != nil {
		return err
	}

	return h.hydrateCanonicalOIDCDeviceClaims(ctx, selection)
}

func (h *OIDCHandler) renderCanonicalOIDCDeviceResult(
	ctx *gin.Context,
	identity cookie.SessionIdentity,
	success bool,
) {
	data := canonicalBasePageData(
		ctx, h.deps.Cfg, h.deps.LangManager, identity, definitions.ProtoOIDC, "", "",
	)
	if success {
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Authorized")
		data["DeviceVerifySuccessMessage"] = frontend.GetLocalized(
			ctx, h.deps.Cfg, h.deps.Logger, "Your device has been successfully authorized.",
		)
		data["DeviceVerifySuccessHint"] = frontend.GetLocalized(
			ctx, h.deps.Cfg, h.deps.Logger, "You can close this window and return to your device.",
		)
		ctx.HTML(http.StatusOK, "idp_device_verify_success.html", data)

		return
	}

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Authorization Failed")
	data["DeviceVerifyFailedMessage"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "Authorization denied",
	)
	data["DeviceVerifyFailedHint"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "This code can no longer be used. Please start again on your device.",
	)
	ctx.HTML(http.StatusOK, "idp_device_verify_failed.html", data)
}

// DeviceConsentGETCanonical renders one consent surface bound to typed device state.
func (h *OIDCHandler) DeviceConsentGETCanonical(ctx *gin.Context) {
	flowID, err := canonicalOIDCDeviceFlowID(ctx, false)
	if err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	selection, err := h.loadCanonicalOIDCDeviceConsent(ctx, flowID)
	if err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	ctx.HTML(http.StatusOK, "idp_consent.html", h.canonicalOIDCDeviceConsentPageData(ctx, selection))
}

// DeviceConsentPOSTCanonical completes one consent decision bound to typed device state.
func (h *OIDCHandler) DeviceConsentPOSTCanonical(ctx *gin.Context) {
	flowID, err := canonicalOIDCDeviceFlowID(ctx, true)
	if err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	selection, err := h.loadCanonicalOIDCDeviceConsent(ctx, flowID)
	if err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	decision := ctx.PostForm("submit")
	if decision != "deny" && decision != oidcConsentDecisionAllow {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	store := flowdomain.NewTypedStore(
		selection.session.Stores, selection.session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCDeviceTTL,
	)

	approved := decision == oidcConsentDecisionAllow
	if approved {
		if err = h.prepareCanonicalOIDCDeviceApproval(ctx, selection, store); err != nil {
			ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

			return
		}
	}

	if _, err = flowdomain.NewController(store).Advance(
		ctx.Request.Context(), flowID, flowdomain.FlowStepCallback, selection.session.EvaluationTime(),
	); err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	if err = h.completeCanonicalOIDCDeviceVerification(
		ctx.Request.Context(), selection, approved,
	); err != nil {
		if errors.Is(err, errCanonicalOIDCDeviceTerminal) {
			// Terminal CAS already published the one final device decision. Never invite retry.
			h.renderCanonicalOIDCDeviceResult(ctx, selection.identity, approved)

			return
		}

		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	h.renderCanonicalOIDCDeviceResult(ctx, selection.identity, approved)
}

func (h *OIDCHandler) canonicalOIDCDeviceFailureStatus(err error) int {
	if errors.Is(err, sessionstate.ErrNotFound) || errors.Is(err, sessionstate.ErrBindingMismatch) ||
		errors.Is(err, sessionstate.ErrRevisionConflict) || errors.Is(err, flowdomain.ErrFlowNotFound) {
		return http.StatusConflict
	}

	return http.StatusServiceUnavailable
}

func (h *OIDCHandler) canonicalDeviceVerifyPageData(ctx *gin.Context) gin.H {
	data := canonicalBasePageData(
		ctx, h.deps.Cfg, h.deps.LangManager, cookie.SessionIdentity{}, definitions.ProtoOIDC, "", "",
	)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Authorization")
	data["DeviceVerifyDescription"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "Enter the code displayed on your device to continue.",
	)
	data["UserCodeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Code")
	data["UserCodePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "ABCD-EFGH")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Continue")
	data["PostDeviceVerifyEndpoint"] = deviceVerifyPathFromContext(ctx)
	data["CSRFToken"] = csrf.Token(ctx)
	data["DeviceCodeOnly"] = true
	data["HaveError"] = false
	data["ErrorMessage"] = ""
	data["UserCode"] = ctx.Query("user_code")

	return data
}

func deviceVerifyPathFromContext(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")
	if lang != "" {
		return frontendDeviceVerifyPath + "/" + lang
	}

	return frontendDeviceVerifyPath
}

// DeviceVerifyPageCanonical renders a manager-free protocol entry surface.
func (h *OIDCHandler) DeviceVerifyPageCanonical(ctx *gin.Context) {
	if h == nil || h.deps == nil || ctx == nil {
		if ctx != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return
	}

	ctx.HTML(http.StatusOK, "idp_device_verify.html", h.canonicalDeviceVerifyPageData(ctx))
}

// DeviceVerifyCanonical consumes one user code and redirects to the typed login continuation.
func (h *OIDCHandler) DeviceVerifyCanonical(ctx *gin.Context) {
	if h == nil || ctx == nil || ctx.Request == nil || ctx.Request.ParseForm() != nil ||
		len(ctx.Request.PostForm["user_code"]) != 1 {
		if ctx != nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
		}

		return
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	selection, err := h.beginCanonicalOIDCDeviceVerification(
		ctx.Request.Context(), session, ctx.Request.PostForm.Get("user_code"),
	)
	if err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCDeviceTTL,
	)

	decision, err := flowdomain.NewController(store).Advance(
		ctx.Request.Context(), selection.state.FlowID, flowdomain.FlowStepLogin, session.EvaluationTime(),
	)
	if err != nil {
		selection.request.Status = domainidp.DeviceCodeStatusDenied
		if deviceStore, ok := h.deviceStore.(canonicalOIDCDeviceStore); ok {
			_ = deviceStore.CompleteClaimedDeviceCode(
				ctx.Request.Context(), selection.deviceCode, selection.request,
			)
		}

		_ = store.Delete(ctx.Request.Context(), selection.state.FlowID)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	ctx.Redirect(http.StatusSeeOther, decision.RedirectURI)
}

// ContinueDeviceLoginCanonical advances an authenticated typed device flow to consent or terminal approval.
func (h *OIDCHandler) ContinueDeviceLoginCanonical(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
) bool {
	if h == nil || ctx == nil || session == nil || state == nil ||
		state.Type != flowdomain.FlowTypeOIDCDeviceCode {
		return false
	}

	store, current, selection, err := h.advanceCanonicalOIDCDeviceLoginToConsent(ctx, session, state)
	if err != nil {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return true
	}

	if !selection.client.SkipConsent {
		ctx.Redirect(
			http.StatusSeeOther,
			flowdomain.AppendTicket(canonicalOIDCDeviceConsentTarget(ctx), current.FlowID),
		)

		return true
	}

	err = h.approveCanonicalOIDCDeviceWithoutConsent(ctx, session, store, current, selection)
	if err != nil && !errors.Is(err, errCanonicalOIDCDeviceTerminal) {
		ctx.AbortWithStatus(h.canonicalOIDCDeviceFailureStatus(err))

		return true
	}

	h.renderCanonicalOIDCDeviceResult(ctx, selection.identity, true)

	return true
}

func (h *OIDCHandler) advanceCanonicalOIDCDeviceLoginToConsent(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
) (*flowdomain.TypedStore, *flowdomain.State, canonicalOIDCDeviceSelection, error) {
	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCDeviceTTL,
	)

	current, err := store.Load(ctx.Request.Context(), state.FlowID)
	if err != nil {
		return nil, nil, canonicalOIDCDeviceSelection{}, err
	}

	if current.CurrentStep != flowdomain.FlowStepLogin || current.AuthOutcome != flowdomain.AuthOutcomeOK {
		return nil, nil, canonicalOIDCDeviceSelection{}, fmt.Errorf("canonical device login state mismatch")
	}

	if _, err = flowdomain.NewController(store).Advance(
		ctx.Request.Context(), current.FlowID, flowdomain.FlowStepConsent, session.EvaluationTime(),
	); err != nil {
		return nil, nil, canonicalOIDCDeviceSelection{}, err
	}

	selection, err := h.loadCanonicalOIDCDeviceConsent(ctx, current.FlowID)
	if err != nil {
		return nil, nil, canonicalOIDCDeviceSelection{}, err
	}

	return store, current, selection, nil
}

func canonicalOIDCDeviceConsentTarget(ctx *gin.Context) string {
	target := frontendDeviceConsentPath
	if language := ctx.Param("languageTag"); language != "" {
		target += "/" + language
	}

	return target
}

func (h *OIDCHandler) approveCanonicalOIDCDeviceWithoutConsent(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	store *flowdomain.TypedStore,
	current *flowdomain.State,
	selection canonicalOIDCDeviceSelection,
) error {
	if err := h.hydrateCanonicalOIDCDeviceClaims(ctx, selection); err != nil {
		return err
	}

	if _, err := flowdomain.NewController(store).Advance(
		ctx.Request.Context(), current.FlowID, flowdomain.FlowStepCallback, session.EvaluationTime(),
	); err != nil {
		return err
	}

	return h.completeCanonicalOIDCDeviceVerification(ctx.Request.Context(), selection, true)
}

func canonicalOIDCDeviceStoreError(err error) error {
	switch {
	case errors.Is(err, domainidp.ErrDeviceCodeNotFound):
		return sessionstate.ErrNotFound
	case errors.Is(err, domainidp.ErrDeviceCodeConflict):
		return sessionstate.ErrRevisionConflict
	default:
		return err
	}
}

func (h *OIDCHandler) canonicalOIDCDeviceDigest(userCode string) (string, error) {
	if h == nil || h.deps == nil || h.deps.Redis == nil {
		return "", sessionstate.ErrBindingMismatch
	}

	userCode = domainidp.NormalizeDeviceUserCode(userCode)
	if userCode == "" {
		return "", sessionstate.ErrBindingMismatch
	}

	return h.deps.Redis.GetSecurityManager().IndexDigest(canonicalOIDCDeviceDigestNamespace, userCode), nil
}

func canonicalOIDCDeviceBeginAvailable(h *OIDCHandler, session *cookie.CanonicalSession) bool {
	return h != nil && h.idp != nil && session != nil && session.Stores != nil && session.Handle != ""
}

func failCanonicalOIDCDeviceClaim(
	ctx context.Context,
	store canonicalOIDCDeviceStore,
	deviceCode string,
	request *domainidp.DeviceCodeRequest,
	failure error,
) (canonicalOIDCDeviceSelection, error) {
	if request != nil {
		request.VerificationLocked = true
		request.Status = domainidp.DeviceCodeStatusDenied
		_ = store.CompleteClaimedDeviceCode(ctx, deviceCode, request)
	}

	return canonicalOIDCDeviceSelection{}, failure
}

func (h *OIDCHandler) resolveCanonicalOIDCDeviceClaim(
	ctx context.Context,
	request *domainidp.DeviceCodeRequest,
) (*config.OIDCClient, string, error) {
	client, err := h.idp.ResolveClient(ctx, request.ClientID)
	if err != nil {
		return nil, "", err
	}

	if client == nil || !slices.Equal(h.idp.FilterScopes(client, request.Scopes), request.Scopes) {
		return nil, "", sessionstate.ErrBindingMismatch
	}

	digest, err := h.canonicalOIDCDeviceDigest(request.UserCode)
	if err != nil {
		return nil, "", err
	}

	return client, digest, nil
}

//nolint:funlen // Device entry keeps atomic claim, client validation, digest binding, and flow start together.
func (h *OIDCHandler) beginCanonicalOIDCDeviceVerification(
	ctx context.Context,
	session *cookie.CanonicalSession,
	userCode string,
) (canonicalOIDCDeviceSelection, error) {
	var selection canonicalOIDCDeviceSelection
	if !canonicalOIDCDeviceBeginAvailable(h, session) {
		return selection, sessionstate.ErrBindingMismatch
	}

	store, ok := h.deviceStore.(canonicalOIDCDeviceStore)
	if !ok {
		return selection, sessionstate.ErrBindingMismatch
	}

	deviceCode, request, err := store.ClaimDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return selection, canonicalOIDCDeviceStoreError(err)
	}

	if strings.TrimSpace(deviceCode) == "" ||
		!canonicalOIDCDeviceRequestLive(request, session.EvaluationTime()) {
		return failCanonicalOIDCDeviceClaim(
			ctx, store, deviceCode, request, sessionstate.ErrBindingMismatch,
		)
	}

	request.VerificationLocked = true

	client, digest, err := h.resolveCanonicalOIDCDeviceClaim(ctx, request)
	if err != nil {
		return failCanonicalOIDCDeviceClaim(ctx, store, deviceCode, request, err)
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		return failCanonicalOIDCDeviceClaim(ctx, store, deviceCode, request, err)
	}

	state := &flowdomain.State{
		FlowID: string(handle), Type: flowdomain.FlowTypeOIDCDeviceCode,
		Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepStart,
		AuthOutcome: flowdomain.AuthOutcomeUnknown, GrantType: definitions.OIDCFlowDeviceCode,
		ReturnTarget: frontendLoginPath,
		Metadata: map[string]string{
			flowdomain.FlowMetadataClientID:             request.ClientID,
			flowdomain.FlowMetadataDeviceCode:           deviceCode,
			flowdomain.FlowMetadataDeviceUserCodeDigest: digest,
			flowdomain.FlowMetadataScope:                strings.Join(request.Scopes, " "),
			flowdomain.FlowMetadataResumeTarget:         flowdomain.FlowMetadataResumeTargetDeviceCodeComplete,
		},
	}
	ttl := min(canonicalOIDCDeviceTTL, request.ExpiresAt.Sub(session.EvaluationTime()))

	typedStore := flowdomain.NewTypedStore(session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, ttl)
	if _, err = flowdomain.NewController(typedStore).StartAtStep(
		ctx, state, flowdomain.FlowStepDeviceVerification, session.EvaluationTime(),
	); err != nil {
		return failCanonicalOIDCDeviceClaim(ctx, store, deviceCode, request, err)
	}

	return canonicalOIDCDeviceSelection{
		session: session, state: state, request: request, client: client, deviceCode: deviceCode,
	}, nil
}

func canonicalOIDCDeviceCompletionAvailable(h *OIDCHandler, selection canonicalOIDCDeviceSelection) bool {
	return h != nil && h.idp != nil && selection.session != nil && selection.session.Stores != nil &&
		selection.state != nil && selection.request != nil && selection.client != nil &&
		strings.TrimSpace(selection.deviceCode) != ""
}

func canonicalOIDCDeviceCallbackBound(state *flowdomain.State, selection canonicalOIDCDeviceSelection) bool {
	return state != nil && state.Type == flowdomain.FlowTypeOIDCDeviceCode &&
		state.GrantType == definitions.OIDCFlowDeviceCode && state.CurrentStep == flowdomain.FlowStepCallback &&
		state.AuthOutcome == flowdomain.AuthOutcomeOK &&
		state.Metadata[flowdomain.FlowMetadataResumeTarget] == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete &&
		strings.TrimSpace(state.Metadata[flowdomain.FlowMetadataDeviceCode]) == selection.deviceCode &&
		selection.client.ClientID == state.Metadata[flowdomain.FlowMetadataClientID]
}

func canonicalOIDCDeviceIdentityBound(
	request *domainidp.DeviceCodeRequest,
	identity cookie.SessionIdentity,
) bool {
	return (request.UserID == "" || request.UserID == identity.Reference) &&
		(request.Username == "" || request.Username == identity.Account)
}

func canonicalOIDCDeviceClaimsBound(
	request *domainidp.DeviceCodeRequest,
	identity cookie.SessionIdentity,
) bool {
	return request.UserID == identity.Reference && request.Username == identity.Account &&
		request.IDTokenClaims != nil && request.AccessTokenClaims != nil
}

func (h *OIDCHandler) prepareCanonicalOIDCDeviceTerminal(
	state *flowdomain.State,
	selection canonicalOIDCDeviceSelection,
	approved bool,
) (cookie.SessionIdentity, *domainidp.OIDCSession, error) {
	session := selection.session
	request := selection.request

	grantedScopes := strings.Fields(state.Metadata[flowdomain.FlowMetadataScope])
	if !canonicalOIDCDeviceRequestLive(request, session.EvaluationTime()) ||
		request.ClientID != selection.client.ClientID ||
		!canonicalOIDCDeviceScopesBounded(grantedScopes, request.Scopes) {
		return cookie.SessionIdentity{}, nil, sessionstate.ErrBindingMismatch
	}

	request.Scopes = append([]string(nil), grantedScopes...)

	digest, err := h.canonicalOIDCDeviceDigest(request.UserCode)
	if err != nil || digest != state.Metadata[flowdomain.FlowMetadataDeviceUserCodeDigest] {
		return cookie.SessionIdentity{}, nil, sessionstate.ErrBindingMismatch
	}

	identity, authenticated := session.Identity()
	if !authenticated || !canonicalOIDCDeviceIdentityBound(request, identity) {
		return cookie.SessionIdentity{}, nil, sessionstate.ErrBindingMismatch
	}

	request.UserID = identity.Reference
	request.Username = identity.Account
	request.DisplayName = identity.DisplayName

	request.VerificationLocked = true
	if approved && !canonicalOIDCDeviceClaimsBound(request, identity) {
		return cookie.SessionIdentity{}, nil, sessionstate.ErrBindingMismatch
	}

	if !approved {
		request.Status = domainidp.DeviceCodeStatusDenied

		return identity, nil, nil
	}

	assurance, hasAssurance := session.Assurance(session.EvaluationTime())

	request.MFACompleted = hasAssurance
	if hasAssurance {
		request.MFAMethod = assurance.Method
	}

	request.Status = domainidp.DeviceCodeStatusAuthorized

	return identity, &domainidp.OIDCSession{
		ClientID: request.ClientID, UserID: identity.Reference, Username: identity.Account,
		DisplayName: identity.DisplayName, Scopes: append([]string(nil), request.Scopes...),
		AuthTime: session.Anchor.Value.CreatedAt, MFACompleted: hasAssurance, MFAMethod: request.MFAMethod,
	}, nil
}

func (h *OIDCHandler) publishCanonicalOIDCDeviceTerminal(
	ctx context.Context,
	store canonicalOIDCDeviceStore,
	typedStore *flowdomain.TypedStore,
	state *flowdomain.State,
	selection canonicalOIDCDeviceSelection,
	identity cookie.SessionIdentity,
	pending *domainidp.OIDCSession,
	approved bool,
) error {
	if approved {
		if err := selection.session.RecordOIDCClient(
			ctx, identity, selection.client.ClientID,
		); err != nil {
			return err
		}
	}

	if err := store.CompleteClaimedDeviceCode(ctx, selection.deviceCode, selection.request); err != nil {
		return canonicalOIDCDeviceStoreError(err)
	}

	if approved {
		persistGrant := h.canonicalDeviceGrantPersister
		if persistGrant == nil {
			persistGrant = h.persistCanonicalOIDCConsentGrant
		}

		if err := persistGrant(ctx, canonicalOIDCConsentSelection{
			session: selection.session, identity: identity, state: state,
			pending: pending, client: selection.client,
		}, pending); err != nil {
			return canonicalOIDCDeviceTerminalError{stage: "consent_grant", cause: err}
		}
	}

	consumeFlow := h.canonicalDeviceFlowConsumer
	if consumeFlow == nil {
		consumeFlow = func(
			consumeCtx context.Context,
			typed *flowdomain.TypedStore,
			current *flowdomain.State,
		) error {
			_, consumeErr := typed.ConsumeOIDC(consumeCtx, current.FlowID, current.Revision)

			return consumeErr
		}
	}

	if err := consumeFlow(ctx, typedStore, state); err != nil {
		return canonicalOIDCDeviceTerminalError{stage: "flow_cleanup", cause: err}
	}

	return nil
}

func (h *OIDCHandler) completeCanonicalOIDCDeviceVerification(
	ctx context.Context,
	selection canonicalOIDCDeviceSelection,
	approved bool,
) error {
	if !canonicalOIDCDeviceCompletionAvailable(h, selection) {
		return sessionstate.ErrBindingMismatch
	}

	deviceStore, ok := h.deviceStore.(canonicalOIDCDeviceStore)
	if !ok {
		return sessionstate.ErrBindingMismatch
	}

	session := selection.session
	typedStore := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, canonicalOIDCDeviceTTL,
	)

	state, err := typedStore.Load(ctx, selection.state.FlowID)
	if err != nil {
		return err
	}

	if !canonicalOIDCDeviceCallbackBound(state, selection) {
		return sessionstate.ErrBindingMismatch
	}

	identity, pending, err := h.prepareCanonicalOIDCDeviceTerminal(state, selection, approved)
	if err != nil {
		return err
	}

	return h.publishCanonicalOIDCDeviceTerminal(
		ctx, deviceStore, typedStore, state, selection, identity, pending, approved,
	)
}
