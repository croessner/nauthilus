// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

const canonicalSAMLSSOTTL = 10 * time.Minute

type canonicalSAMLRequestBinding struct {
	EntityID      string
	RequestID     string
	RequestDigest string
	RelayState    string
	Destination   string
	OriginalURL   string
}

type canonicalSAMLUserLoader func(
	*gin.Context,
	*cookie.CanonicalSession,
	cookie.SessionIdentity,
	*config.SAML2ServiceProvider,
) (*backend.User, error)

type canonicalSAMLPostBinder func(*saml.IdpAuthnRequest) (saml.IdpAuthnRequestForm, error)

type canonicalSAMLFlowConsumer func(
	context.Context,
	*cookie.CanonicalSession,
	string,
	canonicalSAMLRequestBinding,
) (*flowdomain.State, error)

type canonicalSAMLParticipantRegistrar func(
	context.Context,
	string,
	string,
	*saml.Session,
) error

type canonicalSAMLIdentityProvider interface {
	GetUserByUsernameForSAMLCanonical(
		*gin.Context,
		string,
		*config.SAML2ServiceProvider,
		core.RemoteBackendRef,
		core.IDPRequestContext,
	) (*backend.User, error)
}

// SSOCanonical validates a fresh SAML request and starts only typed canonical state.
// Authenticated completion remains fail-closed until its assertion slice is composed.
func (h *SAMLHandler) SSOCanonical(ctx *gin.Context) {
	if h == nil || h.deps == nil || h.idp == nil || ctx == nil || ctx.Request == nil {
		if ctx != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	binding, request, err := h.canonicalSAMLRequestFromContext(ctx)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid SAML AuthnRequest")

		return
	}

	identity, authenticated := session.Identity()
	if authenticated {
		h.completeCanonicalSAMLHTTP(ctx, session, identity, binding, request)

		return
	}

	if strings.TrimSpace(ctx.Query(flowdomain.FlowTicketParameter)) != "" {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	_, target, err := startCanonicalSAMLSSO(ctx.Request.Context(), session, binding)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	ctx.Redirect(http.StatusFound, target)
}

func (h *SAMLHandler) canonicalSAMLRequestFromContext(
	ctx *gin.Context,
) (canonicalSAMLRequestBinding, *saml.IdpAuthnRequest, error) {
	var binding canonicalSAMLRequestBinding

	provider, err := h.getSAMLIDP()
	if err != nil {
		return binding, nil, err
	}

	request, err := saml.NewIdpAuthnRequest(provider, ctx.Request)
	if err != nil {
		return binding, nil, err
	}

	if err = request.Validate(); err != nil {
		return binding, nil, err
	}

	issuer := samlAuthnRequestIssuer(request)
	if err = h.enforceSAMLAuthnRequestSignature(ctx.Request, request, issuer); err != nil {
		return binding, nil, err
	}

	digest := sha256.Sum256(request.RequestBuffer)

	binding = canonicalSAMLRequestBinding{
		EntityID: issuer, RequestID: request.Request.ID,
		RequestDigest: "sha256:" + hex.EncodeToString(digest[:]),
		RelayState:    request.RelayState, Destination: request.Request.Destination,
		OriginalURL: canonicalSAMLOriginalURL(ctx.Request.URL),
	}
	if !binding.valid() {
		return canonicalSAMLRequestBinding{}, nil, sessionstate.ErrBindingMismatch
	}

	return binding, request, nil
}

//nolint:gocyclo,funlen // Assertion completion keeps policy, claims, signing, consume, SLO publication, and rendering ordered.
func (h *SAMLHandler) completeCanonicalSAMLHTTP(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	binding canonicalSAMLRequestBinding,
	request *saml.IdpAuthnRequest,
) {
	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	state, err := loadCanonicalSAMLSSO(ctx.Request.Context(), session, string(ticket), binding)
	if err != nil {
		ctx.AbortWithStatus(canonicalSAMLFailureStatus(err))

		return
	}

	if state.AuthOutcome != flowdomain.AuthOutcomeOK ||
		(state.CurrentStep != flowdomain.FlowStepLogin && state.CurrentStep != flowdomain.FlowStepMFA) {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	sp, ok := h.idp.FindSAMLServiceProvider(binding.EntityID)
	if !ok || sp == nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	ready, err := h.canonicalSAMLPolicyReady(ctx, session, state, identity)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if !ready {
		return
	}

	user, err := h.loadCanonicalSAMLUser(ctx, session, identity, sp)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if user == nil || strings.TrimSpace(user.ID) != identity.Reference ||
		strings.TrimSpace(user.Name) != identity.Account {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	normalizeSAMLRequestRemoteAddr(request)

	samlSession := h.newSAMLAuthnSession(identity.Account)
	populateSAMLSessionAttributes(samlSession, user, sp)

	request.Now = session.EvaluationTime()
	if err = (saml.DefaultAssertionMaker{}).MakeAssertion(request, samlSession); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	postBinding := h.canonicalSAMLPostBinder
	if postBinding == nil {
		postBinding = func(authnRequest *saml.IdpAuthnRequest) (saml.IdpAuthnRequestForm, error) {
			return authnRequest.PostBinding()
		}
	}

	form, err := postBinding(request)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolSAML, canonicalSAMLSSOTTL,
	)
	if _, err = flowdomain.NewController(store).Advance(
		ctx.Request.Context(), state.FlowID, flowdomain.FlowStepCallback, session.EvaluationTime(),
	); err != nil {
		ctx.AbortWithStatus(canonicalSAMLFailureStatus(err))

		return
	}

	consumeFlow := h.canonicalSAMLFlowConsumer
	if consumeFlow == nil {
		consumeFlow = consumeCanonicalSAMLSSO
	}

	if _, err = consumeFlow(ctx.Request.Context(), session, state.FlowID, binding); err != nil {
		ctx.AbortWithStatus(canonicalSAMLFailureStatus(err))

		return
	}

	registerParticipant := h.canonicalSAMLParticipantRegistrar
	if registerParticipant == nil {
		registerParticipant = h.registerSLOParticipantSession
	}

	if err = registerParticipant(
		ctx.Request.Context(), identity.Account, binding.EntityID, samlSession,
	); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	h.renderSAMLPostBinding(ctx, form)
}

func (h *SAMLHandler) canonicalSAMLPolicyReady(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
) (bool, error) {
	frontendHandler := &FrontendHandler{deps: h.deps}

	policy, ok := frontendHandler.canonicalFlowMFAPolicy(ctx.Request.Context(), state)
	if !ok {
		return false, sessionstate.ErrBindingMismatch
	}

	missing, ok := frontendHandler.canonicalMissingEnrollment(ctx, session, state, identity, policy.required)
	if !ok {
		return false, nil
	}

	if len(missing) > 0 {
		if !frontendHandler.startCanonicalRequiredMFAEnrollment(ctx, session, state, identity, missing) &&
			!ctx.Writer.Written() {
			return false, sessionstate.ErrBindingMismatch
		}

		return false, nil
	}

	if !canonicalSessionSatisfiesMFAPolicy(session, policy, session.EvaluationTime()) {
		if !frontendHandler.startCanonicalMFAAssuranceStepUp(ctx, session, state, identity, policy) &&
			!ctx.Writer.Written() {
			return false, sessionstate.ErrBindingMismatch
		}

		return false, nil
	}

	return true, nil
}

func (h *SAMLHandler) loadCanonicalSAMLUser(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	sp *config.SAML2ServiceProvider,
) (*backend.User, error) {
	if h.canonicalSAMLUserLoader != nil {
		return h.canonicalSAMLUserLoader(ctx, session, identity, sp)
	}

	provider, ok := h.idp.(canonicalSAMLIdentityProvider)
	if !ok {
		return nil, sessionstate.ErrBindingMismatch
	}

	assurance, completed := session.Assurance(session.EvaluationTime())

	method := ""
	if completed {
		method = assurance.Method
	}

	return provider.GetUserByUsernameForSAMLCanonical(
		ctx, identity.Account, sp, canonicalRemoteBackendRef(session),
		core.IDPRequestContext{MFACompleted: completed, MFAMethod: method},
	)
}

func canonicalSAMLFailureStatus(err error) int {
	if errors.Is(err, sessionstate.ErrBindingMismatch) || errors.Is(err, sessionstate.ErrNotFound) ||
		errors.Is(err, sessionstate.ErrRevisionConflict) || errors.Is(err, flowdomain.ErrFlowNotFound) {
		return http.StatusConflict
	}

	return http.StatusServiceUnavailable
}

func canonicalSAMLOriginalURL(requestURL *url.URL) string {
	if requestURL == nil {
		return ""
	}

	copyURL := *requestURL
	query := copyURL.Query()
	query.Del(flowdomain.FlowTicketParameter)
	copyURL.RawQuery = query.Encode()

	return copyURL.RequestURI()
}

func (b canonicalSAMLRequestBinding) valid() bool {
	return strings.TrimSpace(b.EntityID) != "" && len(b.EntityID) <= 2048 &&
		strings.TrimSpace(b.RequestID) != "" && len(b.RequestID) <= 512 &&
		strings.TrimSpace(b.RequestDigest) != "" && len(b.RequestDigest) <= 256 &&
		len(b.RelayState) <= 1024 && strings.TrimSpace(b.Destination) != "" &&
		len(b.Destination) <= 2048 && validCanonicalSAMLResumeTarget(b.OriginalURL)
}

func validCanonicalSAMLResumeTarget(target string) bool {
	if len(target) == 0 || len(target) > 8192 {
		return false
	}

	parsed, err := url.ParseRequestURI(target)

	return err == nil && !parsed.IsAbs() && parsed.Host == "" && parsed.Path == frontendSAMLSSOPath
}

func startCanonicalSAMLSSO(
	ctx context.Context,
	session *cookie.CanonicalSession,
	binding canonicalSAMLRequestBinding,
) (*flowdomain.State, string, error) {
	if session == nil || session.Stores == nil || session.Handle == "" || !binding.valid() {
		return nil, "", sessionstate.ErrBindingMismatch
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		return nil, "", err
	}

	state := &flowdomain.State{
		FlowID: string(handle), Type: flowdomain.FlowTypeSAML, Protocol: flowdomain.FlowProtocolSAML,
		CurrentStep: flowdomain.FlowStepStart, AuthOutcome: flowdomain.AuthOutcomeUnknown,
		ReturnTarget: frontendLoginPath,
		Metadata: map[string]string{
			flowdomain.FlowMetadataSAMLEntityID:      binding.EntityID,
			flowdomain.FlowMetadataSAMLRequestID:     binding.RequestID,
			flowdomain.FlowMetadataSAMLRequestDigest: binding.RequestDigest,
			flowdomain.FlowMetadataSAMLRelayState:    binding.RelayState,
			flowdomain.FlowMetadataSAMLDestination:   binding.Destination,
			flowdomain.FlowMetadataOriginalURL:       binding.OriginalURL,
			flowdomain.FlowMetadataResumeTarget:      binding.OriginalURL,
		},
	}
	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolSAML, canonicalSAMLSSOTTL,
	)

	decision, err := flowdomain.NewController(store).StartAtStep(
		ctx, state, flowdomain.FlowStepLogin, session.EvaluationTime(),
	)
	if err != nil {
		return nil, "", err
	}

	return state, decision.RedirectURI, nil
}

func loadCanonicalSAMLSSO(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
	binding canonicalSAMLRequestBinding,
) (*flowdomain.State, error) {
	if session == nil || session.Stores == nil || session.Handle == "" || !binding.valid() {
		return nil, sessionstate.ErrBindingMismatch
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolSAML, canonicalSAMLSSOTTL,
	)

	state, err := store.Load(ctx, flowID)
	if err != nil {
		return nil, err
	}

	if !canonicalSAMLRequestBound(state, binding) {
		return nil, sessionstate.ErrBindingMismatch
	}

	return state, nil
}

func canonicalSAMLRequestBound(state *flowdomain.State, binding canonicalSAMLRequestBinding) bool {
	return state != nil && state.Type == flowdomain.FlowTypeSAML && state.Protocol == flowdomain.FlowProtocolSAML &&
		state.Metadata != nil && state.Metadata[flowdomain.FlowMetadataSAMLEntityID] == binding.EntityID &&
		state.Metadata[flowdomain.FlowMetadataSAMLRequestID] == binding.RequestID &&
		state.Metadata[flowdomain.FlowMetadataSAMLRequestDigest] == binding.RequestDigest &&
		state.Metadata[flowdomain.FlowMetadataSAMLRelayState] == binding.RelayState &&
		state.Metadata[flowdomain.FlowMetadataSAMLDestination] == binding.Destination &&
		state.Metadata[flowdomain.FlowMetadataOriginalURL] == binding.OriginalURL &&
		state.Metadata[flowdomain.FlowMetadataResumeTarget] == binding.OriginalURL
}

func consumeCanonicalSAMLSSO(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flowID string,
	binding canonicalSAMLRequestBinding,
) (*flowdomain.State, error) {
	state, err := loadCanonicalSAMLSSO(ctx, session, flowID, binding)
	if err != nil {
		return nil, err
	}

	if state.AuthOutcome != flowdomain.AuthOutcomeOK || state.CurrentStep != flowdomain.FlowStepCallback {
		return nil, sessionstate.ErrBindingMismatch
	}

	store := flowdomain.NewTypedStore(
		session.Stores, session.Handle, flowdomain.FlowProtocolSAML, canonicalSAMLSSOTTL,
	)

	return store.ConsumeSAML(ctx, state.FlowID, state.Revision)
}
