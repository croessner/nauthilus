// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

const canonicalSelfServiceLoginTTL = 10 * time.Minute

// CanonicalSelfServiceLoginMiddleware starts a bounded primary login for anonymous MFA portal requests.
func (h *FrontendHandler) CanonicalSelfServiceLoginMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := cookie.GetCanonicalSession(ctx)
		if session == nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		if _, authenticated := session.Identity(); authenticated {
			ctx.Set(canonicalAuthenticatedViewContextKey, true)
			ctx.Next()

			return
		}

		target, err := h.startOrResumeCanonicalSelfServiceLogin(ctx, session)
		if err != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		ctx.Redirect(http.StatusFound, target)
		ctx.Abort()
	}
}

// startOrResumeCanonicalSelfServiceLogin reuses one matching live flow or creates a new isolated flow.
func (h *FrontendHandler) startOrResumeCanonicalSelfServiceLogin(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
) (string, error) {
	if h == nil || ctx == nil || session == nil || session.Stores == nil {
		return "", fmt.Errorf("canonical self-service login: unavailable")
	}

	loginTarget := localizedLoginPath(ctx, frontendLoginPath)
	resumeTarget := localizedMFARootPath(ctx, definitions.MFARoot+"/register/home")
	store := flowdomain.NewTypedStore(
		session.Stores,
		session.Handle,
		flowdomain.FlowProtocolInternal,
		canonicalSelfServiceLoginTTL,
	)

	for _, handle := range session.Anchor.Value.SelfServiceFlows {
		state, err := store.Load(ctx.Request.Context(), string(handle))
		if err != nil {
			return "", fmt.Errorf("canonical self-service login: load pending flow: %w", err)
		}

		if reusableCanonicalSelfServiceLogin(state, loginTarget, resumeTarget) {
			return flowdomain.AppendTicket(loginTarget, state.FlowID), nil
		}

		if err = store.Delete(ctx.Request.Context(), state.FlowID); err != nil {
			return "", fmt.Errorf("canonical self-service login: retire pending flow: %w", err)
		}
	}

	return startCanonicalSelfServiceLogin(
		ctx.Request.Context(), session, store, loginTarget, resumeTarget,
	)
}

// reusableCanonicalSelfServiceLogin validates one pending flow against its server-derived route targets.
func reusableCanonicalSelfServiceLogin(state *flowdomain.State, loginTarget string, resumeTarget string) bool {
	return state != nil && state.Type == flowdomain.FlowTypeSelfServiceLogin &&
		state.Protocol == flowdomain.FlowProtocolInternal && state.CurrentStep == flowdomain.FlowStepLogin &&
		state.AuthOutcome == flowdomain.AuthOutcomeUnknown && state.ReturnTarget == loginTarget &&
		state.Metadata[flowdomain.FlowMetadataResumeTarget] == resumeTarget
}

// startCanonicalSelfServiceLogin creates one typed internal flow bound to the current canonical session.
func startCanonicalSelfServiceLogin(
	ctx context.Context,
	session *cookie.CanonicalSession,
	store *flowdomain.TypedStore,
	loginTarget string,
	resumeTarget string,
) (string, error) {
	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		return "", err
	}

	state := &flowdomain.State{
		FlowID: string(handle), Type: flowdomain.FlowTypeSelfServiceLogin,
		Protocol: flowdomain.FlowProtocolInternal, CurrentStep: flowdomain.FlowStepStart,
		AuthOutcome: flowdomain.AuthOutcomeUnknown, ReturnTarget: loginTarget,
		Metadata: map[string]string{flowdomain.FlowMetadataResumeTarget: resumeTarget},
	}

	decision, err := flowdomain.NewController(store).StartAtStep(
		ctx, state, flowdomain.FlowStepLogin, session.EvaluationTime(),
	)
	if err != nil {
		return "", err
	}

	return decision.RedirectURI, nil
}

// validCanonicalSelfServiceLoginFlow verifies the internal flow and both localized server-owned targets.
func validCanonicalSelfServiceLoginFlow(ctx *gin.Context, state *flowdomain.State) bool {
	if ctx == nil || state == nil || state.Metadata == nil {
		return false
	}

	return reusableCanonicalSelfServiceLogin(
		state,
		localizedLoginPath(ctx, frontendLoginPath),
		localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
	)
}

// resumeCanonicalSelfServiceLogin completes a pending internal flow for an already authenticated session.
func (h *FrontendHandler) resumeCanonicalSelfServiceLogin(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
) bool {
	if !validCanonicalSelfServiceLoginFlow(ctx, state) {
		ctx.AbortWithStatus(http.StatusConflict)

		return true
	}

	state.CurrentStep = flowdomain.FlowStepCallback
	if err := state.UpdateAuthOutcome(flowdomain.AuthOutcomeOK); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return true
	}

	store := flowdomain.NewTypedStore(
		session.Stores,
		session.Handle,
		flowdomain.FlowProtocolInternal,
		canonicalSelfServiceLoginTTL,
	)
	if err := store.Save(ctx.Request.Context(), state); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return true
	}

	return h.completeCanonicalSelfServiceLogin(ctx, session, state.FlowID)
}

// completeCanonicalSelfServiceLogin consumes one successful internal flow before redirecting to the portal.
func (h *FrontendHandler) completeCanonicalSelfServiceLogin(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	flowID string,
) bool {
	if h == nil || ctx == nil || session == nil || session.Stores == nil {
		return false
	}

	store := flowdomain.NewTypedStore(
		session.Stores,
		session.Handle,
		flowdomain.FlowProtocolInternal,
		canonicalSelfServiceLoginTTL,
	)

	state, err := store.Load(ctx.Request.Context(), flowID)
	if err != nil {
		return false
	}

	target := state.Metadata[flowdomain.FlowMetadataResumeTarget]
	if !completedCanonicalSelfServiceLogin(ctx, state, target) {
		return false
	}

	if _, err = store.ConsumeInternal(ctx.Request.Context(), flowID, state.Revision); err != nil {
		return handleCanonicalSelfServiceConsumeError(ctx, err)
	}

	ctx.Redirect(http.StatusSeeOther, target)

	return true
}

// completedCanonicalSelfServiceLogin validates terminal state and its server-owned localized target.
func completedCanonicalSelfServiceLogin(ctx *gin.Context, state *flowdomain.State, target string) bool {
	return state != nil && state.Type == flowdomain.FlowTypeSelfServiceLogin &&
		state.Protocol == flowdomain.FlowProtocolInternal && state.CurrentStep == flowdomain.FlowStepCallback &&
		state.AuthOutcome == flowdomain.AuthOutcomeOK &&
		target == localizedMFARootPath(ctx, definitions.MFARoot+"/register/home")
}

// handleCanonicalSelfServiceConsumeError maps replay races to a handled conflict response.
func handleCanonicalSelfServiceConsumeError(ctx *gin.Context, err error) bool {
	if !errors.Is(err, sessionstate.ErrRevisionConflict) && !errors.Is(err, sessionstate.ErrNotFound) {
		return false
	}

	ctx.AbortWithStatus(http.StatusConflict)

	return true
}
