// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/gin-gonic/gin"
)

const canonicalWebAuthnCeremonyParameter = "ceremony"

type canonicalWebAuthnBegin func(
	*gin.Context,
	canonicalMFASelectionState,
) (any, sessionstate.Handle, error)

type canonicalWebAuthnFinish func(
	*gin.Context,
	canonicalMFASelectionState,
	sessionstate.Handle,
) (*backend.User, error)

type canonicalWebAuthnBeginResponse struct {
	Options  any    `json:"options"`
	Ceremony string `json:"ceremony"`
}

// renderCanonicalWebAuthn renders one canonical, ticket-bound WebAuthn challenge.
func (h *FrontendHandler) renderCanonicalWebAuthn(ctx *gin.Context) {
	selection, err := h.canonicalWebAuthnSelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["WebAuthnVerifyMessage"] = frontend.GetLocalized(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		"Please use your security key to login",
	)
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")
	data["CSRFToken"] = csrf.Token(ctx)
	data["WebAuthnBeginEndpoint"] = currentFlowTicketURL(
		ctx,
		localizedLoginPath(ctx, "/login/webauthn/begin"),
	)
	data["WebAuthnFinishEndpoint"] = currentFlowTicketURL(
		ctx,
		localizedLoginPath(ctx, "/login/webauthn/finish"),
	)
	data["BackURL"] = canonicalTOTPBackURL(ctx, selection)
	data["JSInteractWithKey"] = frontend.GetLocalized(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		"Please interact with your security key...",
	)
	data["JSCompletingLogin"] = frontend.GetLocalized(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		"Completing login...",
	)
	data["JSUnknownError"] = frontend.GetLocalized(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		"An unknown error occurred",
	)

	ctx.HTML(http.StatusOK, "idp_webauthn_verify.html", data)
}

// LoginWebAuthnBegin creates one typed, parent-bound WebAuthn ceremony.
func (h *FrontendHandler) LoginWebAuthnBegin(ctx *gin.Context) {
	selection, err := h.canonicalWebAuthnSelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	begin := h.canonicalWebAuthnBegin
	if begin == nil {
		begin = h.beginCanonicalWebAuthn
	}

	options, ceremony, err := begin(ctx, selection)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	ctx.JSON(http.StatusOK, canonicalWebAuthnBeginResponse{
		Options:  options,
		Ceremony: string(ceremony),
	})
}

// completeCanonicalWebAuthn verifies one typed ceremony and commits its step-up proof.
//
//nolint:gocyclo,funlen // WebAuthn completion keeps ceremony consume, step-up publication, post-action, and resume ordered.
func (h *FrontendHandler) completeCanonicalWebAuthn(ctx *gin.Context) {
	selection, err := h.canonicalWebAuthnSelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	ceremony, err := sessionstate.ParseHandle(ctx.Query(canonicalWebAuthnCeremonyParameter))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	finish := h.canonicalWebAuthnFinish
	if finish == nil {
		finish = h.finishCanonicalWebAuthn
	}

	user, err := finish(ctx, selection, ceremony)
	if err != nil {
		h.observeCanonicalWebAuthn(ctx, selection, false, err)

		if !ctx.Writer.Written() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return
	}

	completion, err := selection.session.CompleteStepUp(
		ctx.Request.Context(),
		selection.stepUp.Value.Handle,
		definitions.MFAMethodWebAuthn,
		mfaAssuranceFreshness,
	)
	if err != nil {
		if errors.Is(err, sessionstate.ErrBindingMismatch) ||
			errors.Is(err, sessionstate.ErrRevisionConflict) ||
			errors.Is(err, sessionstate.ErrExpired) {
			ctx.AbortWithStatus(http.StatusConflict)

			return
		}

		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	target, selfService, err := canonicalSelfServiceCompletionTarget(ctx, completion)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if !selfService {
		target, err = canonicalWebAuthnResumeTarget(ctx, selection)
		if err != nil {
			ctx.AbortWithStatus(http.StatusConflict)

			return
		}
	}

	h.observeCanonicalWebAuthn(ctx, selection, true, nil)
	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if user != nil {
		core.QueueCompletedIDPMFAPostAction(
			ctx,
			h.deps.Auth(),
			user,
			canonicalMFAProtocolContext(selection, definitions.MFAMethodWebAuthn, true),
		)
	}

	ctx.JSON(http.StatusOK, webAuthnFinishResponse{Redirect: target})
}

// canonicalWebAuthnSelection requires WebAuthn on one incomplete typed step-up.
func (h *FrontendHandler) canonicalWebAuthnSelection(ctx *gin.Context) (canonicalMFASelectionState, error) {
	selection, err := h.canonicalMFASelection(ctx)
	if err != nil {
		return canonicalMFASelectionState{}, err
	}

	if !selection.availability.haveWebAuthn {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	return selection, nil
}

// beginCanonicalWebAuthn resolves the typed identity and stores one bound ceremony.
func (h *FrontendHandler) beginCanonicalWebAuthn(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
) (any, sessionstate.Handle, error) {
	data, err := h.canonicalWebAuthnBackendData(ctx, selection)
	if err != nil {
		return nil, "", err
	}

	return core.BeginCanonicalWebAuthnLogin(
		ctx.Request.Context(),
		selection.session,
		selection.stepUp.Value.Flow,
		selection.identity.Reference,
		string(selection.parent.Protocol),
		data.WebAuthnUser,
	)
}

// finishCanonicalWebAuthn verifies one bound ceremony without legacy cookie state.
func (h *FrontendHandler) finishCanonicalWebAuthn(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	ceremony sessionstate.Handle,
) (*backend.User, error) {
	data, err := h.canonicalWebAuthnBackendData(ctx, selection)
	if err != nil {
		return nil, err
	}

	user, ok := core.CompleteCanonicalWebAuthnLogin(
		ctx,
		h.deps.Auth(),
		selection.session,
		ceremony,
		selection.stepUp.Value.Flow,
		selection.identity.Reference,
		string(selection.parent.Protocol),
		canonicalMFAProtocolContext(selection, definitions.MFAMethodWebAuthn, false),
		data.WebAuthnUser,
		data.AuthState,
	)
	if !ok {
		return nil, fmt.Errorf("canonical WebAuthn finish: verification failed")
	}

	return user, nil
}

// canonicalWebAuthnBackendData resolves the exact typed identity and authority binding.
func (h *FrontendHandler) canonicalWebAuthnBackendData(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
) (*UserBackendData, error) {
	data, err := h.getUserBackendDataForIdentity(
		ctx,
		selection.identity.Account,
		string(selection.parent.Protocol),
		canonicalRemoteBackendRef(selection.session),
	)
	if err != nil {
		return nil, err
	}

	if data == nil || data.AuthState == nil || data.WebAuthnUser == nil ||
		data.Username != selection.identity.Account || data.UniqueUserID != selection.identity.Reference {
		return nil, sessionstate.ErrBindingMismatch
	}

	return data, nil
}

// canonicalWebAuthnResumeTarget resolves one safe typed protocol continuation for JSON clients.
func canonicalWebAuthnResumeTarget(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
) (string, error) {
	decision, err := flowdomain.NewProtocolAggregate(
		selection.session.Stores,
		selection.session.Handle,
		0,
	).Resume(ctx.Request.Context(), selection.parent.FlowID)
	if err != nil {
		return "", err
	}

	if decision.RedirectURI == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		return "", sessionstate.ErrBindingMismatch
	}

	target := safeLocalIDPResumeTarget(decision.RedirectURI)
	if target == "" || isLoginSelfResume(ctx.Request.URL.Path, target) {
		return "", sessionstate.ErrBindingMismatch
	}

	return target, nil
}

// observeCanonicalWebAuthn records bounded success or failure telemetry.
func (h *FrontendHandler) observeCanonicalWebAuthn(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	success bool,
	err error,
) {
	h.observeCanonicalMFA(
		ctx, selection, definitions.MFAMethodWebAuthn, "WebAuthn verification failed", success, err,
	)
}
