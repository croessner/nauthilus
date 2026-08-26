// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

type canonicalTOTPVerifier func(*gin.Context, canonicalMFASelectionState, string) (bool, error)

// renderCanonicalTOTP renders one canonical, ticket-bound TOTP challenge.
//
//nolint:dupl // TOTP and recovery deliberately use parallel templates with distinct fields and messages.
func (h *FrontendHandler) renderCanonicalTOTP(ctx *gin.Context, haveError bool) {
	selection, err := h.canonicalTOTPSelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")
	data["CSRFToken"] = csrf.Token(ctx)
	data["PostTOTPVerifyEndpoint"] = ctx.Request.URL.Path
	data["BackURL"] = canonicalTOTPBackURL(ctx, selection)
	data["HaveError"] = haveError

	if haveError {
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid OTP code")
	}

	ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)
}

// completeCanonicalTOTP verifies and consumes one typed step-up challenge.
//
//nolint:gocyclo,funlen // TOTP completion keeps fail-latched and authenticating terminal paths explicitly separated.
func (h *FrontendHandler) completeCanonicalTOTP(ctx *gin.Context) {
	selection, err := h.canonicalTOTPSelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	code := ctx.PostForm("code")
	if code == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	verifier := h.canonicalTOTPVerifier
	if verifier == nil {
		verifier = h.verifyCanonicalTOTP
	}

	valid, err := verifier(ctx, selection, code)
	if err != nil {
		h.observeCanonicalTOTP(ctx, selection, false, err)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if !valid {
		h.observeCanonicalTOTP(ctx, selection, false, nil)
		h.renderCanonicalTOTP(ctx, true)

		return
	}

	if completeCanonicalFailLatchedMFA(ctx, selection, definitions.MFAMethodTOTP) {
		return
	}

	completion, err := selection.session.CompleteStepUp(
		ctx.Request.Context(),
		selection.stepUp.Value.Handle,
		definitions.MFAMethodTOTP,
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

	h.observeCanonicalTOTP(ctx, selection, true, nil)

	if selfService {
		ctx.Redirect(http.StatusFound, target)

		return
	}

	h.resumeCanonicalIDPFlow(ctx, selection.session, selection.parent)
}

func (h *FrontendHandler) canonicalTOTPSelection(ctx *gin.Context) (canonicalMFASelectionState, error) {
	selection, err := h.canonicalMFASelection(ctx)
	if err != nil {
		return canonicalMFASelectionState{}, err
	}

	if !selection.availability.haveTOTP {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	return selection, nil
}

func (h *FrontendHandler) verifyCanonicalTOTP(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	code string,
) (bool, error) {
	data, err := h.getUserBackendDataForIdentity(
		ctx,
		newBackendDataLookupRequest(
			selection.identity.Account,
			selection.backendRef,
			canonicalMFAProtocolContext(selection, "", false),
		),
	)
	if err != nil {
		return false, err
	}

	if data == nil || data.AuthState == nil || data.Username != selection.identity.Account ||
		data.UniqueUserID != selection.identity.Reference {
		return false, sessionstate.ErrBindingMismatch
	}

	if data.UsesRemoteWebAuthnAuthority() {
		manager := data.AuthState.GetBackendManager(
			data.AuthState.Runtime.UsedPassDBBackend,
			data.AuthState.Runtime.BackendName,
		)

		operations, ok := manager.(core.RemoteMFAOperations)
		if !ok {
			return false, fmt.Errorf("canonical TOTP verifier: remote MFA operations unavailable")
		}

		return operations.VerifyTOTP(data.AuthState, code)
	}

	if err = core.TotpValidation(ctx, data.AuthState, code, h.deps.Auth()); err != nil {
		return false, nil
	}

	return true, nil
}

func (h *FrontendHandler) observeCanonicalTOTP(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	success bool,
	err error,
) {
	h.observeCanonicalMFA(ctx, selection, definitions.MFAMethodTOTP, "Invalid OTP code", success, err)
}

func canonicalTOTPBackURL(ctx *gin.Context, selection canonicalMFASelectionState) string {
	if selection.availability.count > 1 {
		return flowdomain.AppendTicket(
			localizedLoginPath(ctx, frontendMFASelectPath),
			string(selection.stepUp.Value.Handle),
		)
	}

	target, ok := canonicalMFASelectionBackURL(ctx, selection)
	if !ok {
		return localizedLoginPath(ctx, frontendLoginPath)
	}

	return target
}
