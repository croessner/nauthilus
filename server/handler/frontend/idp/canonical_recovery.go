// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/frontend"
	"github.com/croessner/nauthilus/v4/server/middleware/csrf"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

type canonicalRecoveryVerifier func(*gin.Context, canonicalMFASelectionState, string) (bool, error)

//nolint:dupl // Recovery and TOTP deliberately use parallel templates with distinct fields and messages.
func (h *FrontendHandler) renderCanonicalRecovery(ctx *gin.Context, haveError bool) {
	selection, err := h.canonicalRecoverySelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["RecoveryVerifyMessage"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "Please enter one of your recovery codes",
	)
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")
	data["CSRFToken"] = csrf.Token(ctx)
	data["PostRecoveryVerifyEndpoint"] = ctx.Request.URL.Path
	data["BackURL"] = canonicalTOTPBackURL(ctx, selection)
	data["HaveError"] = haveError

	if haveError {
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid recovery code")
	}

	ctx.HTML(http.StatusOK, "idp_recovery_login.html", data)
}

//nolint:funlen // Recovery completion keeps verification, atomic consume, assurance, and continuation ordered.
func (h *FrontendHandler) completeCanonicalRecovery(ctx *gin.Context) {
	selection, err := h.canonicalRecoverySelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	code := ctx.PostForm("code")
	if code == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	verifier := h.canonicalRecoveryVerifier
	if verifier == nil {
		verifier = h.verifyCanonicalRecovery
	}

	valid, err := verifier(ctx, selection, code)
	if err != nil {
		h.observeCanonicalRecovery(ctx, selection, false, err)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if !valid {
		h.observeCanonicalRecovery(ctx, selection, false, nil)
		h.renderCanonicalRecovery(ctx, true)

		return
	}

	if completeCanonicalFailLatchedMFA(ctx, selection, definitions.MFAMethodRecoveryCodes) {
		return
	}

	completion, err := selection.session.CompleteStepUp(
		ctx.Request.Context(),
		selection.stepUp.Value.Handle,
		definitions.MFAMethodRecoveryCodes,
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

	h.observeCanonicalRecovery(ctx, selection, true, nil)

	if selfService {
		ctx.Redirect(http.StatusFound, target)

		return
	}

	h.resumeCanonicalIDPFlow(ctx, selection.session, selection.parent)
}

func (h *FrontendHandler) canonicalRecoverySelection(ctx *gin.Context) (canonicalMFASelectionState, error) {
	selection, err := h.canonicalMFASelection(ctx)
	if err != nil {
		return canonicalMFASelectionState{}, err
	}

	if !selection.availability.haveRecoveryCodes {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	return selection, nil
}

//nolint:gocyclo // Verification supports the bounded remote, atomic local, and replacement-code backends.
func (h *FrontendHandler) verifyCanonicalRecovery(
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

	manager := data.AuthState.GetBackendManager(
		data.AuthState.Runtime.UsedPassDBBackend,
		data.AuthState.Runtime.BackendName,
	)
	if manager == nil {
		return false, fmt.Errorf("canonical recovery verifier: backend manager unavailable")
	}

	if operations, ok := manager.(core.RemoteMFAOperations); ok {
		return operations.UseRecoveryCode(
			data.AuthState,
			code,
			"recovery-use:"+string(selection.stepUp.Value.Handle),
		)
	}

	if consumer, ok := manager.(core.TOTPRecoveryCodeConsumer); ok {
		valid, _, consumeErr := consumer.ConsumeTOTPRecoveryCode(data.AuthState, code)

		return valid, consumeErr
	}

	recoveryCodes := data.AuthState.GetTOTPRecoveryCodes()
	if !slices.Contains(recoveryCodes, code) {
		return false, nil
	}

	remaining := make([]string, 0, len(recoveryCodes)-1)
	for _, candidate := range recoveryCodes {
		if candidate != code {
			remaining = append(remaining, candidate)
		}
	}

	if err = manager.AddTOTPRecoveryCodes(data.AuthState, mfa.NewTOTPRecovery(remaining)); err != nil {
		return true, err
	}

	return true, nil
}

func (h *FrontendHandler) observeCanonicalRecovery(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	success bool,
	err error,
) {
	h.observeCanonicalMFA(
		ctx, selection, definitions.MFAMethodRecoveryCodes, "Invalid recovery code", success, err,
	)
}
