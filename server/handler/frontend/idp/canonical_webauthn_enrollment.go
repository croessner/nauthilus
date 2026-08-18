// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"net/http"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/gin-gonic/gin"
)

type canonicalWebAuthnEnrollmentBegin func(
	*gin.Context,
	canonicalEnrollmentSelectionState,
) (any, sessionstate.Handle, error)

type canonicalWebAuthnEnrollmentFinish func(
	*gin.Context,
	canonicalEnrollmentSelectionState,
	sessionstate.Handle,
) error

// renderCanonicalWebAuthnEnrollment renders one typed enrollment-bound registration page.
func (h *FrontendHandler) renderCanonicalWebAuthnEnrollment(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodWebAuthn)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")
	data["WebAuthnMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please connect your security key and follow the instructions")
	data["DeviceNameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device name")
	data["DeviceNamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "e.g. Office YubiKey")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingRegistration"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing registration...")
	data["JSDeviceNameRequired"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter a device name")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")
	data["CSRFToken"] = csrf.Token(ctx)
	data["WebAuthnBeginEndpoint"] = flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register/begin"),
		string(selection.enrollment.Value.Handle),
	)
	data["WebAuthnFinishEndpoint"] = flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register/finish"),
		string(selection.enrollment.Value.Handle),
	)
	data["WebAuthnNextEndpoint"] = safeLocalIDPResumeTarget(selection.enrollment.Value.Continuation)
	data["RequireMFAFlow"] = true
	data["RequireMFAMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Your application requires this authentication method to be set up before you can continue")
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["CancelMFAEndpoint"] = flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/register/cancel"),
		string(selection.enrollment.Value.Handle),
	)

	ctx.HTML(http.StatusOK, "idp_webauthn_register.html", data)
}

// BeginWebAuthnRegistration creates one typed, parent-bound registration ceremony.
func (h *FrontendHandler) BeginWebAuthnRegistration(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodWebAuthn)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	begin := h.canonicalWebAuthnEnrollmentBegin
	if begin == nil {
		begin = h.beginCanonicalWebAuthnEnrollment
	}

	options, ceremony, err := begin(ctx, selection)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	ctx.JSON(http.StatusOK, canonicalWebAuthnBeginResponse{Options: options, Ceremony: string(ceremony)})
}

// FinishWebAuthnRegistration consumes one ceremony and advances its enrollment once.
func (h *FrontendHandler) FinishWebAuthnRegistration(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodWebAuthn)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	ceremony, err := sessionstate.ParseHandle(ctx.Query(canonicalWebAuthnCeremonyParameter))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	finish := h.canonicalWebAuthnEnrollmentFinish
	if finish == nil {
		finish = h.finishCanonicalWebAuthnEnrollment
	}

	if err = finish(ctx, selection, ceremony); err != nil {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "fail").Inc()

		if !ctx.Writer.Written() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return
	}

	advanced, err := mfastate.NewAggregate(
		selection.session.Stores, selection.session.Handle, canonicalEnrollmentTTL,
	).CompleteEnrollmentMethod(
		ctx.Request.Context(), selection.enrollment.Value.Handle, definitions.MFAMethodWebAuthn,
	)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	target := canonicalEnrollmentNextTarget(advanced.Value)
	if target == "" {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "webauthn", "success").Inc()
	ctx.JSON(http.StatusOK, webAuthnFinishResponse{Redirect: target})
}

func (h *FrontendHandler) beginCanonicalWebAuthnEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
) (any, sessionstate.Handle, error) {
	data, err := h.canonicalEnrollmentBackendData(ctx, selection)
	if err != nil {
		return nil, "", err
	}

	user := canonicalWebAuthnEnrollmentUser(data)

	return core.BeginCanonicalWebAuthnRegistration(
		ctx.Request.Context(),
		h.deps.Auth(),
		selection.session,
		selection.enrollment.Value.Handle,
		selection.identity.Reference,
		string(selection.parent.Protocol),
		user,
	)
}

func (h *FrontendHandler) finishCanonicalWebAuthnEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	ceremony sessionstate.Handle,
) error {
	data, err := h.canonicalEnrollmentBackendData(ctx, selection)
	if err != nil {
		return err
	}

	return core.CompleteCanonicalWebAuthnRegistration(
		ctx,
		h.deps.Auth(),
		selection.session,
		ceremony,
		selection.enrollment.Value.Handle,
		selection.identity.Reference,
		string(selection.parent.Protocol),
		canonicalWebAuthnEnrollmentUser(data),
		data.AuthState,
	)
}

func canonicalWebAuthnEnrollmentUser(data *UserBackendData) *backend.User {
	if data == nil {
		return nil
	}

	if data.WebAuthnUser != nil {
		return data.WebAuthnUser
	}

	return backend.NewUser(data.Username, data.DisplayName, data.UniqueUserID)
}
