// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

const (
	canonicalTOTPEnrollmentKind       = "totp_enrollment"
	canonicalEnrollmentOperationParam = "operation"
)

type canonicalEnrollmentSelectionState struct {
	session    *cookie.CanonicalSession
	identity   cookie.SessionIdentity
	parent     *flowdomain.State
	enrollment sessionstate.Versioned[sessionstate.EnrollmentRecord]
}

type canonicalTOTPEnrollmentPending struct {
	Secret                string `json:"secret,omitempty"`
	QRCodeURL             string `json:"-"`
	PendingRegistrationID string `json:"pending_registration_id,omitempty"`
	Remote                bool   `json:"remote"`
}

type canonicalTOTPEnrollmentStarter func(
	*gin.Context,
	canonicalEnrollmentSelectionState,
	sessionstate.Handle,
) (canonicalTOTPEnrollmentPending, error)

type canonicalTOTPEnrollmentFinisher func(
	*gin.Context,
	canonicalEnrollmentSelectionState,
	canonicalTOTPEnrollmentPending,
	sessionstate.Handle,
	string,
) (bool, error)

// canonicalEnrollmentSelection loads one identity- and parent-bound enrollment step.
//
//nolint:gocyclo // Enrollment selection validates parent, identity, method, revision, and expiry as one binding gate.
func (h *FrontendHandler) canonicalEnrollmentSelection(
	ctx *gin.Context,
	method string,
) (canonicalEnrollmentSelectionState, error) {
	if h == nil || ctx == nil || ctx.Request == nil {
		return canonicalEnrollmentSelectionState{}, fmt.Errorf("canonical enrollment: unavailable request")
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		return canonicalEnrollmentSelectionState{}, sessionstate.ErrBindingMismatch
	}

	identity, authenticated := session.Identity()
	if !authenticated {
		return canonicalEnrollmentSelectionState{}, sessionstate.ErrBindingMismatch
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		return canonicalEnrollmentSelectionState{}, err
	}

	enrollment, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(ctx.Request.Context(), ticket)
	if err != nil {
		return canonicalEnrollmentSelectionState{}, err
	}

	value := enrollment.Value
	if value.Completed || value.CurrentStep != method || value.Flow == "" ||
		value.AccountReference != identity.Account || value.IdentityReference != identity.Reference {
		return canonicalEnrollmentSelectionState{}, sessionstate.ErrBindingMismatch
	}

	parent, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(ctx.Request.Context(), string(value.Flow))
	if err != nil || parent.AuthOutcome != flowdomain.AuthOutcomeOK || !validCanonicalLoginFlow(parent) {
		return canonicalEnrollmentSelectionState{}, sessionstate.ErrBindingMismatch
	}

	return canonicalEnrollmentSelectionState{
		session: session, identity: identity, parent: parent, enrollment: enrollment,
	}, nil
}

// renderCanonicalTOTPEnrollment begins and renders one typed TOTP enrollment operation.
func (h *FrontendHandler) renderCanonicalTOTPEnrollment(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodTOTP)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	operation, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	starter := h.canonicalTOTPEnrollmentStarter
	if starter == nil {
		starter = h.startCanonicalTOTPEnrollment
	}

	pending, err := starter(ctx, selection, operation)
	if err != nil || pending.Secret == "" || pending.QRCodeURL == "" {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	payload, err := json.Marshal(pending)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	record := &sessionstate.TOTPRecoveryRecord{
		Record:            sessionstate.Record{Handle: operation},
		Session:           selection.session.Handle,
		Flow:              selection.enrollment.Value.Handle,
		AccountReference:  selection.identity.Account,
		IdentityReference: selection.identity.Reference,
		OperationID:       "totp-enrollment:" + string(operation),
		Kind:              canonicalTOTPEnrollmentKind,
		PendingMaterial:   payload,
		Generated:         true,
	}
	if err = mfastate.NewAggregate(
		selection.session.Stores,
		selection.session.Handle,
		canonicalEnrollmentTTL,
	).SaveTOTPRecovery(ctx.Request.Context(), record); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	h.renderCanonicalTOTPEnrollmentPage(ctx, selection, operation, pending)
}

// renderCanonicalTOTPEnrollmentPage renders setup material with opaque flow and operation selectors.
func (h *FrontendHandler) renderCanonicalTOTPEnrollmentPage(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	operation sessionstate.Handle,
	pending canonicalTOTPEnrollmentPending,
) {
	data := h.basePageData(ctx)
	data["QRCode"], data["Secret"] = pending.QRCodeURL, pending.Secret
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")
	data["TOTPMessage"] = frontend.GetLocalized(
		ctx, h.deps.Cfg, h.deps.Logger, "Please scan and verify the following QR code",
	)
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["CSRFToken"] = csrf.Token(ctx)

	postPath := flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/totp/register"),
		string(selection.enrollment.Value.Handle),
	)
	data["PostTOTPRegisterPath"] = appendCanonicalEnrollmentOperation(postPath, operation)
	data["RequireMFAFlow"] = true
	data["RequireMFAMessage"] = frontend.GetLocalized(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		"Your application requires this authentication method to be set up before you can continue",
	)
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["CancelMFAEndpoint"] = flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/register/cancel"),
		string(selection.enrollment.Value.Handle),
	)

	ctx.HTML(http.StatusOK, "idp_totp_register.html", data)
}

// startCanonicalTOTPEnrollment creates backend setup material without browser-session state.
func (h *FrontendHandler) startCanonicalTOTPEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	operation sessionstate.Handle,
) (canonicalTOTPEnrollmentPending, error) {
	data, err := h.canonicalEnrollmentBackendData(ctx, selection)
	if err != nil {
		return canonicalTOTPEnrollmentPending{}, err
	}

	manager := data.AuthState.GetBackendManager(
		data.AuthState.Runtime.UsedPassDBBackend,
		data.AuthState.Runtime.BackendName,
	)
	if operations, ok := manager.(core.RemoteMFAOperations); ok {
		registration, beginErr := operations.BeginTOTPRegistration(
			data.AuthState,
			"totp-enrollment-begin:"+string(operation),
		)
		if beginErr != nil {
			return canonicalTOTPEnrollmentPending{}, beginErr
		}

		return canonicalTOTPEnrollmentPending{
			Secret: registration.Secret, QRCodeURL: registration.OTPAuthURL,
			PendingRegistrationID: registration.PendingRegistrationID, Remote: true,
		}, nil
	}

	registration, err := core.NewTOTPSettings(h.deps.Cfg).Generate(selection.identity.Account)
	if err != nil {
		return canonicalTOTPEnrollmentPending{}, err
	}

	return canonicalTOTPEnrollmentPending{
		Secret: registration.Secret, QRCodeURL: registration.OTPAuthURL,
	}, nil
}

// completeCanonicalTOTPEnrollment verifies pending setup and advances its enrollment once.
//
//nolint:funlen // TOTP enrollment keeps material verification, persistence, consume, and continuation ordered.
func (h *FrontendHandler) completeCanonicalTOTPEnrollment(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodTOTP)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	operation, err := sessionstate.ParseHandle(ctx.Query(canonicalEnrollmentOperationParam))

	code := ctx.PostForm("code")
	if err != nil || code == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	pending, err := h.loadCanonicalTOTPEnrollment(ctx, selection, operation)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	finisher := h.canonicalTOTPEnrollmentFinisher
	if finisher == nil {
		finisher = h.finishCanonicalTOTPEnrollment
	}

	valid, err := finisher(ctx, selection, pending, operation, code)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if !valid {
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	aggregate := mfastate.NewAggregate(
		selection.session.Stores,
		selection.session.Handle,
		canonicalEnrollmentTTL,
	)

	advanced, err := aggregate.CompleteEnrollmentMethod(
		ctx.Request.Context(),
		selection.enrollment.Value.Handle,
		definitions.MFAMethodTOTP,
	)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if err = aggregate.DeleteTOTPRecovery(ctx.Request.Context(), operation); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	target := canonicalEnrollmentNextTarget(advanced.Value)
	if target == "" {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	ctx.Header("HX-Redirect", target)
	ctx.Status(http.StatusOK)
}

// loadCanonicalTOTPEnrollment loads and validates one pending typed setup operation.
func (h *FrontendHandler) loadCanonicalTOTPEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	operation sessionstate.Handle,
) (canonicalTOTPEnrollmentPending, error) {
	loaded, err := mfastate.NewAggregate(selection.session.Stores, selection.session.Handle, 0).
		LoadTOTPRecovery(ctx.Request.Context(), operation)
	if err != nil {
		return canonicalTOTPEnrollmentPending{}, err
	}

	value := loaded.Value
	if value.Saved || !value.Generated || value.Kind != canonicalTOTPEnrollmentKind ||
		value.Flow != selection.enrollment.Value.Handle ||
		value.AccountReference != selection.identity.Account ||
		value.IdentityReference != selection.identity.Reference {
		return canonicalTOTPEnrollmentPending{}, sessionstate.ErrBindingMismatch
	}

	var pending canonicalTOTPEnrollmentPending
	if err = json.Unmarshal(value.PendingMaterial, &pending); err != nil || pending.Secret == "" {
		return canonicalTOTPEnrollmentPending{}, sessionstate.ErrBindingMismatch
	}

	return pending, nil
}

// finishCanonicalTOTPEnrollment persists one validated local or authority-owned setup.
func (h *FrontendHandler) finishCanonicalTOTPEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	pending canonicalTOTPEnrollmentPending,
	operation sessionstate.Handle,
	code string,
) (bool, error) {
	data, err := h.canonicalEnrollmentBackendData(ctx, selection)
	if err != nil {
		return false, err
	}

	manager := data.AuthState.GetBackendManager(
		data.AuthState.Runtime.UsedPassDBBackend,
		data.AuthState.Runtime.BackendName,
	)
	if pending.Remote {
		operations, ok := manager.(core.RemoteMFAOperations)
		if !ok || pending.PendingRegistrationID == "" {
			return false, sessionstate.ErrBindingMismatch
		}

		if err = operations.FinishTOTPRegistration(
			data.AuthState,
			pending.PendingRegistrationID,
			code,
			"totp-enrollment-finish:"+string(operation),
		); err != nil {
			return false, err
		}

		return true, nil
	}

	if err = core.ValidateTOTPCode(code, pending.Secret, h.deps.Auth()); err != nil {
		return false, nil
	}

	if manager == nil {
		return false, fmt.Errorf("canonical TOTP enrollment: backend manager unavailable")
	}

	if err = manager.AddTOTPSecret(data.AuthState, core.NewTOTPSecret(pending.Secret)); err != nil {
		return false, err
	}

	return true, nil
}

// canonicalEnrollmentBackendData resolves the target identity through its canonical affinity.
func (h *FrontendHandler) canonicalEnrollmentBackendData(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
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

	if data == nil || data.AuthState == nil || data.Username != selection.identity.Account ||
		data.UniqueUserID != selection.identity.Reference {
		return nil, sessionstate.ErrBindingMismatch
	}

	return data, nil
}

// appendCanonicalEnrollmentOperation adds one opaque typed child selector to a local target.
func appendCanonicalEnrollmentOperation(target string, operation sessionstate.Handle) string {
	parsed, err := url.Parse(target)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return target
	}

	query := parsed.Query()
	query.Set(canonicalEnrollmentOperationParam, string(operation))
	parsed.RawQuery = query.Encode()

	return parsed.String()
}

type canonicalEnrollmentContinuationState struct {
	session    *cookie.CanonicalSession
	enrollment sessionstate.Versioned[sessionstate.EnrollmentRecord]
	parent     *flowdomain.State
	target     string
}

//nolint:gocyclo // Enrollment continuation resolves required-factor sequencing and typed parent resume together.
func (h *FrontendHandler) canonicalEnrollmentContinuation(
	ctx *gin.Context,
	requireCompleted bool,
) (canonicalEnrollmentContinuationState, error) {
	if ctx == nil || ctx.Request == nil {
		return canonicalEnrollmentContinuationState{}, sessionstate.ErrBindingMismatch
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		return canonicalEnrollmentContinuationState{}, sessionstate.ErrBindingMismatch
	}

	identity, authenticated := session.Identity()
	if !authenticated {
		return canonicalEnrollmentContinuationState{}, sessionstate.ErrBindingMismatch
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		return canonicalEnrollmentContinuationState{}, err
	}

	enrollment, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(ctx.Request.Context(), ticket)
	if err != nil {
		return canonicalEnrollmentContinuationState{}, err
	}

	value := enrollment.Value
	if value.Flow == "" || value.AccountReference != identity.Account ||
		value.IdentityReference != identity.Reference || requireCompleted && !value.Completed {
		return canonicalEnrollmentContinuationState{}, sessionstate.ErrBindingMismatch
	}

	aggregate := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0)

	parent, err := aggregate.Load(ctx.Request.Context(), string(value.Flow))
	if err != nil || parent.AuthOutcome != flowdomain.AuthOutcomeOK || !validCanonicalLoginFlow(parent) {
		return canonicalEnrollmentContinuationState{}, sessionstate.ErrBindingMismatch
	}

	decision, err := aggregate.Resume(ctx.Request.Context(), parent.FlowID)
	if err != nil {
		return canonicalEnrollmentContinuationState{}, err
	}

	target := safeLocalIDPResumeTarget(decision.RedirectURI)
	if target == "" || target != safeLocalIDPResumeTarget(value.Continuation) {
		return canonicalEnrollmentContinuationState{}, sessionstate.ErrBindingMismatch
	}

	return canonicalEnrollmentContinuationState{
		session: session, enrollment: enrollment, parent: parent, target: target,
	}, nil
}

// canonicalEnrollmentNextTarget selects the next typed method or the stored safe continuation.
func canonicalEnrollmentNextTarget(record sessionstate.EnrollmentRecord) string {
	if record.Completed {
		return flowdomain.AppendTicket(definitions.MFARoot+"/register/continue", string(record.Handle))
	}

	target := canonicalRequiredMFARegistrationTarget(record.CurrentStep)
	if target == "" {
		return ""
	}

	return flowdomain.AppendTicket(target, string(record.Handle))
}
