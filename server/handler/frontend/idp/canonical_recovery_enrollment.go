// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

const canonicalRecoveryEnrollmentKind = "recovery_enrollment"

type canonicalRecoveryEnrollmentGenerator func(
	*gin.Context,
	canonicalEnrollmentSelectionState,
	sessionstate.Handle,
) ([]string, error)

type canonicalRecoveryEnrollmentSaver func(
	*gin.Context,
	canonicalEnrollmentSelectionState,
	sessionstate.Handle,
	[]string,
) error

// renderCanonicalRecoveryEnrollment generates and renders one typed recovery-code operation.
func (h *FrontendHandler) renderCanonicalRecoveryEnrollment(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodRecoveryCodes)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	operation, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	generator := h.canonicalRecoveryEnrollmentGenerator
	if generator == nil {
		generator = h.generateCanonicalRecoveryEnrollment
	}

	codes, err := generator(ctx, selection, operation)
	if err != nil || len(codes) == 0 {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	record := &sessionstate.TOTPRecoveryRecord{
		Record:            sessionstate.Record{Handle: operation},
		Session:           selection.session.Handle,
		Flow:              selection.enrollment.Value.Handle,
		AccountReference:  selection.identity.Account,
		IdentityReference: selection.identity.Reference,
		OperationID:       "recovery-enrollment:" + string(operation),
		Kind:              canonicalRecoveryEnrollmentKind,
		RecoveryCodes:     append([]string(nil), codes...),
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

	h.renderCanonicalRecoveryEnrollmentPage(ctx, selection, operation, codes)
}

func (h *FrontendHandler) renderCanonicalRecoveryEnrollmentPage(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	operation sessionstate.Handle,
	codes []string,
) {
	data := h.recoveryCodesRegisterPageData(ctx, codes, true)
	saveTarget := flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/recovery/register/save"),
		string(selection.enrollment.Value.Handle),
	)
	continueTarget := flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/recovery/register"),
		string(selection.enrollment.Value.Handle),
	)
	data["SaveRecoveryCodesEndpoint"] = appendCanonicalEnrollmentOperation(saveTarget, operation)
	data["PostRecoveryRegisterEndpoint"] = appendCanonicalEnrollmentOperation(continueTarget, operation)
	data["CancelMFAEndpoint"] = flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/register/cancel"),
		string(selection.enrollment.Value.Handle),
	)

	ctx.HTML(http.StatusOK, "idp_recovery_codes_register.html", data)
}

func (h *FrontendHandler) generateCanonicalRecoveryEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	operation sessionstate.Handle,
) ([]string, error) {
	data, err := h.canonicalEnrollmentBackendData(ctx, selection)
	if err != nil {
		return nil, err
	}

	manager := data.AuthState.GetBackendManager(
		data.AuthState.Runtime.UsedPassDBBackend,
		data.AuthState.Runtime.BackendName,
	)
	if operations, ok := manager.(core.RemoteMFAOperations); ok {
		return operations.GenerateRecoveryCodes(
			data.AuthState,
			0,
			"recovery-enrollment-generate:"+string(operation),
		)
	}

	recovery, err := core.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	return recovery.GetCodes(), nil
}

// saveCanonicalRecoveryEnrollment persists one generated set exactly once.
func (h *FrontendHandler) saveCanonicalRecoveryEnrollment(ctx *gin.Context) {
	selection, operation, loaded, codes, ok := h.canonicalRecoverySaveRequest(ctx)
	if !ok {
		return
	}

	if loaded.Value.Saved {
		ctx.Status(http.StatusOK)

		return
	}

	saver := h.canonicalRecoveryEnrollmentSaver
	if saver == nil {
		saver = h.persistCanonicalRecoveryEnrollment
	}

	if err := saver(ctx, selection, operation, codes); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	record := loaded.Value
	record.Revision = loaded.Revision

	record.Saved = true
	if err := mfastate.NewAggregate(
		selection.session.Stores,
		selection.session.Handle,
		canonicalEnrollmentTTL,
	).SaveTOTPRecovery(ctx.Request.Context(), &record); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	ctx.Status(http.StatusOK)
}

func (h *FrontendHandler) canonicalRecoverySaveRequest(
	ctx *gin.Context,
) (
	canonicalEnrollmentSelectionState,
	sessionstate.Handle,
	sessionstate.Versioned[sessionstate.TOTPRecoveryRecord],
	[]string,
	bool,
) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodRecoveryCodes)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return canonicalEnrollmentSelectionState{}, "",
			sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]{}, nil, false
	}

	operation, err := sessionstate.ParseHandle(ctx.Query(canonicalEnrollmentOperationParam))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return canonicalEnrollmentSelectionState{}, "",
			sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]{}, nil, false
	}

	loaded, err := h.loadCanonicalRecoveryEnrollment(ctx, selection, operation)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return canonicalEnrollmentSelectionState{}, "",
			sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]{}, nil, false
	}

	var payload recoveryCodesPayload
	if err = ctx.ShouldBindJSON(&payload); err != nil || !slices.Equal(payload.Codes, loaded.Value.RecoveryCodes) {
		ctx.AbortWithStatus(http.StatusConflict)

		return canonicalEnrollmentSelectionState{}, "",
			sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]{}, nil, false
	}

	return selection, operation, loaded, append([]string(nil), loaded.Value.RecoveryCodes...), true
}

func (h *FrontendHandler) persistCanonicalRecoveryEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	_ sessionstate.Handle,
	codes []string,
) error {
	if selection.session != nil {
		if affinity, ok := selection.session.BackendAffinity(); ok && affinity.Authority != "" {
			// Authority generation already persisted the codes atomically; the browser save only acknowledges receipt.
			return nil
		}
	}

	data, err := h.canonicalEnrollmentBackendData(ctx, selection)
	if err != nil {
		return err
	}

	manager := data.AuthState.GetBackendManager(
		data.AuthState.Runtime.UsedPassDBBackend,
		data.AuthState.Runtime.BackendName,
	)
	if _, ok := manager.(core.RemoteMFAOperations); ok {
		return nil
	}

	if manager == nil {
		return fmt.Errorf("canonical recovery enrollment: backend manager unavailable")
	}

	return manager.AddTOTPRecoveryCodes(data.AuthState, mfa.NewTOTPRecovery(codes))
}

// completeCanonicalRecoveryEnrollment advances only after the generated set was persisted.
func (h *FrontendHandler) completeCanonicalRecoveryEnrollment(ctx *gin.Context) {
	selection, err := h.canonicalEnrollmentSelection(ctx, definitions.MFAMethodRecoveryCodes)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	operation, err := sessionstate.ParseHandle(ctx.Query(canonicalEnrollmentOperationParam))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	loaded, err := h.loadCanonicalRecoveryEnrollment(ctx, selection, operation)
	if err != nil || !loaded.Value.Saved {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	aggregate := mfastate.NewAggregate(selection.session.Stores, selection.session.Handle, canonicalEnrollmentTTL)

	advanced, err := aggregate.CompleteEnrollmentMethod(
		ctx.Request.Context(),
		selection.enrollment.Value.Handle,
		definitions.MFAMethodRecoveryCodes,
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

	redirectCanonicalBrowserMutation(ctx, target)
}

func (h *FrontendHandler) loadCanonicalRecoveryEnrollment(
	ctx *gin.Context,
	selection canonicalEnrollmentSelectionState,
	operation sessionstate.Handle,
) (sessionstate.Versioned[sessionstate.TOTPRecoveryRecord], error) {
	loaded, err := mfastate.NewAggregate(selection.session.Stores, selection.session.Handle, 0).
		LoadTOTPRecovery(ctx.Request.Context(), operation)
	if err != nil {
		return sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]{}, err
	}

	value := loaded.Value
	if !value.Generated || value.Kind != canonicalRecoveryEnrollmentKind || len(value.RecoveryCodes) == 0 ||
		value.Flow != selection.enrollment.Value.Handle ||
		value.AccountReference != selection.identity.Account ||
		value.IdentityReference != selection.identity.Reference {
		return sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]{}, sessionstate.ErrBindingMismatch
	}

	return loaded, nil
}
