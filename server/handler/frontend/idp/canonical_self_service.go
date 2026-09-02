// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

const canonicalSelfServiceAssuranceScope = "self-service"

type canonicalSelfServiceRename func(
	*gin.Context,
	*cookie.CanonicalSession,
	cookie.SessionIdentity,
	[]byte,
	string,
) error

type canonicalSelfServiceBackendResolver func(
	*gin.Context,
	*cookie.CanonicalSession,
	cookie.SessionIdentity,
) (*UserBackendData, uint8, error)

type canonicalSelfServiceTOTPDeleter func(*gin.Context, *UserBackendData) error

type canonicalSelfServiceRecoveryGenerator func(*gin.Context, *UserBackendData) ([]string, error)

// authorizeCanonicalSelfServiceMutation accepts only exact-scope fresh assurance or starts one typed operation.
func (h *FrontendHandler) authorizeCanonicalSelfServiceMutation(
	ctx *gin.Context,
	supportedMethods []string,
	mutation *mfaSelfServiceStepUpMutation,
) bool {
	if ctx == nil {
		return false
	}

	session := cookie.GetCanonicalSession(ctx)
	if _, authenticated := session.Identity(); !authenticated {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	target, ok := mfaSelfServiceStepUpTargetForRequest(ctx)
	if !ok {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	credentialID, deviceName, ok := canonicalSelfServiceMutationPayload(target.action, mutation)
	if !ok {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	if canonicalSessionHasFreshSelfServiceAssurance(session) {
		return true
	}

	handle, err := beginCanonicalSelfServiceStepUp(
		ctx, session, target.action, supportedMethods, h.canonicalGlobalMFAMethodLevels(), credentialID, deviceName,
	)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	redirectCanonicalBrowserMutation(
		ctx,
		flowdomain.AppendTicket(h.getMFASelectPath(ctx), string(handle)),
	)

	return false
}

// beginCanonicalSelfServiceStepUp stores one operation-bound assurance challenge.
func beginCanonicalSelfServiceStepUp(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	operation string,
	supportedMethods []string,
	methodLevels map[string]int,
	credentialID string,
	deviceName string,
) (sessionstate.Handle, error) {
	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		return "", err
	}

	record := &sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
		SelfServiceOperation: operation, RequestedLevel: 1,
		SelfServiceCredentialID: credentialID, SelfServiceDeviceName: deviceName,
		SupportedMethods: append([]string(nil), supportedMethods...), MethodLevels: maps.Clone(methodLevels),
		Scope: canonicalSelfServiceAssuranceScope,
	}
	err = mfastate.NewAggregate(session.Stores, session.Handle, canonicalStepUpTTL).
		BeginStepUp(ctx.Request.Context(), record)

	return handle, err
}

// authorizeCanonicalSelfServiceCaller resolves factor choices only from the canonical identity and backend capability.
func (h *FrontendHandler) authorizeCanonicalSelfServiceCaller(
	ctx *gin.Context,
	mutation *mfaSelfServiceStepUpMutation,
) bool {
	session := cookie.GetCanonicalSession(ctx)

	identity, authenticated := session.Identity()
	if !authenticated {
		if ctx != nil {
			ctx.AbortWithStatus(http.StatusConflict)
		}

		return false
	}

	if canonicalSessionHasFreshSelfServiceAssurance(session) {
		return h.authorizeCanonicalSelfServiceMutation(ctx, nil, mutation)
	}

	resolver := h.canonicalMFAAvailabilityResolver
	if resolver == nil {
		resolver = h.resolveCanonicalMFAAvailability
	}

	availability, err := resolver(ctx, session, identity, nil, nil)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	availability = filterCanonicalMFAAvailability(availability, nil, 1, h.canonicalGlobalMFAMethodLevels())

	supported := canonicalSelfServiceSupportedMethods(availability)
	if len(supported) == 0 {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	return h.authorizeCanonicalSelfServiceMutation(ctx, supported, mutation)
}

func canonicalSelfServiceMutationPayload(
	action string,
	mutation *mfaSelfServiceStepUpMutation,
) (string, string, bool) {
	if action != mfaSelfServiceActionWebAuthnDeviceName {
		return "", "", mutation == nil
	}

	if mutation == nil || strings.TrimSpace(mutation.webAuthnCredentialID) == "" ||
		strings.TrimSpace(mutation.webAuthnDeviceName) == "" {
		return "", "", false
	}

	return mutation.webAuthnCredentialID, mutation.webAuthnDeviceName, true
}

func canonicalSelfServiceSupportedMethods(availability mfaAvailability) []string {
	methods := make([]string, 0, 3)
	if availability.haveTOTP {
		methods = append(methods, definitions.MFAMethodTOTP)
	}

	if availability.haveWebAuthn {
		methods = append(methods, definitions.MFAMethodWebAuthn)
	}

	if availability.haveRecoveryCodes {
		methods = append(methods, definitions.MFAMethodRecoveryCodes)
	}

	return methods
}

func canonicalSessionHasFreshSelfServiceAssurance(session *cookie.CanonicalSession) bool {
	if session == nil {
		return false
	}

	assurance, ok := session.Assurance(session.EvaluationTime())

	return ok && assurance.Level >= 1 && assurance.Scope == canonicalSelfServiceAssuranceScope
}

func canonicalSelfServiceReturnTarget(ctx *gin.Context, operation string) (string, bool) {
	path, ok := mfaSelfServiceStepUpReturnForAction(strings.TrimSpace(operation))
	if !ok {
		return "", false
	}

	return localizedMFARootPath(ctx, path), true
}

func canonicalMFASelectionBackURL(ctx *gin.Context, selection canonicalMFASelectionState) (string, bool) {
	if selection.parent != nil {
		return flowdomain.AppendTicket(localizedLoginPath(ctx, frontendLoginPath), selection.parent.FlowID), true
	}

	return canonicalSelfServiceReturnTarget(ctx, selection.stepUp.Value.SelfServiceOperation)
}

func canonicalSelfServiceCompletionTarget(
	ctx *gin.Context,
	completion cookie.StepUpCompletion,
) (string, bool, error) {
	operation := strings.TrimSpace(completion.SelfServiceOperation)
	if operation == "" {
		if completion.Flow == "" {
			return "", false, sessionstate.ErrBindingMismatch
		}

		return "", false, nil
	}

	if completion.Flow != "" {
		return "", false, sessionstate.ErrBindingMismatch
	}

	if operation == mfaSelfServiceActionWebAuthnDeviceName {
		if completion.Handle == "" {
			return "", false, sessionstate.ErrBindingMismatch
		}

		return flowdomain.AppendTicket(
			localizedMFARootPath(ctx, definitions.MFARoot+"/self-service/continue"),
			string(completion.Handle),
		), true, nil
	}

	target, ok := canonicalSelfServiceReturnTarget(ctx, operation)
	if !ok {
		return "", false, sessionstate.ErrBindingMismatch
	}

	return target, true, nil
}

//nolint:gocyclo // Self-service continuation validates operation, assurance, selected backend, and consume together.
func (h *FrontendHandler) continueCanonicalSelfServiceStepUp(ctx *gin.Context) {
	session := cookie.GetCanonicalSession(ctx)

	identity, authenticated := session.Identity()
	if !authenticated || !canonicalSessionHasFreshSelfServiceAssurance(session) {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	aggregate := mfastate.NewAggregate(session.Stores, session.Handle, 0)

	loaded, err := aggregate.LoadStepUp(ctx.Request.Context(), ticket)
	if err != nil || !loaded.Value.Completed || loaded.Value.Flow != "" ||
		loaded.Value.SelfServiceOperation != mfaSelfServiceActionWebAuthnDeviceName ||
		loaded.Value.Scope != canonicalSelfServiceAssuranceScope ||
		strings.TrimSpace(loaded.Value.SelfServiceCredentialID) == "" ||
		strings.TrimSpace(loaded.Value.SelfServiceDeviceName) == "" {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	credentialID, err := base64.RawURLEncoding.DecodeString(loaded.Value.SelfServiceCredentialID)
	if err != nil || len(credentialID) == 0 ||
		len([]rune(loaded.Value.SelfServiceDeviceName)) > webAuthnDeviceNameMaxRunes {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if err = aggregate.DeleteStepUp(ctx.Request.Context(), ticket); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	rename := h.canonicalSelfServiceRename
	if rename == nil {
		rename = h.renameCanonicalSelfServiceDevice
	}

	if err = rename(ctx, session, identity, credentialID, loaded.Value.SelfServiceDeviceName); err != nil {
		h.renderPendingWebAuthnDeviceNameError(ctx, "Failed to update credential", err)

		return
	}

	redirectWebAuthnDevices(ctx)
}

func (h *FrontendHandler) renameCanonicalSelfServiceDevice(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	credentialID []byte,
	deviceName string,
) error {
	data, err := h.getUserBackendDataForIdentity(
		ctx,
		newBackendDataLookupRequest(
			identity.Account,
			canonicalRemoteBackendRef(session),
			core.IDPMFAProtocolContext{Protocol: identity.Protocol},
		),
	)
	if err != nil {
		return err
	}

	if data == nil || data.Username != identity.Account || data.UniqueUserID != identity.Reference {
		return sessionstate.ErrBindingMismatch
	}

	failure := h.applyWebAuthnDeviceNameUpdate(ctx, credentialID, deviceName, data)
	if failure == nil {
		return nil
	}

	if failure.err != nil {
		return failure.err
	}

	return errors.New(failure.message)
}

func (h *FrontendHandler) canonicalSelfServiceBackend(
	ctx *gin.Context,
) (*cookie.CanonicalSession, cookie.SessionIdentity, *UserBackendData, uint8, error) {
	session := cookie.GetCanonicalSession(ctx)

	identity, authenticated := session.Identity()
	if !authenticated {
		return nil, cookie.SessionIdentity{}, nil, 0, sessionstate.ErrBindingMismatch
	}

	resolver := h.canonicalSelfServiceBackendResolver
	if resolver == nil {
		resolver = h.resolveCanonicalSelfServiceBackend
	}

	data, sourceBackend, err := resolver(ctx, session, identity)
	if err != nil {
		return nil, cookie.SessionIdentity{}, nil, 0, err
	}

	if data == nil || data.Username != identity.Account || data.UniqueUserID != identity.Reference {
		return nil, cookie.SessionIdentity{}, nil, 0, sessionstate.ErrBindingMismatch
	}

	return session, identity, data, sourceBackend, nil
}

func (h *FrontendHandler) resolveCanonicalSelfServiceBackend(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
) (*UserBackendData, uint8, error) {
	data, err := h.getUserBackendDataForIdentity(
		ctx,
		newBackendDataLookupRequest(
			identity.Account,
			canonicalRemoteBackendRef(session),
			core.IDPMFAProtocolContext{Protocol: identity.Protocol},
		),
	)
	if err != nil {
		return nil, 0, err
	}

	if data == nil {
		return nil, 0, fmt.Errorf("canonical self-service backend: unavailable")
	}

	sourceBackend := uint8(definitions.BackendLDAP)
	if data.AuthState != nil {
		sourceBackend = uint8(data.AuthState.Runtime.UsedPassDBBackend)
	}

	return data, sourceBackend, nil
}

// deleteCanonicalSelfServiceTOTP deletes TOTP through only the backend selected by canonical identity resolution.
func (h *FrontendHandler) deleteCanonicalSelfServiceTOTP(
	_ *gin.Context,
	data *UserBackendData,
) error {
	manager, err := canonicalSelfServiceMFABackend(data)
	if err != nil {
		return err
	}

	if operations, ok := manager.(core.RemoteMFAOperations); ok {
		operation, operationErr := canonicalSelfServiceOperationID("totp-delete")
		if operationErr != nil {
			return operationErr
		}

		return operations.DeleteTOTP(data.AuthState, operation)
	}

	return manager.DeleteTOTPSecret(data.AuthState)
}

// generateCanonicalSelfServiceRecoveryCodes replaces recovery codes in only the selected canonical backend.
func (h *FrontendHandler) generateCanonicalSelfServiceRecoveryCodes(
	_ *gin.Context,
	data *UserBackendData,
) ([]string, error) {
	manager, err := canonicalSelfServiceMFABackend(data)
	if err != nil {
		return nil, err
	}

	if operations, ok := manager.(core.RemoteMFAOperations); ok {
		operation, operationErr := canonicalSelfServiceOperationID("recovery-generate")
		if operationErr != nil {
			return nil, operationErr
		}

		return operations.GenerateRecoveryCodes(data.AuthState, 0, operation)
	}

	recovery, err := core.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	if err = manager.AddTOTPRecoveryCodes(data.AuthState, recovery); err != nil {
		return nil, err
	}

	return recovery.GetCodes(), nil
}

// canonicalSelfServiceMFABackend returns only the backend selected during canonical identity resolution.
func canonicalSelfServiceMFABackend(data *UserBackendData) (core.BackendManager, error) {
	if data == nil || data.AuthState == nil || data.AuthState.Runtime.UsedPassDBBackend == definitions.BackendUnknown {
		return nil, sessionstate.ErrBindingMismatch
	}

	manager := data.AuthState.GetBackendManager(
		data.AuthState.Runtime.UsedPassDBBackend,
		data.AuthState.Runtime.BackendName,
	)
	if manager == nil {
		return nil, sessionstate.ErrBindingMismatch
	}

	return manager, nil
}

// canonicalSelfServiceOperationID creates an opaque idempotency key for one backend mutation.
func canonicalSelfServiceOperationID(prefix string) (string, error) {
	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		return "", err
	}

	return prefix + ":" + string(handle), nil
}
