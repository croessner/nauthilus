// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/gin-gonic/gin"
)

type canonicalMFAAvailabilityResolver func(
	*gin.Context,
	*cookie.CanonicalSession,
	cookie.SessionIdentity,
	*flowdomain.State,
	[]string,
) (mfaAvailability, error)

const (
	canonicalMFAStatusFail    = "fail"
	canonicalMFAStatusSuccess = "success"
)

type canonicalMFASelectionState struct {
	session      *cookie.CanonicalSession
	identity     cookie.SessionIdentity
	backendRef   core.RemoteBackendRef
	parent       *flowdomain.State
	stepUp       sessionstate.Versioned[sessionstate.StepUpRecord]
	availability mfaAvailability
	failLatched  bool
}

func canonicalMFABoundFlow(selection canonicalMFASelectionState) sessionstate.Handle {
	if selection.stepUp.Value.Flow != "" {
		return selection.stepUp.Value.Flow
	}

	return selection.stepUp.Value.Handle
}

func canonicalMFAProtocol(selection canonicalMFASelectionState) string {
	if selection.parent != nil {
		return string(selection.parent.Protocol)
	}

	return selection.identity.Protocol
}

func completeCanonicalFailLatchedMFA(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	method string,
) bool {
	if !selection.failLatched {
		return false
	}

	_, err := selection.session.ConsumeFailLatchedStepUp(
		ctx.Request.Context(), selection.stepUp.Value.Handle, method,
	)
	if err != nil {
		if errors.Is(err, sessionstate.ErrBindingMismatch) ||
			errors.Is(err, sessionstate.ErrRevisionConflict) ||
			errors.Is(err, sessionstate.ErrNotFound) ||
			errors.Is(err, sessionstate.ErrExpired) {
			ctx.AbortWithStatus(http.StatusConflict)

			return true
		}

		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return true
	}

	ctx.AbortWithStatus(http.StatusUnauthorized)

	return true
}

func (h *FrontendHandler) observeCanonicalMFA(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	method string,
	failureMessage string,
	success bool,
	err error,
) {
	status := canonicalMFAStatusFail
	message := failureMessage

	if success {
		status = canonicalMFAStatusSuccess
		message = ""
	} else if err != nil {
		message = err.Error()
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", method, status).Inc()

	if h == nil || h.deps == nil {
		return
	}

	core.LogIDPMFAuthResult(
		ctx,
		h.deps.Auth(),
		canonicalMFAProtocolContext(selection, method, success),
		selection.identity.Account,
		method,
		message,
		success,
	)
}

func canonicalMFAProtocolContext(
	selection canonicalMFASelectionState,
	method string,
	completed bool,
) core.IDPMFAProtocolContext {
	protocolContext := core.IDPMFAProtocolContext{Protocol: selection.identity.Protocol}
	protocolContext.Request.MFACompleted = completed

	protocolContext.Request.MFAMethod = method
	if selection.parent == nil {
		return protocolContext
	}

	protocolContext.Protocol = string(selection.parent.Protocol)
	protocolContext.Request.GrantType = selection.parent.GrantType
	protocolContext.Request.RedirectURI = selection.parent.Metadata[flowdomain.FlowMetadataRedirectURI]

	protocolContext.Request.RequestedScopes = strings.Fields(
		selection.parent.Metadata[flowdomain.FlowMetadataScope],
	)
	switch selection.parent.Protocol {
	case flowdomain.FlowProtocolOIDC:
		protocolContext.OIDCClientID = selection.parent.Metadata[flowdomain.FlowMetadataClientID]
	case flowdomain.FlowProtocolSAML:
		protocolContext.SAMLEntityID = selection.parent.Metadata[flowdomain.FlowMetadataSAMLEntityID]
	}

	return protocolContext
}

// canonicalMFASelection composes one incomplete typed step-up with its canonical identity and parent flow.
//
//nolint:gocyclo,funlen // Selection validates the complete ticket, parent, identity, affinity, and factor binding.
func (h *FrontendHandler) canonicalMFASelection(ctx *gin.Context) (canonicalMFASelectionState, error) {
	if h == nil || ctx == nil || ctx.Request == nil {
		return canonicalMFASelectionState{}, fmt.Errorf("canonical MFA selection: unavailable request")
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		return canonicalMFASelectionState{}, fmt.Errorf("canonical MFA selection: ticket: %w", err)
	}

	stepUp, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(ctx.Request.Context(), ticket)
	if err != nil {
		return canonicalMFASelectionState{}, fmt.Errorf("canonical MFA selection: step-up: %w", err)
	}

	selfServiceOperation := strings.TrimSpace(stepUp.Value.SelfServiceOperation)
	hasParentFlow := stepUp.Value.Flow != ""

	hasSelfServiceOperation := selfServiceOperation != ""
	if stepUp.Value.Completed || hasParentFlow == hasSelfServiceOperation || stepUp.Value.RequestedLevel <= 0 ||
		strings.TrimSpace(stepUp.Value.Scope) == "" {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	var parent *flowdomain.State
	if hasParentFlow {
		parent, err = flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
			Load(ctx.Request.Context(), string(stepUp.Value.Flow))
		if err != nil || !validCanonicalLoginFlow(parent) {
			return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
		}
	} else if stepUp.Value.Scope != canonicalSelfServiceAssuranceScope {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	_, authenticated := session.Identity()

	failLatched := stepUp.Value.AuthOutcome == string(flowdomain.AuthOutcomeFailLatched)
	if failLatched {
		pending := stepUp.Value.PendingIdentity
		if authenticated || parent == nil || parent.AuthOutcome != flowdomain.AuthOutcomeFailLatched ||
			session.Anchor.Value.Assurance.Level != 0 || stepUp.Value.PendingIdentityReference == "" ||
			pending.Subject != stepUp.Value.PendingIdentityReference || pending.Account == "" ||
			pending.Protocol != string(parent.Protocol) {
			return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
		}

		identity := cookie.SessionIdentity{
			Reference: stepUp.Value.PendingIdentityReference, Account: pending.Account,
			Subject: pending.Subject, DisplayName: pending.DisplayName, Protocol: pending.Protocol,
		}
		affinity := stepUp.Value.PendingBackendAffinity
		backendRef := core.RemoteBackendRef{
			Type: affinity.Type, Name: affinity.Name, Protocol: affinity.Protocol,
			Authority: affinity.Authority, OpaqueToken: affinity.OpaqueToken,
		}
		availability := filterCanonicalMFAAvailability(mfaAvailability{
			haveTOTP:          slices.Contains(stepUp.Value.SupportedMethods, definitions.MFAMethodTOTP),
			haveWebAuthn:      slices.Contains(stepUp.Value.SupportedMethods, definitions.MFAMethodWebAuthn),
			haveRecoveryCodes: slices.Contains(stepUp.Value.SupportedMethods, definitions.MFAMethodRecoveryCodes),
		}, stepUp.Value.SupportedMethods)

		return canonicalMFASelectionState{
			session: session, identity: identity, backendRef: backendRef, parent: parent,
			stepUp: stepUp, availability: availability, failLatched: true,
		}, nil
	}

	identity, mfaIdentityBound := session.MFAIdentity()
	if !mfaIdentityBound {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	backendRef := canonicalRemoteMFABackendRef(session)

	if stepUp.Value.AuthOutcome != "" || !authenticated ||
		parent != nil && parent.AuthOutcome != flowdomain.AuthOutcomeOK {
		return canonicalMFASelectionState{}, sessionstate.ErrBindingMismatch
	}

	resolver := h.canonicalMFAAvailabilityResolver
	if resolver == nil {
		resolver = h.resolveCanonicalMFAAvailability
	}

	availability, err := resolver(ctx, session, identity, parent, stepUp.Value.SupportedMethods)
	if err != nil {
		return canonicalMFASelectionState{}, fmt.Errorf("canonical MFA selection: availability: %w", err)
	}

	availability = filterCanonicalMFAAvailability(availability, stepUp.Value.SupportedMethods)

	return canonicalMFASelectionState{
		session: session, identity: identity, backendRef: backendRef, parent: parent,
		stepUp: stepUp, availability: filterCanonicalMFAAvailability(availability, stepUp.Value.SupportedMethods),
	}, nil
}

func validCanonicalLoginFlow(state *flowdomain.State) bool {
	switch state.Protocol {
	case flowdomain.FlowProtocolOIDC:
		return validCanonicalOIDCLoginFlow(state)
	case flowdomain.FlowProtocolSAML:
		return validCanonicalSAMLLoginFlow(state)
	default:
		return false
	}
}

// resolveCanonicalMFAAvailability reads factor presence through the canonical identity and backend capability only.
//
//nolint:gocyclo // Availability is fail-closed across session, parent protocol, backend, and identity checks.
func (h *FrontendHandler) resolveCanonicalMFAAvailability(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	identity cookie.SessionIdentity,
	parent *flowdomain.State,
	_ []string,
) (mfaAvailability, error) {
	if h == nil || h.deps == nil || ctx == nil || session == nil {
		return mfaAvailability{}, fmt.Errorf("canonical MFA availability: unavailable")
	}

	boundIdentity, authenticated := session.MFAIdentity()
	if !authenticated || boundIdentity != identity {
		return mfaAvailability{}, sessionstate.ErrBindingMismatch
	}

	protocol := identity.Protocol
	if parent != nil {
		protocol = string(parent.Protocol)
	}

	if strings.TrimSpace(protocol) == "" {
		return mfaAvailability{}, sessionstate.ErrBindingMismatch
	}

	data, err := h.getUserBackendDataForIdentity(
		ctx,
		newBackendDataLookupRequest(
			identity.Account,
			canonicalRemoteMFABackendRef(session),
			canonicalMFAProtocolContext(canonicalMFASelectionState{
				identity: identity,
				parent:   parent,
			}, "", false),
		),
	)
	if err != nil {
		return mfaAvailability{}, err
	}

	if data == nil || data.Username != identity.Account || data.UniqueUserID != identity.Reference {
		return mfaAvailability{}, sessionstate.ErrBindingMismatch
	}

	return mfaAvailability{
		haveTOTP: data.HaveTOTP, haveWebAuthn: data.HaveWebAuthn, haveRecoveryCodes: data.NumRecoveryCodes > 0,
	}, nil
}

func canonicalRemoteBackendRef(session *cookie.CanonicalSession) core.RemoteBackendRef {
	affinity, ok := session.BackendAffinity()
	if !ok {
		return core.RemoteBackendRef{}
	}

	return core.RemoteBackendRef{
		Type: affinity.Type, Name: affinity.Name, Protocol: affinity.Protocol,
		Authority: affinity.Authority, OpaqueToken: affinity.OpaqueToken,
	}
}

func canonicalRemoteMFABackendRef(session *cookie.CanonicalSession) core.RemoteBackendRef {
	affinity, ok := session.MFABackendAffinity()
	if !ok {
		return core.RemoteBackendRef{}
	}

	return core.RemoteBackendRef{
		Type: affinity.Type, Name: affinity.Name, Protocol: affinity.Protocol,
		Authority: affinity.Authority, OpaqueToken: affinity.OpaqueToken,
	}
}

func filterCanonicalMFAAvailability(availability mfaAvailability, supported []string) mfaAvailability {
	if len(supported) > 0 {
		availability.haveTOTP = availability.haveTOTP && slices.Contains(supported, definitions.MFAMethodTOTP)
		availability.haveWebAuthn = availability.haveWebAuthn && slices.Contains(supported, definitions.MFAMethodWebAuthn)
		availability.haveRecoveryCodes = availability.haveRecoveryCodes &&
			slices.Contains(supported, definitions.MFAMethodRecoveryCodes)
	}

	availability.count = countMFAAvailability(availability)

	return availability
}
