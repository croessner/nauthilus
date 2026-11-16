// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package idp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/sessionstate"

	"github.com/gin-gonic/gin"
)

const (
	// canonicalSelfServiceProtocol names step-ups that protect account self-service instead of a protocol flow.
	canonicalSelfServiceProtocol = "account"
	// canonicalMFAReasonVerified is the stable reason of a verified factor.
	canonicalMFAReasonVerified = "verified"
)

// canonicalAuthEventEmitter receives host step events; the production emitter is the native plugin runner.
type canonicalAuthEventEmitter interface {
	EmitAuthEvent(context.Context, pluginapi.AuthEvent)
}

// canonicalMFAOutcome is the bounded classification of one observed second-factor attempt.
type canonicalMFAOutcome struct {
	result     pluginapi.AuthEventResult
	reason     string
	flowEffect pluginapi.AuthEventFlowEffect
}

var (
	mfaOutcomeVerified = canonicalMFAOutcome{
		result: pluginapi.AuthEventSuccess, reason: canonicalMFAReasonVerified, flowEffect: pluginapi.AuthEventFlowStepUpCompleted,
	}
	mfaOutcomeFailLatchedVerified = canonicalMFAOutcome{
		result: pluginapi.AuthEventSuccess, reason: canonicalMFAReasonVerified, flowEffect: pluginapi.AuthEventFlowPrimaryFailureKept,
	}
	mfaOutcomeInvalidCode         = newMFAFailure(pluginapi.AuthEventInvalid, "invalid_code")
	mfaOutcomeAssertionRejected   = newMFAFailure(pluginapi.AuthEventInvalid, "assertion_rejected")
	mfaOutcomeCeremonyUnavailable = newMFAFailure(pluginapi.AuthEventInvalid, "ceremony_unavailable")
	mfaOutcomeAttemptLimit        = newMFAFailure(pluginapi.AuthEventRateLimited, "attempt_limit")
	mfaOutcomeAttemptStoreError   = newMFAFailure(pluginapi.AuthEventError, "attempt_store_error")
	mfaOutcomeVerifierError       = newMFAFailure(pluginapi.AuthEventError, "verifier_error")
	mfaOutcomeStateError          = newMFAFailure(pluginapi.AuthEventError, "state_error")
	mfaOutcomeStepUpConflict      = newMFAFailure(pluginapi.AuthEventRejected, "step_up_conflict")
	mfaOutcomeStepUpExpired       = newMFAFailure(pluginapi.AuthEventRejected, "step_up_expired")
	mfaOutcomeResumeConflict      = canonicalMFAOutcome{
		result: pluginapi.AuthEventRejected, reason: "resume_conflict", flowEffect: pluginapi.AuthEventFlowStepUpCompleted,
	}
)

// newMFAFailure builds an outcome that did not change the flow.
func newMFAFailure(result pluginapi.AuthEventResult, reason string) canonicalMFAOutcome {
	return canonicalMFAOutcome{result: result, reason: reason, flowEffect: pluginapi.AuthEventFlowNone}
}

// emitCanonicalMFAEvent hands one secret-free verification event to the host step-event sinks. It never blocks and
// never exposes the step-up, ceremony, session, or flow handles.
func (h *FrontendHandler) emitCanonicalMFAEvent(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	method string,
	outcome canonicalMFAOutcome,
) {
	emitter := h.authEventEmitter()
	if emitter == nil || ctx == nil || ctx.Request == nil {
		return
	}

	event := pluginapi.AuthEvent{
		ObservedAt: time.Now().UTC(), EventID: newCanonicalMFAEventID(), RequestID: ctx.GetString(definitions.CtxGUIDKey),
		FlowRef: flowdomain.DiagnosticFlowRef(string(selection.stepUp.Value.Flow)), Protocol: canonicalSelfServiceProtocol,
		Account: selection.identity.Account, ClientIP: ctx.ClientIP(), FactorRole: pluginapi.AuthEventFactorRoleSecond,
		Method: method, Reason: outcome.reason, Type: pluginapi.AuthEventMFAVerification, Result: outcome.result,
		FlowEffect: outcome.flowEffect, Version: pluginapi.AuthEventVersion, FailLatched: selection.failLatched,
	}

	if parent := selection.parent; parent != nil {
		event.Protocol = string(parent.Protocol)
		event.ClientID = parent.Metadata[flowdomain.FlowMetadataClientID]
		event.SAMLEntityID = parent.Metadata[flowdomain.FlowMetadataSAMLEntityID]
	}

	emitter.EmitAuthEvent(ctx.Request.Context(), event)
}

// authEventEmitter returns the configured step-event emitter, or nil when step events are disabled.
func (h *FrontendHandler) authEventEmitter() canonicalAuthEventEmitter {
	if h == nil {
		return nil
	}

	if h.canonicalAuthEventEmitter != nil {
		return h.canonicalAuthEventEmitter
	}

	if h.deps == nil || h.deps.PluginRunner == nil {
		return nil
	}

	return h.deps.PluginRunner
}

// newCanonicalMFAEventID returns a random 128-bit hex idempotency key, or empty when randomness is unavailable.
func newCanonicalMFAEventID() string {
	var buffer [16]byte

	if _, err := rand.Read(buffer[:]); err != nil {
		return ""
	}

	return hex.EncodeToString(buffer[:])
}

// admitCanonicalMFACode reserves the account budget before any local or remote verifier is dispatched.
func (h *FrontendHandler) admitCanonicalMFACode(ctx *gin.Context, selection canonicalMFASelectionState, method string) bool {
	if h == nil || h.deps == nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)
		return false
	}

	err := core.ConsumeMFAAttempt(ctx.Request.Context(), h.deps.Auth(), selection.identity.Reference)
	if err == nil {
		return true
	}

	if errors.Is(err, core.ErrMFAAttemptLimit) {
		h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeAttemptLimit)
		ctx.Header("Retry-After", "300")
		ctx.AbortWithStatus(http.StatusTooManyRequests)
	} else {
		h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeAttemptStoreError)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)
	}

	return false
}

// completeCanonicalFailLatchedMFA consumes a verified factor on a fail-latched flow without authenticating. It reports
// whether the request was answered; the primary failure stays authoritative.
func (h *FrontendHandler) completeCanonicalFailLatchedMFA(
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
		if errors.Is(err, sessionstate.ErrNotFound) {
			h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeStepUpConflict)
			ctx.AbortWithStatus(http.StatusConflict)

			return true
		}

		h.answerCanonicalStepUpError(ctx, selection, method, err)

		return true
	}

	h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeFailLatchedVerified)
	ctx.AbortWithStatus(http.StatusUnauthorized)

	return true
}

// completeCanonicalStepUp publishes the verified factor proof. It reports false after answering a failure.
func (h *FrontendHandler) completeCanonicalStepUp(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	method string,
) (cookie.StepUpCompletion, bool) {
	completion, err := selection.session.CompleteStepUp(
		ctx.Request.Context(),
		selection.stepUp.Value.Handle,
		method,
		mfaAssuranceFreshness,
	)
	if err != nil {
		h.answerCanonicalStepUpError(ctx, selection, method, err)

		return cookie.StepUpCompletion{}, false
	}

	return completion, true
}

// answerCanonicalStepUpError maps step-up state failures onto their unchanged HTTP answer and event outcome.
func (h *FrontendHandler) answerCanonicalStepUpError(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	method string,
	err error,
) {
	switch {
	case errors.Is(err, sessionstate.ErrExpired):
		h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeStepUpExpired)
		ctx.AbortWithStatus(http.StatusConflict)
	case errors.Is(err, sessionstate.ErrBindingMismatch) || errors.Is(err, sessionstate.ErrRevisionConflict):
		h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeStepUpConflict)
		ctx.AbortWithStatus(http.StatusConflict)
	default:
		h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeStateError)
		ctx.AbortWithStatus(http.StatusServiceUnavailable)
	}
}

// answerCanonicalResumeConflict answers a continuation conflict after the step-up was already completed.
func (h *FrontendHandler) answerCanonicalResumeConflict(
	ctx *gin.Context,
	selection canonicalMFASelectionState,
	method string,
) {
	h.emitCanonicalMFAEvent(ctx, selection, method, mfaOutcomeResumeConflict)
	ctx.AbortWithStatus(http.StatusConflict)
}

// canonicalWebAuthnFailureOutcome classifies a failed WebAuthn finish by the typed core failure.
func canonicalWebAuthnFailureOutcome(err error) canonicalMFAOutcome {
	switch {
	case errors.Is(err, core.ErrWebAuthnAssertionRejected):
		return mfaOutcomeAssertionRejected
	case errors.Is(err, core.ErrWebAuthnCeremonyUnavailable):
		return mfaOutcomeCeremonyUnavailable
	default:
		return mfaOutcomeVerifierError
	}
}
