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

package pluginapi

import (
	"context"
	"time"
)

// AuthEventType names one host-observed authentication step event.
type AuthEventType string

// AuthEventMFAVerification is one observed second-factor verification attempt.
const AuthEventMFAVerification AuthEventType = "mfa.verification"

// AuthEventOIDCCodeIssuance is one authorization code the IdP handed to the browser for its client's redirect URI.
const AuthEventOIDCCodeIssuance AuthEventType = "oidc.code_issuance"

// AuthEventOIDCCodeRedemption is one consumed authorization code at the token endpoint, successful or not.
const AuthEventOIDCCodeRedemption AuthEventType = "oidc.code_redemption"

// AuthEventVersion is the current AuthEvent contract version of mfa.verification events.
const AuthEventVersion uint16 = 1

// AuthEventOIDCCodeVersion is the current contract version of both OIDC authorization-code event types. Version 1
// defines that an issued code cannot be redeemed later than ten minutes after the issuance event was observed; a
// change of that lifetime requires a new version.
const AuthEventOIDCCodeVersion uint16 = 1

// Completion reports whether the event type belongs to the OIDC authorization-code completion evidence.
func (t AuthEventType) Completion() bool {
	return t == AuthEventOIDCCodeIssuance || t == AuthEventOIDCCodeRedemption
}

// AuthEventResult is the observed result of one step event.
type AuthEventResult string

const (
	// AuthEventSuccess marks a verified factor.
	AuthEventSuccess AuthEventResult = "success"
	// AuthEventInvalid marks a factor the user submitted that did not verify.
	AuthEventInvalid AuthEventResult = "invalid"
	// AuthEventError marks a technical failure that prevented verification.
	AuthEventError AuthEventResult = "error"
	// AuthEventRateLimited marks an attempt rejected by the attempt budget.
	AuthEventRateLimited AuthEventResult = "rate_limited"
	// AuthEventRejected marks a verified factor whose flow state could not be completed.
	AuthEventRejected AuthEventResult = "rejected"
)

// AuthEventFlowEffect describes what the event changed in the browser flow.
type AuthEventFlowEffect string

const (
	// AuthEventFlowNone marks an event without flow change.
	AuthEventFlowNone AuthEventFlowEffect = "none"
	// AuthEventFlowStepUpCompleted marks a completed step-up.
	AuthEventFlowStepUpCompleted AuthEventFlowEffect = "step_up_completed"
	// AuthEventFlowPrimaryFailureKept marks a verified factor on a flow whose primary step already failed.
	AuthEventFlowPrimaryFailureKept AuthEventFlowEffect = "primary_failure_kept"
	// AuthEventFlowCodeIssued marks an authorization code handed to the browser for the client redirect URI.
	AuthEventFlowCodeIssued AuthEventFlowEffect = "code_issued"
	// AuthEventFlowTokensIssued marks a redeemed code whose token response was handed to the transport.
	AuthEventFlowTokensIssued AuthEventFlowEffect = "tokens_issued"
	// AuthEventFlowCodeConsumed marks a code consumed by a rejected or failed redemption; the flow cannot complete.
	AuthEventFlowCodeConsumed AuthEventFlowEffect = "code_consumed"
)

// AuthEventFactorRoleSecond marks a second factor after a primary authentication step.
const AuthEventFactorRoleSecond = "second_factor"

// AuthEvent is one bounded, secret-free step event observed by the host. It never contains passwords, hashes, OTP
// values, recovery codes, authorization codes, PKCE verifiers, tokens, cookies, authorizing handles, or WebAuthn
// payloads.
type AuthEvent struct {
	ObservedAt   time.Time
	EventID      string
	RequestID    string
	FlowRef      string
	Protocol     string
	ClientID     string
	SAMLEntityID string
	Account      string
	ClientIP     string
	FactorRole   string
	Method       string
	Reason       string
	Type         AuthEventType
	Result       AuthEventResult
	FlowEffect   AuthEventFlowEffect
	Version      uint16
	FailLatched  bool
}

// AuthEventSink receives host-observed step events. ObserveAuthEvent must only enqueue and return quickly; the host
// delivers events from a bounded queue and never lets a sink delay an authentication request.
type AuthEventSink interface {
	Name() string
	ObserveAuthEvent(context.Context, AuthEvent) error
}

// AuthEventRegistrar is an optional additive registrar for step-event sinks.
type AuthEventRegistrar interface {
	RegisterAuthEventSink(AuthEventSink) error
}
