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
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
)

func TestResetFlowAuthOutcomeForRetryClearsFailLatchedCookieFlow(t *testing.T) {
	const flowID = "flow-retry"

	mgr := &mockCookieManager{data: map[string]any{}}
	controller := newFlowController(mgr, nil, "")

	_, err := controller.Start(t.Context(), &flowdomain.State{
		FlowID:      flowID,
		Type:        flowdomain.FlowTypeOIDCAuthorization,
		Protocol:    flowdomain.FlowProtocolOIDC,
		CurrentStep: flowdomain.FlowStepStart,
		GrantType:   definitions.OIDCFlowAuthorizationCode,
	}, time.Now())
	if err != nil {
		t.Fatalf("start flow: %v", err)
	}

	advanceFlow(t.Context(), mgr, nil, "", flowdomain.FlowStepLogin)
	advanceFlow(t.Context(), mgr, nil, "", flowdomain.FlowStepMFA)

	if !setFlowAuthOutcome(t.Context(), mgr, nil, "", flowdomain.AuthOutcomeFailLatched) {
		t.Fatal("failed to latch auth outcome")
	}

	if !flowAuthFailureLatched(t.Context(), mgr, nil, "") {
		t.Fatal("expected fail-latched flow before retry reset")
	}

	if !resetFlowAuthOutcomeForRetry(t.Context(), mgr, nil, "") {
		t.Fatal("retry reset failed")
	}

	outcome, ok := getFlowAuthOutcome(t.Context(), mgr, nil, "")
	if !ok {
		t.Fatal("missing flow auth outcome after retry reset")
	}

	if outcome != flowdomain.AuthOutcomeUnknown {
		t.Fatalf("auth outcome = %q, want %q", outcome, flowdomain.AuthOutcomeUnknown)
	}
}

func TestResetFlowAuthOutcomeForLoginAttemptAllowsCorrectRetryAfterFailLatched(t *testing.T) {
	const flowID = "flow-correct-retry"

	mgr := &mockCookieManager{data: map[string]any{}}
	controller := newFlowController(mgr, nil, "")

	_, err := controller.Start(t.Context(), &flowdomain.State{
		FlowID:      flowID,
		Type:        flowdomain.FlowTypeOIDCAuthorization,
		Protocol:    flowdomain.FlowProtocolOIDC,
		CurrentStep: flowdomain.FlowStepStart,
		GrantType:   definitions.OIDCFlowAuthorizationCode,
	}, time.Now())
	if err != nil {
		t.Fatalf("start flow: %v", err)
	}

	advanceFlow(t.Context(), mgr, nil, "", flowdomain.FlowStepLogin)
	advanceFlow(t.Context(), mgr, nil, "", flowdomain.FlowStepMFA)

	if !setFlowAuthOutcome(t.Context(), mgr, nil, "", flowdomain.AuthOutcomeFailLatched) {
		t.Fatal("failed to latch auth outcome")
	}

	if !resetFlowAuthOutcomeForLoginAttempt(t.Context(), mgr, nil, "") {
		t.Fatal("failed to reset auth outcome for retry login attempt")
	}

	if !setFlowAuthOutcome(t.Context(), mgr, nil, "", flowdomain.AuthOutcomeOK) {
		t.Fatal("failed to store successful retry outcome")
	}

	outcome, ok := getFlowAuthOutcome(t.Context(), mgr, nil, "")
	if !ok {
		t.Fatal("missing flow auth outcome after successful retry")
	}

	if outcome != flowdomain.AuthOutcomeOK {
		t.Fatalf("auth outcome = %q, want %q", outcome, flowdomain.AuthOutcomeOK)
	}
}
