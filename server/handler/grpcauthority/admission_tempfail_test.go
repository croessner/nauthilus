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

package grpcauthority

import (
	"errors"
	"testing"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
)

// newCapacityRejectedGRPCHandler builds one authority handler whose Policy session admission is exhausted.
func newCapacityRejectedGRPCHandler(
	t *testing.T,
	category error,
) (*Handler, *recordingGRPCBoundaryCurrentService, *recordingGRPCBoundaryDecisionSessionFactory) {
	t.Helper()

	current := newRecordingGRPCBoundaryCurrentService()
	factory := &recordingGRPCBoundaryDecisionSessionFactory{
		openErr: errors.Join(decisionservice.ErrDecisionAdmission, category),
	}

	service, err := core.NewAuthnCandidateApplicationServiceWithInternalProfiles(
		current, factory, mustGRPCBoundaryProfiles(t),
	)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationServiceWithInternalProfiles() error = %v", err)
	}

	return New(service), current, factory
}

func TestGRPCBackchannelCapacityAdmissionRejectionAnswersTempFail(t *testing.T) {
	for name, category := range map[string]error{
		"concurrency": admission.ErrConcurrencyLimitExceeded,
		"rate":        admission.ErrRateLimitExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			handler, current, factory := newCapacityRejectedGRPCHandler(t, category)

			ctx, gate := grpcBoundaryRequestContext()
			defer gate.Complete()

			authResponse, err := handler.Authenticate(ctx, grpcBoundaryAuthRequest())
			assertGRPCTempFailResponse(t, "Authenticate", authResponse, err)

			lookupResponse, err := handler.LookupIdentity(ctx, grpcBoundaryLookupIdentityRequest())
			assertGRPCTempFailResponse(t, "LookupIdentity", lookupResponse, err)

			listResponse, err := handler.ListAccounts(ctx, grpcBoundaryListAccountsRequest())
			assertGRPCListAccountsTempFail(t, listResponse, err)

			if factory.calls != 3 || factory.callbackCalls != 0 || current.totalHostCalls() != 0 {
				t.Fatalf(
					"session calls/callbacks/host calls = %d/%d/%d, want 3/0/0",
					factory.calls, factory.callbackCalls, current.totalHostCalls(),
				)
			}
		})
	}
}

// assertGRPCTempFailResponse verifies the regular temporary-failure response mapping.
func assertGRPCTempFailResponse(t *testing.T, method string, response *authv1.AuthResponse, err error) {
	t.Helper()

	if err != nil || response == nil {
		t.Fatalf("%s() = %v / %v, want tempfail response", method, response, err)
	}

	if response.GetDecision() != authv1.AuthDecision_AUTH_DECISION_TEMPFAIL || response.GetOk() ||
		response.GetStatusMessage() != definitions.TempFailDefault || response.GetSession() == "" {
		t.Fatalf("%s() response = %v, want regular tempfail mapping", method, response)
	}
}

// assertGRPCListAccountsTempFail verifies the regular empty temporary-failure listing.
func assertGRPCListAccountsTempFail(t *testing.T, response *authv1.ListAccountsResponse, err error) {
	t.Helper()

	if err != nil || response == nil || len(response.GetAccounts()) != 0 || response.GetSession() == "" {
		t.Fatalf("ListAccounts() = %v / %v, want empty tempfail listing with session", response, err)
	}
}
