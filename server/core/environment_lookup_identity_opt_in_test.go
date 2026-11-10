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

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"

	"github.com/gin-gonic/gin"
)

// countingRBLService records how often the RBL control actually queried block lists.
type countingRBLService struct {
	calls int
}

// Score counts one block-list evaluation and never lists the client.
func (s *countingRBLService) Score(*gin.Context, *StateView) (int, error) {
	s.calls++

	return 0, nil
}

// Threshold returns a fixed threshold the zero score never reaches.
func (s *countingRBLService) Threshold() int {
	return 5
}

// TestLookupIdentityRBLRunsOnlyWhenPolicyScheduled verifies the no-auth RBL opt-in:
// the unscheduled environment path keeps skipping RBL, a policy-scheduled provider runs it.
func TestLookupIdentityRBLRunsOnlyWhenPolicyScheduled(t *testing.T) {
	tests := []struct {
		name      string
		scheduled bool
		wantCalls int
	}{
		{name: "unscheduled environment path skips RBL", scheduled: false, wantCalls: 0},
		{name: "policy-scheduled provider runs RBL", scheduled: true, wantCalls: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t, definitions.ControlRBL)
			cfg.RBLs = &config.RBLSection{Threshold: 5}
			service := &countingRBLService{}
			previous := GetRBLService()

			RegisterRBLService(service)
			t.Cleanup(func() {
				RegisterRBLService(previous)
			})

			auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
			auth.Request.NoAuth = true

			auth.handleEnvironmentProviders(ctx, authnEnvironmentProviderPlan{rbl: true, policyScheduled: test.scheduled})

			if service.calls != test.wantCalls {
				t.Fatalf("RBL lookups = %d, want %d", service.calls, test.wantCalls)
			}
		})
	}
}

// TestLookupIdentitySchedulerRunsOptedInRBL verifies that a scheduler-dispatched RBL provider
// counts as policy-scheduled, so an explicit lookup_identity domain-plan binding reaches the block lists.
func TestLookupIdentitySchedulerRunsOptedInRBL(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlRBL)
	cfg.RBLs = &config.RBLSection{Threshold: 5}
	service := &countingRBLService{}
	previous := GetRBLService()

	RegisterRBLService(service)
	t.Cleanup(func() {
		RegisterRBLService(previous)
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.NoAuth = true

	execution := &authnCandidateExecution{auth: auth, ginCtx: ctx, operation: policy.OperationLookupIdentity}
	if _, _, err := execution.prepareProviderInstance(nil, policy.AuthnProviderRBL); err != nil {
		t.Fatalf("prepareProviderInstance() error = %v", err)
	}

	if service.calls != 1 {
		t.Fatalf("RBL lookups = %d, want 1", service.calls)
	}
}

// TestLookupIdentityTLSRunsOnlyWhenPolicyScheduled verifies the same opt-in for TLS enforcement.
func TestLookupIdentityTLSRunsOnlyWhenPolicyScheduled(t *testing.T) {
	tests := []struct {
		name      string
		scheduled bool
		want      definitions.AuthResult
	}{
		{name: "unscheduled environment path skips TLS", scheduled: false, want: definitions.AuthResultOK},
		{name: "policy-scheduled provider enforces TLS", scheduled: true, want: definitions.AuthResultPreAuthTLS},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
			cfg.ClearTextList = nil

			auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
			auth.Request.NoAuth = true

			got := auth.handleEnvironmentProviders(ctx, authnEnvironmentProviderPlan{tls: true, policyScheduled: test.scheduled})
			if got != test.want {
				t.Fatalf("handleEnvironmentProviders() = %v, want %v", got, test.want)
			}
		})
	}
}
