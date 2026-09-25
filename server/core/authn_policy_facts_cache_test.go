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
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	policycollection "github.com/croessner/nauthilus/v4/server/policy/collection"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/gin-gonic/gin"
)

// newStandardAuthFactsExecution builds a request-local execution with an empty policy collection context.
func newStandardAuthFactsExecution(t *testing.T) (*authnCandidateExecution, *policycollection.DecisionContext, decision.Target) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/", nil)

	policyCtx := policycollection.NewDecisionContext(policy.OperationAuthenticate, nil, 0)
	ctx.Set(policyCollectionContextKey, policyCtx)

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return &authnCandidateExecution{auth: &AuthState{}, ginCtx: ctx, operation: policy.OperationAuthenticate}, policyCtx, target
}

// factBool returns the boolean value of one fact or fails.
func factBool(t *testing.T, facts decision.FactSet, id string) bool {
	t.Helper()

	fact, ok := facts.Get(id)
	if !ok {
		t.Fatalf("fact %s missing from %d facts", id, facts.Len())
	}

	value, ok := fact.Value().Boolean()
	if !ok {
		t.Fatalf("fact %s is not boolean", id)
	}

	return value
}

func TestStandardAuthFactsReprojectsOnlyChangedAttributes(t *testing.T) {
	execution, policyCtx, target := newStandardAuthFactsExecution(t)

	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth, Value: true,
	})

	first, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	if err != nil {
		t.Fatalf("StandardAuthFacts() error = %v", err)
	}

	if !factBool(t, first, policy.AuthnFactBruteForceTriggered) {
		t.Fatal("first projection lost the recorded value")
	}

	cold := testing.AllocsPerRun(20, func() {
		fresh := &authnCandidateExecution{auth: execution.auth, ginCtx: execution.ginCtx, operation: execution.operation}
		_, _ = fresh.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	})
	warm := testing.AllocsPerRun(20, func() {
		_, _ = execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	})

	if warm >= cold {
		t.Fatalf("cached projection allocations = %.0f, uncached = %.0f; the cache must avoid the reprojection", warm, cold)
	}

	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth, Value: false,
	})

	updated, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	if err != nil {
		t.Fatalf("StandardAuthFacts() error = %v", err)
	}

	if factBool(t, updated, policy.AuthnFactBruteForceTriggered) {
		t.Fatal("a re-recorded attribute kept its stale cached projection")
	}
}

func TestStandardAuthFactsProjectsAttributesThatApplyAtALaterCheckpoint(t *testing.T) {
	execution, policyCtx, target := newStandardAuthFactsExecution(t)

	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeTLSSecure, Stage: policy.StageAuthDecision, Value: true,
	})

	preAuth, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	if err != nil {
		t.Fatalf("StandardAuthFacts(pre_auth) error = %v", err)
	}

	if _, ok := preAuth.Get(policy.AuthnFactTLSSecure); ok {
		t.Fatal("an auth_decision attribute was projected at pre_auth")
	}

	final, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StageAuthDecision))
	if err != nil {
		t.Fatalf("StandardAuthFacts(auth_decision) error = %v", err)
	}

	if !factBool(t, final, policy.AuthnFactTLSSecure) {
		t.Fatal("the attribute cached as not applying at pre_auth was not projected at auth_decision")
	}
}

func TestStandardAuthFactsReusesTheSetWhileNothingChanges(t *testing.T) {
	execution, policyCtx, target := newStandardAuthFactsExecution(t)

	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth, Value: true,
	})

	first, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	if err != nil {
		t.Fatalf("StandardAuthFacts() error = %v", err)
	}

	allocs := testing.AllocsPerRun(20, func() {
		_, _ = execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	})
	if allocs != 0 {
		t.Fatalf("unchanged StandardAuthFacts() allocations = %.0f, want 0", allocs)
	}

	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeTLSSecure, Stage: policy.StagePreAuth, Value: true,
	})

	second, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	if err != nil {
		t.Fatalf("StandardAuthFacts() error = %v", err)
	}

	if second.Len() <= first.Len() {
		t.Fatalf("StandardAuthFacts() after a new attribute = %d facts, want more than %d", second.Len(), first.Len())
	}
}

func TestStandardAuthFactsDropsCachesWhenTheDecisionContextIsReplaced(t *testing.T) {
	execution, policyCtx, target := newStandardAuthFactsExecution(t)

	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth, Value: true,
	})

	if _, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth)); err != nil {
		t.Fatalf("StandardAuthFacts() error = %v", err)
	}

	// A replacement context restarts its revisions and reaches the same revision with a different value.
	replacement := policycollection.NewDecisionContext(policy.OperationAuthenticate, nil, 0)
	replacement.RecordAttribute(policycollection.AttributeValue{
		ID: policy.AttributeBruteForceTriggered, Stage: policy.StagePreAuth, Value: false,
	})
	execution.ginCtx.Set(policyCollectionContextKey, replacement)

	if replacement.Revision() != policyCtx.Revision() {
		t.Fatalf("fixture revisions differ: %d and %d", replacement.Revision(), policyCtx.Revision())
	}

	facts, err := execution.StandardAuthFacts(t.Context(), target, string(policy.StagePreAuth))
	if err != nil {
		t.Fatalf("StandardAuthFacts() error = %v", err)
	}

	if factBool(t, facts, policy.AuthnFactBruteForceTriggered) {
		t.Fatal("facts of the replaced decision context were reused")
	}
}
