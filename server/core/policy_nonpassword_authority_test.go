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
	"context"
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/policy"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestAuthBoundaryConfiguredLookupDecisionOverridesFoundIdentity(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, customLookupDenySnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.NoAuth = true

	passDBResult := GetPassDBResultFromPool()
	passDBResult.UserFound = true
	passDBResult.Authenticated = true
	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	got, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultOK)
	if !ok {
		t.Fatal("configured lookup decision was not evaluated")
	}

	if got != definitions.AuthResultFail {
		t.Fatalf("auth result = %v, want %v", got, definitions.AuthResultFail)
	}

	if got := auth.Runtime.StatusMessage; got != "Custom lookup deny" {
		t.Fatalf("status message = %q, want configured lookup message", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Operation != policy.OperationLookupIdentity {
		t.Fatalf("operation = %q, want %q", policyCtx.Report().Operation, policy.OperationLookupIdentity)
	}

	if policyCtx.Report().Final == nil || policyCtx.Report().Final.PolicyName != "custom_deny_lookup_identity" {
		t.Fatalf("final = %#v, want custom lookup denial", policyCtx.Report().Final)
	}
}

func TestAuthBoundaryConfiguredIDPLookupUsesLookupOperationAndSurface(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, customLookupDenySnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.NoAuth = true
	auth.Request.Service = definitions.ServIdP

	passDBResult := GetPassDBResultFromPool()
	passDBResult.UserFound = true
	passDBResult.Authenticated = true
	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	if _, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultOK); !ok {
		t.Fatal("configured IDP lookup decision was not evaluated")
	}

	if got := auth.policyResponseSurface(); got != "idp_browser" {
		t.Fatalf("response surface = %q, want idp_browser", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Operation != policy.OperationLookupIdentity {
		t.Fatalf("operation = %q, want %q", policyCtx.Report().Operation, policy.OperationLookupIdentity)
	}
}

func TestAuthBoundaryConfiguredListAccountsDecisionOverridesProviderSuccess(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{mustPolicyBackendForTest(t, definitions.BackendTest)}
	activatePolicySnapshotForTest(t, customListAccountsDenySnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ListAccounts = true
	auth.Request.Service = definitions.ServJSON
	auth.SetStatusCodes(auth.Request.Service)
	ctx.Request.Header.Set("Accept", "application/json")

	auth.writeListAccountsResponse(ctx)

	if got := ctx.Writer.Status(); got != http.StatusForbidden {
		t.Fatalf("HTTP status = %d, want configured list-accounts denial", got)
	}

	if got := auth.Runtime.StatusMessage; got != "Custom account listing deny" {
		t.Fatalf("status message = %q, want configured list-accounts message", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Operation != policy.OperationListAccounts {
		t.Fatalf("operation = %q, want %q", policyCtx.Report().Operation, policy.OperationListAccounts)
	}

	if _, exists := policyCtx.Report().Attributes[policy.AttributeAccountProviderCompleted]; !exists {
		t.Fatal("missing account-provider completion attribute")
	}

	if policyCtx.Report().Attributes[policy.AttributeAccountProviderCompleted].Details["count"].Value == nil {
		t.Fatal("missing account-provider count detail")
	}

	if _, exists := policyCtx.Report().Attributes["accounts"]; exists {
		t.Fatal("account list must not be exposed as a policy attribute")
	}

	if policyCtx.Report().Final == nil || policyCtx.Report().Final.PolicyName != "custom_deny_account_listing" {
		t.Fatalf("final = %#v, want custom account-listing denial", policyCtx.Report().Final)
	}
}

func TestAuthApplicationServiceListAccountsReturnsConfiguredDenialOutcome(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{mustPolicyBackendForTest(t, definitions.BackendTest)}
	activatePolicySnapshotForTest(t, customListAccountsDenySnapshotForTest())

	service, _ := newCurrentBehaviorApplicationService(t, cfg)
	outcome, err := service.ListAccounts(context.Background(), NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeListAccounts, authdto.Request{
		ClientIP: "203.0.113.45",
	}))
	if err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}

	if outcome.Decision != AuthDecisionFail {
		t.Fatalf("decision = %q, want %q", outcome.Decision, AuthDecisionFail)
	}

	if len(outcome.Accounts) != 0 {
		t.Fatalf("accounts = %#v, want empty response data on denial", outcome.Accounts)
	}

	if outcome.StatusMessage != "Custom account listing deny" {
		t.Fatalf("status message = %q, want configured list-accounts message", outcome.StatusMessage)
	}
}

func mustPolicyBackendForTest(t *testing.T, backendName definitions.Backend) *config.Backend {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(backendName.String()); err != nil {
		t.Fatalf("backend.Set(%q) failed: %v", backendName.String(), err)
	}

	return backend
}

func customLookupDenySnapshotForTest() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    121,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationLookupIdentity: {
				policy.StageAuthDecision: {
					Stage: policy.StageAuthDecision,
					Policies: []policyruntime.CompiledPolicy{
						{
							Name:          "custom_deny_lookup_identity",
							Stage:         policy.StageAuthDecision,
							Operations:    []policy.Operation{policy.OperationLookupIdentity},
							RequireChecks: []string{"ldap_backend"},
							Root: policyruntime.CompiledExpr{
								Kind:        policyruntime.ExprKindAttribute,
								AttributeID: policy.AttributeIdentityFound,
								Operator:    "is",
								Expected:    policyruntime.TypedValue{Value: true},
							},
							Then: policyruntime.DecisionPlan{
								Decision:       policy.DecisionDeny,
								OutcomeMarker:  "auth.outcome.custom_lookup_deny",
								FSMEventMarker: policy.FSMEventMarkerAuthDeny,
								ResponseMarker: policy.ResponseMarkerFail,
								ResponseMessage: policyruntime.ResponseMessagePlan{
									Source:  "literal",
									Literal: "Custom lookup deny",
								},
							},
						},
					},
				},
			},
		},
	}
}

func customListAccountsDenySnapshotForTest() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    122,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationListAccounts: {
				policy.StageAccountProvider: {
					Stage: policy.StageAccountProvider,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "account_provider",
							Type:       policy.CheckTypeAccountProvider,
							Stage:      policy.StageAccountProvider,
							Operations: []policy.Operation{policy.OperationListAccounts},
							ConfigRef:  "auth.backends",
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
					},
				},
				policy.StageAuthDecision: {
					Stage: policy.StageAuthDecision,
					Policies: []policyruntime.CompiledPolicy{
						{
							Name:          "custom_deny_account_listing",
							Stage:         policy.StageAuthDecision,
							Operations:    []policy.Operation{policy.OperationListAccounts},
							RequireChecks: []string{"account_provider"},
							Root: policyruntime.CompiledExpr{
								Kind:        policyruntime.ExprKindAttribute,
								AttributeID: policy.AttributeAccountProviderCompleted,
								Operator:    "is",
								Expected:    policyruntime.TypedValue{Value: true},
							},
							Then: policyruntime.DecisionPlan{
								Decision:       policy.DecisionDeny,
								OutcomeMarker:  "auth.outcome.custom_account_listing_deny",
								FSMEventMarker: policy.FSMEventMarkerAuthDeny,
								ResponseMarker: policy.ResponseMarkerFail,
								ResponseMessage: policyruntime.ResponseMessagePlan{
									Source:  "literal",
									Literal: "Custom account listing deny",
								},
							},
						},
					},
				},
			},
		},
	}
}
