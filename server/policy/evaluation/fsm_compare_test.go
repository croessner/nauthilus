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

package evaluation

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/report"
)

func TestCompareWithProductionAddsFSMComparisonForOperations(t *testing.T) {
	for _, testCase := range fsmComparisonCases() {
		t.Run(testCase.name, func(t *testing.T) {
			policyReport := testCase.buildReport()
			got := CompareWithProduction(context.Background(), policyReport, CompareInput{
				Production: ProductionOutcome{
					Effect:                  policy.DecisionPermit,
					ResponseMarker:          testCase.response,
					CurrentFSMTerminalState: testCase.terminal,
					CurrentFSMEventPath:     testCase.eventPath,
				},
				ProductionSet: true,
			})

			if got.Mismatch {
				t.Fatalf("policy mismatch = true, want false")
			}

			if policyReport.FSM == nil {
				t.Fatal("FSM report is nil")
			}

			if policyReport.FSM.PolicyName != testCase.policyName {
				t.Fatalf("policy name = %q, want %q", policyReport.FSM.PolicyName, testCase.policyName)
			}

			if policyReport.FSM.Operation != testCase.operation {
				t.Fatalf("operation = %q, want %q", policyReport.FSM.Operation, testCase.operation)
			}

			if policyReport.FSM.CurrentTerminalState != testCase.terminal {
				t.Fatalf("current terminal = %q, want %q", policyReport.FSM.CurrentTerminalState, testCase.terminal)
			}

			if policyReport.FSM.TargetTerminalState != testCase.terminal {
				t.Fatalf("target terminal = %q, want %q", policyReport.FSM.TargetTerminalState, testCase.terminal)
			}

			if policyReport.FSM.Mismatch {
				t.Fatal("FSM mismatch = true, want false")
			}
		})
	}
}

func TestCompareWithProductionReportsFSMMismatchSeparately(t *testing.T) {
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, true, nil),
	)

	got := CompareWithProduction(context.Background(), policyReport, CompareInput{
		Production: ProductionOutcome{
			Effect:                  policy.DecisionPermit,
			ResponseMarker:          "auth.response.ok",
			CurrentFSMTerminalState: "auth_fail",
			CurrentFSMEventPath: []string{
				policy.FSMEventMarkerParseOK,
				policy.FSMEventMarkerPreAuthOK,
				policy.FSMEventMarkerAuthEvaluated,
				policy.FSMEventMarkerAuthDeny,
			},
		},
		ProductionSet: true,
	})

	if got.Mismatch {
		t.Fatal("policy mismatch = true, want false")
	}

	if policyReport.FSM == nil || !policyReport.FSM.Mismatch {
		t.Fatalf("FSM report = %#v, want mismatch", policyReport.FSM)
	}
}

type fsmComparisonCase struct {
	buildReport func() *report.DecisionReport
	name        string
	operation   policy.Operation
	policyName  string
	response    string
	terminal    string
	eventPath   []string
}

func fsmComparisonCases() []fsmComparisonCase {
	return []fsmComparisonCase{
		authenticateFSMComparisonCase(),
		lookupIdentityFSMComparisonCase(),
		listAccountsFSMComparisonCase(),
	}
}

func authenticateFSMComparisonCase() fsmComparisonCase {
	return fsmComparisonCase{
		name:        "authenticate",
		operation:   policy.OperationAuthenticate,
		policyName:  "standard_auth_success",
		response:    "auth.response.ok",
		terminal:    "auth_ok",
		eventPath:   authEventPath(policy.FSMEventMarkerAuthPermit),
		buildReport: authenticateFSMReport,
	}
}

func lookupIdentityFSMComparisonCase() fsmComparisonCase {
	return fsmComparisonCase{
		name:        "lookup identity",
		operation:   policy.OperationLookupIdentity,
		policyName:  "standard_lookup_identity_success",
		response:    "auth.response.ok",
		terminal:    "auth_ok",
		eventPath:   authEventPath(policy.FSMEventMarkerAuthPermit),
		buildReport: lookupIdentityFSMReport,
	}
}

func listAccountsFSMComparisonCase() fsmComparisonCase {
	return fsmComparisonCase{
		name:        "list accounts",
		operation:   policy.OperationListAccounts,
		policyName:  "standard_list_accounts_success",
		response:    "auth.response.list_accounts.ok",
		terminal:    "auth_ok",
		eventPath:   accountProviderEventPath(policy.FSMEventMarkerAuthPermit),
		buildReport: listAccountsFSMReport,
	}
}

func authEventPath(final string) []string {
	return []string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerAuthEvaluated,
		final,
	}
}

func accountProviderEventPath(final string) []string {
	return []string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerAccountProviderEvaluated,
		final,
	}
}

func authenticateFSMReport() *report.DecisionReport {
	return standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, true, nil),
	)
}

func lookupIdentityFSMReport() *report.DecisionReport {
	return standardReport(
		policy.OperationLookupIdentity,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeIdentityFound, policy.StageAuthBackend, policy.OperationLookupIdentity, true, nil),
	)
}

func listAccountsFSMReport() *report.DecisionReport {
	return standardReport(
		policy.OperationListAccounts,
		check("account_provider", policy.CheckTypeAccountProvider, policy.StageAccountProvider, policy.CheckStatusOK),
		boolAttr(policy.AttributeAccountProviderCompleted, policy.StageAccountProvider, policy.OperationListAccounts, true, nil),
		boolAttr(policy.AttributeAccountProviderTempFail, policy.StageAccountProvider, policy.OperationListAccounts, false, nil),
	)
}
