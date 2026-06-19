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
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	"github.com/croessner/nauthilus/v3/server/policy/observability"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

type policyDiagnosticReport struct {
	Final         *report.FinalDecision             `json:"final,omitempty"`
	Observe       *report.ObserveReport             `json:"observe,omitempty"`
	Attributes    map[string]report.AttributeValue  `json:"attributes,omitempty"`
	Checks        map[string]report.CheckResult     `json:"checks,omitempty"`
	MissingChecks map[string]string                 `json:"missing_checks,omitempty"`
	Unavailable   map[string]report.UnavailableFact `json:"unavailable,omitempty"`
	Policies      []report.PolicyDecision           `json:"policies,omitempty"`
	SessionID     string                            `json:"session_id,omitempty"`
	Operation     policy.Operation                  `json:"operation,omitempty"`
	Stage         policy.Stage                      `json:"stage,omitempty"`
}

func (a *AuthState) emitPolicyReport(
	ctx *gin.Context,
	policyCtx *policycollection.DecisionContext,
	completedStage policy.Stage,
) {
	if a == nil || policyCtx == nil {
		return
	}

	snapshot := policyCtx.Snapshot()
	if snapshot == nil || !snapshot.Report.Enabled {
		return
	}

	mode, defaultPolicy, generation := policyCtx.SnapshotMetadata()
	observability.Debug(
		contextFromGin(ctx),
		a.Cfg(),
		a.Logger(),
		observability.ComponentReport,
		definitions.LogKeyGUID, a.Runtime.GUID,
		"operation", string(policyCtx.Report().Operation),
		"completed_stage", string(completedStage),
		"snapshot_generation", generation,
		"policy_mode", mode,
		"policy_set", defaultPolicy,
		"policy_report", newPolicyDiagnosticReport(policyCtx.Report(), snapshot.Report),
	)
}

func newPolicyDiagnosticReport(
	source *report.DecisionReport,
	settings policyruntime.ReportSettings,
) policyDiagnosticReport {
	redacted := source.Redacted()
	diagnostic := policyDiagnosticReport{
		SessionID: redacted.SessionID,
		Operation: redacted.Operation,
		Stage:     redacted.Stage,
		Policies:  redacted.Policies,
		Final:     redacted.Final,
		Observe:   redacted.Observe,
	}

	if settings.IncludeChecks {
		diagnostic.Checks = redacted.Checks
		diagnostic.MissingChecks = redacted.MissingChecks
		diagnostic.Unavailable = redacted.Unavailable
	}

	if settings.IncludeAttributes {
		diagnostic.Attributes = redacted.Attributes
	}

	if !settings.IncludeFSM {
		stripPolicyReportFSMFields(&diagnostic)
	}

	return diagnostic
}

func stripPolicyReportFSMFields(diagnostic *policyDiagnosticReport) {
	if diagnostic == nil {
		return
	}

	for index := range diagnostic.Policies {
		diagnostic.Policies[index].FSMEventMarker = ""
	}

	stripPolicyFinalFSMField(diagnostic.Final)
	if diagnostic.Observe == nil {
		return
	}

	stripPolicyFinalFSMField(diagnostic.Observe.Production)
	stripPolicyFinalFSMField(diagnostic.Observe.Shadow)
	diagnostic.Observe.ProductionTerminalState = ""
	diagnostic.Observe.ShadowTerminalState = ""
}

func stripPolicyFinalFSMField(final *report.FinalDecision) {
	if final == nil {
		return
	}

	final.FSMEventMarker = ""
}
