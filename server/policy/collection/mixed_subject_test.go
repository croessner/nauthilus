// Copyright (C) 2026 Christian Roessner
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

package collection

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestSubjectScriptPhasesDefersLuaDependencyAcrossNativeBoundary(t *testing.T) {
	ctx := NewDecisionContext(mixedSubjectSnapshot(true), policy.OperationAuthenticate, nil)

	phases := ctx.SubjectScriptPhases(AuthStateAuthenticated)
	if !phases.Mixed {
		t.Fatal("SubjectScriptPhases().Mixed = false, want true")
	}

	assertScriptScheduleNames(t, phases.Before, []string{"geoip_history", "geoip_reputation"})
	assertScriptScheduleNames(t, phases.After, []string{"director_routing"})
}

func TestSubjectScriptPhasesKeepsLegacyLuaPlanWithoutCrossSourceDependency(t *testing.T) {
	ctx := NewDecisionContext(mixedSubjectSnapshot(false), policy.OperationAuthenticate, nil)

	phases := ctx.SubjectScriptPhases(AuthStateAuthenticated)
	if phases.Mixed {
		t.Fatal("SubjectScriptPhases().Mixed = true, want false")
	}

	assertScriptScheduleNames(t, phases.Before, []string{"geoip_history", "geoip_reputation", "director_routing"})
	assertScriptScheduleNames(t, phases.After, nil)
}

// assertScriptScheduleNames verifies one stable phase schedule.
func assertScriptScheduleNames(t *testing.T, plan ScriptSchedulePlan, want []string) {
	t.Helper()

	got := make([]string, 0, len(plan.Schedules))
	for _, schedule := range plan.Schedules {
		got = append(got, schedule.Name)
	}

	if len(got) != len(want) {
		t.Fatalf("schedule names = %#v, want %#v", got, want)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("schedule names = %#v, want %#v", got, want)
		}
	}
}

// mixedSubjectSnapshot returns the target subject check topology with an optional cross-source dependency.
func mixedSubjectSnapshot(crossSource bool) *policyruntime.Snapshot {
	directorAfter := []string{"lua_subject_geoip_reputation"}
	if crossSource {
		directorAfter = []string{"plugin_subject_rns_auth_rns_ldap"}
	}

	checks := []policyruntime.CompiledCheck{
		mixedSubjectCheck("lua_subject_geoip_history", policy.CheckTypeLuaSubjectSource, "auth.policy.attribute_sources.lua.subject.geoip_history", nil),
		mixedSubjectCheck("lua_subject_geoip_reputation", policy.CheckTypeLuaSubjectSource, "auth.policy.attribute_sources.lua.subject.geoip_reputation", []string{"lua_subject_geoip_history"}),
		mixedSubjectCheck("plugin_subject_rns_auth_rns_ldap", policy.CheckTypePluginSubjectSource, "plugins.modules.rns_auth.subject", nil),
		mixedSubjectCheck("lua_subject_director_routing", policy.CheckTypeLuaSubjectSource, "auth.policy.attribute_sources.lua.subject.director_routing", directorAfter),
	}

	return &policyruntime.Snapshot{
		Generation:    46,
		Mode:          modeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StageSubjectAnalysis: {
					Stage:  policy.StageSubjectAnalysis,
					Checks: checks,
				},
			},
		},
	}
}

// mixedSubjectCheck builds one authenticated subject-analysis check.
func mixedSubjectCheck(name string, checkType string, configRef string, after []string) policyruntime.CompiledCheck {
	return policyruntime.CompiledCheck{
		Name:       name,
		Type:       checkType,
		Stage:      policy.StageSubjectAnalysis,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAuthenticated},
		After:      append([]string(nil), after...),
		ConfigRef:  configRef,
	}
}
