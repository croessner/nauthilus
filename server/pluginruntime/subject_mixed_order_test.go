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

package pluginruntime

import (
	"context"
	"sync"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

func TestAuthStateSubjectLuaMixedSourceOrder(t *testing.T) {
	tests := []struct {
		name        string
		want        []string
		crossSource bool
	}{
		{
			name:        "lua after native dependency",
			crossSource: true,
			want:        []string{"geoip_history", "geoip_reputation", "native_rns_ldap", "director_routing"},
		},
		{
			name:        "legacy order without cross source dependency",
			crossSource: false,
			want:        []string{"geoip_history", "geoip_reputation", "director_routing", "native_rns_ldap"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runSubjectOrderTest(t, test.crossSource, test.want)
		})
	}
}

// runSubjectOrderTest executes one real AuthState-to-native-bridge callback sequence.
func runSubjectOrderTest(t *testing.T, crossSource bool, want []string) {
	t.Helper()

	recorder := &subjectOrderRecorder{}
	source := &fakeSubjectSource{evaluate: func(_ context.Context, _ pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
		recorder.append("native_rns_ldap")

		return pluginapi.SubjectResult{}, nil
	}}
	bridge := newSubjectTestBridge(t, source)

	activateMixedSubjectPolicySnapshot(t, crossSource)
	auth := newSubjectTestAuth(t)
	passDBResult := newSubjectTestPassDBResult()

	defer core.PutPassDBResultToPool(passDBResult)

	core.RegisterLuaSubject(&orderedLuaSubject{recorder: recorder})
	core.RegisterPluginSubjectSourceBridge(bridge)
	t.Cleanup(func() {
		core.RegisterLuaSubject(nil)
		core.RegisterPluginSubjectSourceBridge(nil)
	})

	result := auth.SubjectLua(auth.Request.HTTPClientContext, passDBResult)
	if result != definitions.AuthResultOK {
		t.Fatalf("SubjectLua() = %v, want OK", result)
	}

	recorder.assert(t, want)
}

type subjectOrderRecorder struct {
	mu     sync.Mutex
	events []string
}

// append records one callback in execution order.
func (r *subjectOrderRecorder) append(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// assert verifies the exact callback sequence.
func (r *subjectOrderRecorder) assert(t *testing.T, want []string) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.events) != len(want) {
		t.Fatalf("callback order = %#v, want %#v", r.events, want)
	}

	for index := range want {
		if r.events[index] != want[index] {
			t.Fatalf("callback order = %#v, want %#v", r.events, want)
		}
	}
}

type orderedLuaSubject struct {
	recorder *subjectOrderRecorder
}

// Analyze records the existing whole-Lua callback order.
func (s *orderedLuaSubject) Analyze(_ *gin.Context, view *core.StateView, _ *core.PassDBResult) definitions.AuthResult {
	for _, name := range []string{"geoip_history", "geoip_reputation", "director_routing"} {
		s.recorder.append(name)
	}

	view.Auth().Runtime.Authorized = true

	return definitions.AuthResultOK
}

// AnalyzeSchedule records only the Lua callbacks selected for one mixed-source phase.
func (s *orderedLuaSubject) AnalyzeSchedule(
	_ *gin.Context,
	view *core.StateView,
	_ *core.PassDBResult,
	plan policycollection.ScriptSchedulePlan,
) definitions.AuthResult {
	for _, schedule := range plan.Schedules {
		s.recorder.append(schedule.Name)
	}

	view.Auth().Runtime.Authorized = true

	return definitions.AuthResultOK
}

// activateMixedSubjectPolicySnapshot installs the real mixed check topology for one host-path test.
func activateMixedSubjectPolicySnapshot(t *testing.T, crossSource bool) {
	t.Helper()

	directorAfter := []string{"lua_subject_geoip_reputation"}
	if crossSource {
		directorAfter = []string{subjectCheckName}
	}

	checks := []policyruntime.CompiledCheck{
		orderedSubjectCheck("lua_subject_geoip_history", policy.CheckTypeLuaSubjectSource, "auth.policy.attribute_sources.lua.subject.geoip_history", nil),
		orderedSubjectCheck("lua_subject_geoip_reputation", policy.CheckTypeLuaSubjectSource, "auth.policy.attribute_sources.lua.subject.geoip_reputation", []string{"lua_subject_geoip_history"}),
		orderedSubjectCheck(subjectCheckName, policy.CheckTypePluginSubjectSource, subjectCheckConfigRef, nil),
		orderedSubjectCheck("lua_subject_director_routing", policy.CheckTypeLuaSubjectSource, "auth.policy.attribute_sources.lua.subject.director_routing", directorAfter),
	}

	snapshot := &policyruntime.Snapshot{
		Generation:    2,
		Mode:          pluginPolicyModeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StageSubjectAnalysis: {Stage: policy.StageSubjectAnalysis, Checks: checks},
			},
		},
	}

	if err := policyruntime.DefaultStore().Activate(snapshot); err != nil {
		t.Fatalf("activate policy snapshot: %v", err)
	}

	t.Cleanup(func() {
		if err := policyruntime.DefaultStore().Activate(&policyruntime.Snapshot{}); err != nil {
			t.Fatalf("restore policy snapshot: %v", err)
		}
	})
}

// orderedSubjectCheck builds one authenticated subject-analysis check.
func orderedSubjectCheck(name string, checkType string, configRef string, after []string) policyruntime.CompiledCheck {
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
