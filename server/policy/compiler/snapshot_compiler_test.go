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

package compiler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestCompilerBuildsSnapshotFromConfiguredPolicy(t *testing.T) {
	cfg := policyCompilerTestConfig()

	snapshot, err := NewCompiler().Compile(context.Background(), Input{
		Config:     cfg,
		Generation: 42,
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if snapshot.Generation != 42 {
		t.Fatalf("generation = %d, want 42", snapshot.Generation)
	}

	if snapshot.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", snapshot.Mode)
	}

	if _, ok := snapshot.AttributeRegistry["auth.brute_force.triggered"]; !ok {
		t.Fatal("built-in brute-force attribute missing")
	}

	stagePlan := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	if len(stagePlan.Checks) != 2 {
		t.Fatalf("pre-auth checks = %d, want 2", len(stagePlan.Checks))
	}

	if got := stagePlan.Checks[0].Name; got != "brute_force" {
		t.Fatalf("first check = %q, want brute_force", got)
	}

	if len(stagePlan.Policies) != 2 {
		t.Fatalf("pre-auth policies = %d, want 2", len(stagePlan.Policies))
	}

	if _, ok := snapshot.Sets.Networks["trusted_clients"]; !ok {
		t.Fatal("compiled network set missing")
	}

	if _, ok := snapshot.Sets.TimeWindows["business_hours"]; !ok {
		t.Fatal("compiled time-window set missing")
	}
}

func TestCompilerRunsLuaRegistryScript(t *testing.T) {
	scriptPath := writeLuaRegistryScript(t, validLuaRegistryScript())
	cfg := luaRegistryPolicyConfig(scriptPath)

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	definition, ok := snapshot.AttributeRegistry["lua.billing.account_locked"]
	if !ok {
		t.Fatal("Lua-registered attribute missing")
	}

	detail := definition.Details["status_message"]
	if detail.Type != policyregistry.AttributeTypeString {
		t.Fatalf("detail type = %q, want string", detail.Type)
	}

	if detail.Sensitivity != "public" || detail.Purpose != "response_message" {
		t.Fatalf("detail metadata = %#v, want public response_message", detail)
	}
}

func validLuaRegistryScript() string {
	return `
nauthilus_policy.register_attribute({
  id = "lua.billing.account_locked",
  stage = "auth_filters",
  operations = { "authenticate" },
  category = "subject",
  type = "bool",
  description = "Billing lock",
  details = {
    status_message = {
      type = "string",
      sensitivity = "public",
      purpose = "response_message",
      max_length = 128,
    },
  },
})
`
}

func writeLuaRegistryScript(t *testing.T, script string) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "attributes.lua")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return scriptPath
}

func luaRegistryPolicyConfig(scriptPath string) *config.FileSettings {
	return &config.FileSettings{
		Auth: &config.AuthSection{
			Policy: config.AuthPolicySection{
				Mode:            "enforce",
				DefaultPolicy:   policy.BuiltinDefaultSet,
				RegistryScripts: []string{scriptPath},
				Policies:        []config.PolicyRuleConfig{billingLockPolicy()},
			},
		},
	}
}

func billingLockPolicy() config.PolicyRuleConfig {
	return config.PolicyRuleConfig{
		Name:  "deny_billing_lock",
		Stage: string(policy.StageAuthDecision),
		If: config.PolicyConditionConfig{
			Attribute: "lua.billing.account_locked",
			Is:        true,
		},
		Then: config.PolicyThenConfig{
			Decision:       string(policy.DecisionDeny),
			ResponseMarker: "auth.response.fail",
			ResponseMessage: config.PolicyResponseMessageConfig{
				From:      "attribute_detail",
				Attribute: "lua.billing.account_locked",
				Detail:    "status_message",
				Fallback:  "Account locked",
			},
		},
	}
}

func TestCompilerRejectsInvalidLuaRegistryCategory(t *testing.T) {
	scriptPath := writeLuaRegistryScript(t, `
nauthilus_policy.register_attribute({
  id = "lua.invalid.category",
  stage = "pre_auth",
  operations = { "authenticate" },
  category = "unsupported",
  type = "bool",
  description = "Invalid category",
})
`)

	cfg := &config.FileSettings{
		Auth: &config.AuthSection{
			Policy: config.AuthPolicySection{
				Mode:            "enforce",
				DefaultPolicy:   policy.BuiltinDefaultSet,
				RegistryScripts: []string{scriptPath},
			},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want invalid Lua registry category error")
	}

	if !strings.Contains(err.Error(), "auth.policy.registry_scripts[0]") {
		t.Fatalf("Compile() error = %q, want registry script path", err)
	}
}

func TestCompilerRejectsInvalidPolicyWithCanonicalPath(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].If.Attribute = "auth.missing"

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want unknown attribute error")
	}

	if !strings.Contains(err.Error(), "auth.policy.policies[0].if.attribute") {
		t.Fatalf("Compile() error = %q, want canonical attribute path", err)
	}
}

func TestCompilerRejectsCurrentFSMEventNames(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.FSMEventMarker = "features_ok"

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want current event name rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy.policies[0].then.fsm_event_marker") {
		t.Fatalf("Compile() error = %q, want canonical FSM marker path", err)
	}
}

func TestCompilerRejectsPreAuthPermitDecision(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.Decision = string(policy.DecisionPermit)
	cfg.Auth.Policy.Policies[0].Then.ResponseMarker = "auth.response.ok"

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want pre-auth permit rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy.policies[0].then.decision") {
		t.Fatalf("Compile() error = %q, want canonical decision path", err)
	}
}

func TestCompilerRejectsInvalidNetworkSet(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Sets.Networks["trusted_clients"] = []string{"not-a-network"}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want invalid network set error")
	}

	if !strings.Contains(err.Error(), "auth.policy.sets.networks.trusted_clients[0]") {
		t.Fatalf("Compile() error = %q, want network set path", err)
	}
}

func TestCompilerRejectsAttributeWithoutProducingCheck(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Checks = nil
	cfg.Auth.Policy.Policies = []config.PolicyRuleConfig{
		{
			Name:  "deny_backend_failure",
			Stage: string(policy.StageAuthDecision),
			If: config.PolicyConditionConfig{
				Attribute: "auth.authenticated",
				Is:        false,
			},
			Then: config.PolicyThenConfig{
				Decision:       string(policy.DecisionDeny),
				ResponseMarker: "auth.response.fail",
			},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want missing producer error")
	}

	if !strings.Contains(err.Error(), "auth.policy.policies[0].if.attribute") {
		t.Fatalf("Compile() error = %q, want canonical attribute path", err)
	}
}

func TestCompilerRejectsRunIfIncompatibleCheckDependency(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies = nil
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		{
			Name:      "lua_control_auth_only",
			Type:      policy.CheckTypeLuaControl,
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "auth.controls.lua.controls.auth_only",
			RunIf:     config.PolicyRunIfConfig{AuthState: policy.RunIfAuthenticated},
		},
		{
			Name:      "lua_control_unauth_only",
			Type:      policy.CheckTypeLuaControl,
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "auth.controls.lua.controls.unauth_only",
			RunIf:     config.PolicyRunIfConfig{AuthState: policy.RunIfUnauthenticated},
			After:     []string{"lua_control_auth_only"},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want scheduler compatibility error")
	}

	if !strings.Contains(err.Error(), "auth.policy.checks.lua_control_unauth_only.after[0]") {
		t.Fatalf("Compile() error = %q, want dependency path", err)
	}
}

func TestCompilerLeavesStoreUnchangedWhenCandidateFails(t *testing.T) {
	store := policyruntime.NewSnapshotStore(&policyruntime.Snapshot{Generation: 7})
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].RequireChecks = []string{"missing"}

	if err := CompileAndActivate(context.Background(), store, NewCompiler(), Input{
		Config:     cfg,
		Generation: 8,
	}); err == nil {
		t.Fatal("CompileAndActivate() error = nil, want invalid required check error")
	}

	active := store.Active()
	if active == nil {
		t.Fatal("active snapshot is nil")
	}

	if active.Generation != 7 {
		t.Fatalf("active generation = %d, want 7", active.Generation)
	}
}

func policyCompilerTestConfig() *config.FileSettings {
	return &config.FileSettings{
		Auth: &config.AuthSection{
			Policy: config.AuthPolicySection{
				Mode:          "enforce",
				DefaultPolicy: policy.BuiltinDefaultSet,
				Sets:          policyCompilerSets(),
				Checks:        policyCompilerChecks(),
				Policies:      policyCompilerPolicies(),
			},
		},
	}
}

func policyCompilerSets() config.PolicySetsConfig {
	return config.PolicySetsConfig{
		Networks: map[string][]string{
			"trusted_clients": {"10.0.0.0/8", "2001:db8::/32"},
		},
		TimeWindows: map[string]config.PolicyTimeWindowConfig{
			"business_hours": {
				Timezone: "Europe/Berlin",
				Days:     []string{"mon", "tue"},
				Intervals: []config.PolicyTimeIntervalConfig{
					{Start: "08:00", End: "18:00"},
				},
			},
		},
	}
}

func policyCompilerChecks() []config.PolicyCheckConfig {
	return []config.PolicyCheckConfig{
		{
			Name:      "brute_force",
			Type:      "builtin.brute_force",
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "auth.controls.brute_force",
		},
		{
			Name:      "tls_encryption",
			Type:      "builtin.tls_encryption",
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "auth.controls.tls_encryption",
		},
	}
}

func policyCompilerPolicies() []config.PolicyRuleConfig {
	return []config.PolicyRuleConfig{
		{
			Name:          "deny_bruteforce",
			Stage:         string(policy.StagePreAuth),
			RequireChecks: []string{"brute_force"},
			If: config.PolicyConditionConfig{
				Attribute: "auth.brute_force.triggered",
				Is:        true,
			},
			Then: config.PolicyThenConfig{
				Decision:       string(policy.DecisionDeny),
				ResponseMarker: "auth.response.fail",
			},
		},
		tlsTempfailPolicy(),
	}
}

func tlsTempfailPolicy() config.PolicyRuleConfig {
	return config.PolicyRuleConfig{
		Name:          "tls_tempfail",
		Stage:         string(policy.StagePreAuth),
		RequireChecks: []string{"tls_encryption"},
		If: config.PolicyConditionConfig{
			Attribute: "auth.tls.secure",
			Is:        false,
		},
		Then: config.PolicyThenConfig{
			Decision:       string(policy.DecisionTempFail),
			ResponseMarker: "auth.response.tempfail.no_tls",
		},
	}
}
