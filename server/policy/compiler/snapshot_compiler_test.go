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
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

const testRBLReturnCodeListed = "127.0.0.2"

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

	if detail.Sensitivity != policyregistry.DetailSensitivityPublic ||
		detail.Purpose != policyregistry.DetailPurposeResponseMessage {
		t.Fatalf("detail metadata = %#v, want public response_message", detail)
	}
}

func TestCompilerGeneratesBruteForceBucketAttributes(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.BruteForce = &config.BruteForceSection{
		Buckets: []config.BruteForceRule{
			{
				Name:           "IMAP Short",
				Period:         time.Minute,
				BanTime:        time.Hour,
				CIDR:           32,
				FailedRequests: 5,
				IPv4:           true,
			},
		},
	}
	cfg.Auth.Policy.Policies = append(cfg.Auth.Policy.Policies, config.PolicyRuleConfig{
		Name:          "imap_short_near_limit",
		Stage:         string(policy.StagePreAuth),
		RequireChecks: []string{"brute_force"},
		If: config.PolicyConditionConfig{
			Attribute: "auth.brute_force.bucket.imap_short.ratio",
			GTE:       0.8,
		},
		Then: config.PolicyThenConfig{
			Decision:       string(policy.DecisionDeny),
			ResponseMarker: policy.ResponseMarkerFail,
		},
	})

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	for _, attributeID := range []string{
		"auth.brute_force.bucket.imap_short.matched",
		"auth.brute_force.bucket.imap_short.count",
		"auth.brute_force.bucket.imap_short.effective_limit",
		"auth.brute_force.bucket.imap_short.ratio",
		"auth.brute_force.bucket.imap_short.repeating",
	} {
		if _, ok := snapshot.AttributeRegistry[attributeID]; !ok {
			t.Fatalf("generated brute-force bucket attribute %q missing", attributeID)
		}
	}
}

func TestCompilerRejectsBruteForceBucketIdentifierCollision(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.BruteForce = &config.BruteForceSection{
		Buckets: []config.BruteForceRule{
			{Name: "imap-short", Period: time.Minute, CIDR: 32, FailedRequests: 5, IPv4: true},
			{Name: "imap_short", Period: time.Minute, CIDR: 32, FailedRequests: 5, IPv4: true},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want identifier collision")
	}

	if !strings.Contains(err.Error(), `normalizes to policy identifier "imap_short"`) {
		t.Fatalf("Compile() error = %q, want normalized identifier collision", err)
	}
}

func TestCompilerGeneratesRBLListAttributes(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.RBLs = &config.RBLSection{
		Lists: []config.RBL{
			{
				Name:        "Zen Spamhaus",
				RBL:         "zen.spamhaus.org",
				ReturnCodes: []string{testRBLReturnCodeListed},
				IPv4:        true,
				Weight:      5,
			},
		},
		Threshold: 5,
	}
	cfg.Auth.Policy.Checks = append(cfg.Auth.Policy.Checks, config.PolicyCheckConfig{
		Name:      "rbl",
		Type:      policy.CheckTypeRBL,
		Stage:     string(policy.StagePreAuth),
		ConfigRef: "auth.controls.rbl",
	})
	cfg.Auth.Policy.Policies = append(cfg.Auth.Policy.Policies, config.PolicyRuleConfig{
		Name:          "zen_matched",
		Stage:         string(policy.StagePreAuth),
		RequireChecks: []string{"rbl"},
		If: config.PolicyConditionConfig{
			Attribute: "auth.rbl.list.zen_spamhaus.listed",
			Is:        true,
		},
		Then: config.PolicyThenConfig{
			Decision:       string(policy.DecisionDeny),
			ResponseMarker: policy.ResponseMarkerFail,
		},
	})

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	for _, attributeID := range []string{
		"auth.rbl.list.zen_spamhaus.listed",
		"auth.rbl.list.zen_spamhaus.weight",
		"auth.rbl.list.zen_spamhaus.error",
		"auth.rbl.list.zen_spamhaus.allow_failure",
	} {
		if _, ok := snapshot.AttributeRegistry[attributeID]; !ok {
			t.Fatalf("generated RBL list attribute %q missing", attributeID)
		}
	}
}

func TestCompilerRejectsRBLListIdentifierCollision(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.RBLs = &config.RBLSection{
		Lists: []config.RBL{
			{Name: "zen-spamhaus", RBL: "zen.spamhaus.org", ReturnCodes: []string{testRBLReturnCodeListed}, IPv4: true},
			{Name: "zen_spamhaus", RBL: "zen2.spamhaus.org", ReturnCodes: []string{testRBLReturnCodeListed}, IPv4: true},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want identifier collision")
	}

	if !strings.Contains(err.Error(), `normalizes to policy identifier "zen_spamhaus"`) {
		t.Fatalf("Compile() error = %q, want normalized identifier collision", err)
	}
}

func TestCompilerGeneratesSubjectAttributeExports(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.AttributeExports = []config.PolicyAttributeExportConfig{
		{Name: "Account Status", Attribute: "accountStatus", Type: "string"},
	}
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		{
			Name:      "ldap_backend",
			Type:      policy.CheckTypeLDAPBackend,
			Stage:     string(policy.StageAuthBackend),
			ConfigRef: "auth.backends.ldap",
		},
	}
	cfg.Auth.Policy.Policies = []config.PolicyRuleConfig{
		{
			Name:  "deny_locked_subject",
			Stage: string(policy.StageAuthDecision),
			If: config.PolicyConditionConfig{
				Attribute: "auth.subject.attribute.account_status",
				Detail:    "value",
				Eq:        "locked",
			},
			Then: config.PolicyThenConfig{
				Decision:       string(policy.DecisionDeny),
				ResponseMarker: policy.ResponseMarkerFail,
			},
		},
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	definition, ok := snapshot.AttributeRegistry["auth.subject.attribute.account_status"]
	if !ok {
		t.Fatal("generated subject attribute missing")
	}

	if definition.Type != policyregistry.AttributeTypeBool {
		t.Fatalf("subject attribute type = %q, want bool", definition.Type)
	}

	if definition.Details["value"].Type != policyregistry.AttributeTypeString {
		t.Fatalf("value detail type = %q, want string", definition.Details["value"].Type)
	}
}

func TestCompilerLoadsBundledLuaPluginRegistry(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "lua-plugins.d", "policy", "registry.lua")
	cfg := luaRegistryPolicyConfig(scriptPath)
	cfg.Auth.Policy.Policies = nil

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	for _, attributeID := range []string{
		"lua.plugin.blocklist.matched",
		"lua.plugin.geoip.rejected",
		"lua.plugin.account_protection.active",
		"lua.plugin.failed_login_hotspot.triggered",
		"lua.plugin.director.backend_server",
	} {
		if _, ok := snapshot.AttributeRegistry[attributeID]; !ok {
			t.Fatalf("bundled Lua plugin attribute %q missing", attributeID)
		}
	}
}

func validLuaRegistryScript() string {
	return `
nauthilus_policy.register_attribute({
  id = "lua.billing.account_locked",
  stage = "subject_analysis",
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

func TestCompilerRejectsUnknownFSMEventNames(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.FSMEventMarker = "unknown_pre_auth_marker"

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want unknown event name rejection")
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

func TestCompilerAcceptsLuaActionDispatchObligationArgs(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.Obligations = []config.PolicyEffectConfig{
		{
			ID: policy.ObligationLuaActionDispatch,
			Args: map[string]any{
				policy.ObligationArgAction:      policy.LuaActionDispatchLua,
				policy.ObligationArgEnvironment: "lua_environment_named_script",
				policy.ObligationArgWait:        true,
			},
		},
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	obligations := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Policies[0].Then.Obligations
	if len(obligations) != 1 {
		t.Fatalf("obligations = %d, want one lua action obligation", len(obligations))
	}

	if got := obligations[0].Args[policy.ObligationArgAction]; got != policy.LuaActionDispatchLua {
		t.Fatalf("action arg = %v, want %s", got, policy.LuaActionDispatchLua)
	}
}

func TestCompilerRejectsLuaActionDispatchInvalidArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{
			name:    "unknown action",
			args:    map[string]any{policy.ObligationArgAction: "smtp"},
			wantErr: "allowed Lua action",
		},
		{
			name:    "non-string action",
			args:    map[string]any{policy.ObligationArgAction: true},
			wantErr: "must be a string",
		},
		{
			name:    "non-string environment",
			args:    map[string]any{policy.ObligationArgAction: policy.LuaActionDispatchLua, policy.ObligationArgEnvironment: true},
			wantErr: "must be a string",
		},
		{
			name:    "non-boolean wait",
			args:    map[string]any{policy.ObligationArgAction: policy.LuaActionDispatchLua, policy.ObligationArgWait: "yes"},
			wantErr: "must be a boolean",
		},
		{
			name:    "unknown argument",
			args:    map[string]any{policy.ObligationArgAction: policy.LuaActionDispatchLua, "label": "bad"},
			wantErr: "is not supported",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := policyCompilerTestConfig()
			cfg.Auth.Policy.Policies[0].Then.Obligations = []config.PolicyEffectConfig{
				{
					ID:   policy.ObligationLuaActionDispatch,
					Args: testCase.args,
				},
			}

			_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
			if err == nil {
				t.Fatal("Compile() error = nil, want invalid lua action obligation args")
			}

			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("Compile() error = %q, want %q", err, testCase.wantErr)
			}
		})
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
			Name:      "lua_environment_auth_only",
			Type:      policy.CheckTypeLuaEnvironment,
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "auth.policy.attribute_sources.lua.environment.auth_only",
			RunIf:     config.PolicyRunIfConfig{AuthState: policy.RunIfAuthenticated},
		},
		{
			Name:      "lua_environment_unauth_only",
			Type:      policy.CheckTypeLuaEnvironment,
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "auth.policy.attribute_sources.lua.environment.unauth_only",
			RunIf:     config.PolicyRunIfConfig{AuthState: policy.RunIfUnauthenticated},
			After:     []string{"lua_environment_auth_only"},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want scheduler compatibility error")
	}

	if !strings.Contains(err.Error(), "auth.policy.checks.lua_environment_unauth_only.after[0]") {
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
