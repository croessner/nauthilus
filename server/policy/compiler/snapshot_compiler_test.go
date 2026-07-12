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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const testRBLReturnCodeListed = "127.0.0.2"

const (
	testPolicyI18NKey            = "auth.policy.company.account_blocked"
	testPolicyI18NFallback       = "Login failed because the account is locked."
	testPolicyResponseLanguage   = "de"
	testRequestHeaderName        = "X-Company-Domain"
	testRequestMetadataKey       = "x-company-domain"
	testRequestHeaderAttribute   = "request.header.company_domain"
	testRequestMetadataAttribute = "request.metadata.company_domain"
	testPluginPolicyModule       = "native_policy"
	testPluginPolicySubjectCheck = "plugin_subject_native_policy_subject"
	testPluginPolicyAttribute    = "plugin.native_policy.subject.flag"
	testPluginNamedAttribute     = "plugin.native_policy.subject.named_flag"
	testPluginObligationID       = testPluginPolicyModule + ".sync_obligation"
	testPluginPostActionID       = testPluginPolicyModule + ".post_action"
	testExternalPluginModule     = "clickhouse"
	testExternalPostActionID     = testExternalPluginModule + ".post_action"
)

// assertCompileErrorContains verifies that compiling a config fails with a canonical path fragment.
func assertCompileErrorContains(t *testing.T, cfg config.File, wantErr string, wantDescription string) {
	t.Helper()

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatalf("Compile() error = nil, want %s", wantDescription)
	}

	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("Compile() error = %q, want %s", err, wantErr)
	}
}

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

func TestCompilerAcceptsI18NResponseMessageAndResponseLanguage(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.ResponseMessage = config.PolicyResponseMessageConfig{
		From:     policy.ResponseSourceI18N,
		I18NKey:  testPolicyI18NKey,
		Fallback: testPolicyI18NFallback,
	}
	cfg.Auth.Policy.Policies[0].Then.ResponseLanguage = config.PolicyResponseLanguageConfig{
		From:     policy.ResponseSourceLiteral,
		Language: testPolicyResponseLanguage,
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Policies[0]
	if compiled.Then.ResponseMessage.Source != policy.ResponseSourceI18N {
		t.Fatalf("response message source = %q, want i18n", compiled.Then.ResponseMessage.Source)
	}

	if compiled.Then.ResponseMessage.I18NKey != testPolicyI18NKey {
		t.Fatalf("i18n key = %q, want configured key", compiled.Then.ResponseMessage.I18NKey)
	}

	if compiled.Then.ResponseLanguage.Source != policy.ResponseSourceLiteral ||
		compiled.Then.ResponseLanguage.Language != testPolicyResponseLanguage {
		t.Fatalf("response language = %#v, want literal de", compiled.Then.ResponseLanguage)
	}
}

func TestCompilerRegistersRequestHeaderAndMetadataAttributes(t *testing.T) {
	cfg := policyCompilerTestConfig()
	addRequestAttributeConfigs(cfg)
	addRequestAttributeLanguagePolicies(cfg)

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	assertRequestAttributeDefinition(t, snapshot, testRequestHeaderAttribute)
	assertRequestAttributeDefinition(t, snapshot, testRequestMetadataAttribute)
	assertRequestAttributePlans(t, snapshot)
}

func TestCompilerRejectsInvalidI18NResponseMessage(t *testing.T) {
	testCases := map[string]invalidPolicyOutputTestCase{
		"i18n without key": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.Policies[0].Then.ResponseMessage = config.PolicyResponseMessageConfig{
					From:     policy.ResponseSourceI18N,
					Fallback: testPolicyI18NFallback,
				}
			},
			wantErr: "auth.policy.policies[0].then.response_message.i18n_key",
		},
		"i18n without fallback": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.Policies[0].Then.ResponseMessage = config.PolicyResponseMessageConfig{
					From:    policy.ResponseSourceI18N,
					I18NKey: testPolicyI18NKey,
				}
			},
			wantErr: "auth.policy.policies[0].then.response_message.fallback",
		},
		"i18n with attribute": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.Policies[0].Then.ResponseMessage = config.PolicyResponseMessageConfig{
					From:      policy.ResponseSourceI18N,
					I18NKey:   testPolicyI18NKey,
					Attribute: policy.AttributeBruteForceTriggered,
					Fallback:  testPolicyI18NFallback,
				}
			},
			wantErr: "auth.policy.policies[0].then.response_message",
		},
	}

	runInvalidPolicyOutputTestCases(t, testCases)
}

func TestCompilerRejectsInvalidResponseLanguage(t *testing.T) {
	testCases := map[string]invalidPolicyOutputTestCase{
		"literal language without tag": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.Policies[0].Then.ResponseLanguage = config.PolicyResponseLanguageConfig{
					From: policy.ResponseSourceLiteral,
				}
			},
			wantErr: "auth.policy.policies[0].then.response_language.language",
		},
		"literal language with invalid tag": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.Policies[0].Then.ResponseLanguage = config.PolicyResponseLanguageConfig{
					From:     policy.ResponseSourceLiteral,
					Language: "not a language",
				}
			},
			wantErr: "auth.policy.policies[0].then.response_language.language",
		},
		"attribute language without attribute": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.Policies[0].Then.ResponseLanguage = config.PolicyResponseLanguageConfig{
					From: policy.ResponseSourceAttribute,
				}
			},
			wantErr: "auth.policy.policies[0].then.response_language.attribute",
		},
	}

	runInvalidPolicyOutputTestCases(t, testCases)
}

func TestCompilerRejectsInvalidRequestAttributeAllowlists(t *testing.T) {
	testCases := map[string]invalidPolicyOutputTestCase{
		"duplicate request attribute id": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.RequestHeaders = []config.PolicyRequestHeaderAttributeConfig{
					{Header: testRequestHeaderName, Attribute: testRequestHeaderAttribute, Visibility: requestAttributeVisibility},
				}
				cfg.Auth.Policy.RequestMetadata = []config.PolicyRequestMetadataAttributeConfig{
					{Key: testRequestMetadataKey, Attribute: testRequestHeaderAttribute, Visibility: requestAttributeVisibility},
				}
			},
			wantErr: "auth.policy.request_metadata[0].attribute",
		},
		"unsafe header attribute id": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.RequestHeaders = []config.PolicyRequestHeaderAttributeConfig{
					{Header: testRequestHeaderName, Attribute: policy.AttributeBackendTempFail, Visibility: requestAttributeVisibility},
				}
			},
			wantErr: "auth.policy.request_headers[0].attribute",
		},
		"unsafe metadata key": {
			configure: func(cfg *config.FileSettings) {
				cfg.Auth.Policy.RequestMetadata = []config.PolicyRequestMetadataAttributeConfig{
					{Key: "Authorization", Attribute: testRequestMetadataAttribute, Visibility: requestAttributeVisibility},
				}
			},
			wantErr: "auth.policy.request_metadata[0].key",
		},
	}

	runInvalidPolicyOutputTestCases(t, testCases)
}

type invalidPolicyOutputTestCase struct {
	configure func(*config.FileSettings)
	wantErr   string
}

func runInvalidPolicyOutputTestCases(t *testing.T, testCases map[string]invalidPolicyOutputTestCase) {
	t.Helper()

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := policyCompilerTestConfig()
			testCase.configure(cfg)

			_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
			if err == nil {
				t.Fatal("Compile() error = nil, want validation error")
			}

			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("Compile() error = %q, want path %q", err, testCase.wantErr)
			}
		})
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
				From:      policy.ResponseSourceAttributeDetail,
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

	assertCompileErrorContains(t, cfg, "auth.policy.policies[0].if.attribute", "unknown attribute error")
}

func TestCompilerRejectsUnknownFSMEventNames(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.FSMEventMarker = "unknown_pre_auth_marker"

	assertCompileErrorContains(t, cfg, "auth.policy.policies[0].then.fsm_event_marker", "unknown event name rejection")
}

func TestCompilerRejectsPreAuthPermitDecision(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.Decision = string(policy.DecisionPermit)
	cfg.Auth.Policy.Policies[0].Then.ResponseMarker = "auth.response.ok"

	assertCompileErrorContains(t, cfg, "auth.policy.policies[0].then.decision", "pre-auth permit rejection")
}

func TestCompilerAcceptsLuaActionDispatchObligationArgs(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.Obligations = []config.PolicyEffectConfig{
		{
			ID: policy.ObligationLuaActionDispatch,
			Args: map[string]any{
				policy.ObligationArgAction:      policy.LuaActionDispatchLua,
				policy.ObligationArgEnvironment: "lua_environment_named_script",
				policy.ObligationArgFeature:     policy.LuaActionDispatchBruteForce,
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

	if got := obligations[0].Args[policy.ObligationArgFeature]; got != policy.LuaActionDispatchBruteForce {
		t.Fatalf("feature arg = %v, want %s", got, policy.LuaActionDispatchBruteForce)
	}
}

func TestCompilerAcceptsBruteForceUpdateObligationArgs(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.Obligations = []config.PolicyEffectConfig{
		{
			ID: policy.ObligationBruteForceUpdate,
			Args: map[string]any{
				policy.ObligationArgFeature:     policy.LuaActionDispatchLua,
				policy.ObligationArgEnvironment: "blocklist",
			},
		},
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	obligations := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Policies[0].Then.Obligations
	if len(obligations) != 1 {
		t.Fatalf("obligations = %d, want one brute-force update obligation", len(obligations))
	}

	if got := obligations[0].Args[policy.ObligationArgFeature]; got != policy.LuaActionDispatchLua {
		t.Fatalf("feature arg = %v, want %s", got, policy.LuaActionDispatchLua)
	}

	if got := obligations[0].Args[policy.ObligationArgEnvironment]; got != "blocklist" {
		t.Fatalf("environment arg = %v, want blocklist", got)
	}
}

func TestCompilerRejectsBruteForceUpdateInvalidArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{name: "non-string feature", args: map[string]any{policy.ObligationArgFeature: true}, wantErr: "must be a string"},
		{name: "empty feature", args: map[string]any{policy.ObligationArgFeature: ""}, wantErr: "must not be empty"},
		{name: "non-string environment", args: map[string]any{policy.ObligationArgEnvironment: true}, wantErr: "must be a string"},
		{name: "unknown argument", args: map[string]any{"action": "rbl"}, wantErr: "is not supported"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assertCompilerRejectsObligationArgs(t, policy.ObligationBruteForceUpdate, testCase.args, testCase.wantErr)
		})
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
			name:    "non-string feature",
			args:    map[string]any{policy.ObligationArgAction: policy.LuaActionDispatchLua, "feature": true},
			wantErr: "must be a string",
		},
		{
			name:    "unknown argument",
			args:    map[string]any{policy.ObligationArgAction: policy.LuaActionDispatchLua, "label": "bad"},
			wantErr: "is not supported",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assertCompilerRejectsObligationArgs(t, policy.ObligationLuaActionDispatch, testCase.args, testCase.wantErr)
		})
	}
}

// assertCompilerRejectsObligationArgs verifies one bounded obligation argument failure.
func assertCompilerRejectsObligationArgs(t *testing.T, id string, args map[string]any, wantErr string) {
	t.Helper()

	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies[0].Then.Obligations = []config.PolicyEffectConfig{
		{ID: id, Args: args},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want invalid obligation args")
	}

	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("Compile() error = %q, want %q", err, wantErr)
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

func TestCompilerAcceptsPluginBackendStandardAttributes(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		{
			Name:      "plugin_backend_example_auth",
			Type:      policy.CheckTypePluginBackend,
			Stage:     string(policy.StageAuthBackend),
			ConfigRef: "auth.backends.order",
		},
	}
	cfg.Auth.Policy.Policies = []config.PolicyRuleConfig{
		backendAttributePolicy("backend_tempfail", policy.AttributeBackendTempFail, policy.OperationAuthenticate),
		backendAttributePolicy("authenticated", policy.AttributeAuthenticated, policy.OperationAuthenticate),
		backendAttributePolicy("identity_found", policy.AttributeIdentityFound, policy.OperationLookupIdentity),
		backendAttributePolicy("empty_username", policy.AttributeBackendEmptyUsername, policy.OperationLookupIdentity),
		backendAttributePolicy("empty_password", policy.AttributeBackendEmptyPassword, policy.OperationAuthenticate),
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	authChecks := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthBackend].Checks
	if len(authChecks) != 1 || authChecks[0].Type != policy.CheckTypePluginBackend {
		t.Fatalf("authenticate backend checks = %#v, want one native plugin backend check", authChecks)
	}

	lookupChecks := snapshot.StagePlans[policy.OperationLookupIdentity][policy.StageAuthBackend].Checks
	if len(lookupChecks) != 1 || lookupChecks[0].Type != policy.CheckTypePluginBackend {
		t.Fatalf("lookup backend checks = %#v, want one native plugin backend check", lookupChecks)
	}
}

func TestCompilerAcceptsPluginEnvironmentCheckType(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies = nil
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		{
			Name:      "plugin_environment_geoip",
			Type:      policy.CheckTypePluginEnvironment,
			Stage:     string(policy.StagePreAuth),
			ConfigRef: "plugins.modules.geoip.environment",
		},
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	checks := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Checks
	if len(checks) != 1 {
		t.Fatalf("pre-auth checks = %d, want 1", len(checks))
	}

	if checks[0].Type != policy.CheckTypePluginEnvironment {
		t.Fatalf("check type = %q, want %q", checks[0].Type, policy.CheckTypePluginEnvironment)
	}
}

func TestCompilerAcceptsGeoIPPrivacyEnvironmentFacts(t *testing.T) {
	publishCompilerPluginState(t, loadCompilerPluginStateForModule(t, "geoip", compilerGeoIPPrivacyPlugin{}))

	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Policies = nil
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{{
		Name:       "plugin_environment_geoip",
		Type:       policy.CheckTypePluginEnvironment,
		Stage:      string(policy.StagePreAuth),
		Operations: []string{string(policy.OperationAuthenticate), string(policy.OperationLookupIdentity)},
		ConfigRef:  "plugins.modules.geoip.environment",
	}}

	for index, condition := range []config.PolicyConditionConfig{
		{Attribute: "plugin.environment.geoip.is_tor_exit_node", Is: true},
		{Attribute: "plugin.environment.geoip.is_known_vpn_exit", Is: true},
		{Attribute: "plugin.environment.geoip.is_public_proxy", Is: true},
		{Attribute: "plugin.environment.geoip.privacy_data_stale", Is: false},
		{Attribute: "plugin.environment.geoip.is_hosting_network", Is: true},
		{Attribute: "plugin.environment.geoip.is_shared_egress", Is: true},
	} {
		cfg.Auth.Policy.Policies = append(cfg.Auth.Policy.Policies, config.PolicyRuleConfig{
			Name:          fmt.Sprintf("geoip_privacy_%d", index),
			Stage:         string(policy.StagePreAuth),
			Operations:    []string{string(policy.OperationAuthenticate)},
			RequireChecks: []string{"plugin_environment_geoip"},
			If:            condition,
			Then: config.PolicyThenConfig{
				Decision:       string(policy.DecisionDeny),
				ResponseMarker: policy.ResponseMarkerFail,
			},
		})
	}

	if _, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1}); err != nil {
		t.Fatalf("Compile() GeoIP privacy policy error = %v", err)
	}
}

func TestCompilerRegistersNativePluginPolicySurface(t *testing.T) {
	publishCompilerPluginState(t, loadCompilerPluginState(t))

	cfg := nativePluginPolicySurfaceConfig()

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	assertNativePluginPolicySurface(t, snapshot)
}

func TestCompilerRegistersExternalPostActionFromPluginState(t *testing.T) {
	publishCompilerPluginState(t, loadCompilerExternalPostActionPluginState(t))

	effects, err := compileEffectRegistries()
	if err != nil {
		t.Fatalf("compileEffectRegistries() error = %v", err)
	}

	definition, ok := effects.obligations[testExternalPostActionID]
	if !ok {
		t.Fatalf("obligation %q missing", testExternalPostActionID)
	}

	if definition.Kind != effectKindPostAction {
		t.Fatalf("obligation kind = %q, want %q", definition.Kind, effectKindPostAction)
	}
}

func TestCompilerRejectsPluginCustomFactWithUnresolvedProducerCheck(t *testing.T) {
	publishCompilerPluginState(t, loadCompilerPluginState(t))

	cfg := nativePluginPolicySurfaceConfig()
	cfg.Auth.Policy.Policies[0].If.Attribute = testPluginNamedAttribute

	assertCompileErrorContains(
		t,
		cfg,
		"requires the producing check in the active check plan",
		"unresolved native plugin producer check error",
	)
}

func TestCompilerRegistersPluginSubjectAttributesWithComponentIdentity(t *testing.T) {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		{
			Name:      "plugin_subject_example_auth_policy",
			Type:      policy.CheckTypePluginSubjectSource,
			Stage:     string(policy.StageSubjectAnalysis),
			ConfigRef: "plugins.modules.example_auth.subject",
		},
	}
	cfg.Auth.Policy.Policies = []config.PolicyRuleConfig{
		{
			Name:  "deny_native_subject_rejection",
			Stage: string(policy.StageAuthDecision),
			If: config.PolicyConditionConfig{
				Attribute: "auth.plugin.subject.example_auth.policy.rejected",
				Is:        true,
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

	assertRegisteredPluginSubjectAttribute(t, snapshot, "auth.plugin.subject.example_auth.policy.rejected")
	assertRegisteredPluginSubjectAttribute(t, snapshot, "auth.plugin.subject.example_auth.policy.error")
}

// nativePluginPolicySurfaceConfig builds a config that consumes registered plugin policy metadata.
func nativePluginPolicySurfaceConfig() *config.FileSettings {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		{
			Name:      testPluginPolicySubjectCheck,
			Type:      policy.CheckTypePluginSubjectSource,
			Stage:     string(policy.StageSubjectAnalysis),
			ConfigRef: "plugins.modules." + testPluginPolicyModule + ".subject",
		},
	}
	cfg.Auth.Policy.Policies = []config.PolicyRuleConfig{
		{
			Name:  "deny_native_subject_flag",
			Stage: string(policy.StageAuthDecision),
			If: config.PolicyConditionConfig{
				Attribute: testPluginPolicyAttribute,
				Is:        true,
			},
			Then: config.PolicyThenConfig{
				Decision:       string(policy.DecisionDeny),
				ResponseMarker: policy.ResponseMarkerFail,
				Obligations: []config.PolicyEffectConfig{
					{
						ID:   testPluginObligationID,
						Args: map[string]any{"message": "native"},
					},
				},
			},
		},
	}

	return cfg
}

// assertRegisteredPluginSubjectAttribute verifies generated native subject attributes use the canonical producer.
func assertRegisteredPluginSubjectAttribute(t *testing.T, snapshot *policyruntime.Snapshot, attributeID string) {
	t.Helper()

	definition, ok := snapshot.AttributeRegistry[attributeID]
	if !ok {
		t.Fatalf("generated plugin subject attribute %q missing", attributeID)
	}

	if definition.ProducerCheck != "plugin_subject_example_auth_policy" {
		t.Fatalf("producer check = %q, want plugin_subject_example_auth_policy", definition.ProducerCheck)
	}
}

// assertNativePluginPolicySurface verifies plugin attributes, checks, and effects are compiled.
func assertNativePluginPolicySurface(t *testing.T, snapshot *policyruntime.Snapshot) {
	t.Helper()

	definition, ok := snapshot.AttributeRegistry[testPluginPolicyAttribute]
	if !ok {
		t.Fatal("native plugin policy attribute missing")
	}

	if definition.Source != policyregistry.SourcePlugin {
		t.Fatalf("attribute source = %q, want plugin", definition.Source)
	}

	if !stringsContain(definition.ProducerTypes, policy.CheckTypePluginSubjectSource) {
		t.Fatalf("producer types = %#v, want plugin subject source", definition.ProducerTypes)
	}

	checks := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageSubjectAnalysis].Checks
	if len(checks) != 1 || checks[0].Type != policy.CheckTypePluginSubjectSource {
		t.Fatalf("subject checks = %#v, want one native plugin subject check", checks)
	}

	if got := snapshot.ObligationRegistry[testPluginObligationID].Kind; got != effectKindObligation {
		t.Fatalf("obligation kind = %q, want %q", got, effectKindObligation)
	}

	if got := snapshot.ObligationRegistry[testPluginPostActionID].Kind; got != effectKindPostAction {
		t.Fatalf("post-action kind = %q, want %q", got, effectKindPostAction)
	}

	obligations := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision].Policies[0].Then.Obligations
	if len(obligations) != 1 || obligations[0].ID != testPluginObligationID {
		t.Fatalf("compiled obligations = %#v, want native obligation", obligations)
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

func addRequestAttributeConfigs(cfg *config.FileSettings) {
	cfg.Auth.Policy.RequestHeaders = []config.PolicyRequestHeaderAttributeConfig{
		{
			Header:     testRequestHeaderName,
			Attribute:  testRequestHeaderAttribute,
			Visibility: requestAttributeVisibility,
			Normalize:  requestAttributeNormalizeConfig(),
		},
	}
	cfg.Auth.Policy.RequestMetadata = []config.PolicyRequestMetadataAttributeConfig{
		{
			Key:        testRequestMetadataKey,
			Attribute:  testRequestMetadataAttribute,
			Visibility: requestAttributeVisibility,
			Normalize:  requestAttributeNormalizeConfig(),
		},
	}
}

func requestAttributeNormalizeConfig() config.PolicyRequestAttributeNormalizeConfig {
	return config.PolicyRequestAttributeNormalizeConfig{
		Trim:      true,
		Case:      requestAttributeCaseLower,
		MaxLength: 64,
	}
}

func addRequestAttributeLanguagePolicies(cfg *config.FileSettings) {
	cfg.Auth.Policy.Policies = append(
		cfg.Auth.Policy.Policies,
		requestAttributeLanguagePolicy("company_header_language", testRequestHeaderAttribute, "companyde", "de"),
		requestAttributeLanguagePolicy("company_metadata_language", testRequestMetadataAttribute, "companyfr", "fr"),
	)
}

func requestAttributeLanguagePolicy(name string, attribute string, value string, language string) config.PolicyRuleConfig {
	return config.PolicyRuleConfig{
		Name:  name,
		Stage: string(policy.StageAuthDecision),
		If:    config.PolicyConditionConfig{Attribute: attribute, Eq: value},
		Then: config.PolicyThenConfig{
			Decision:        string(policy.DecisionDeny),
			ResponseMarker:  policy.ResponseMarkerFail,
			ResponseMessage: requestAttributeI18NResponseMessage(),
			ResponseLanguage: config.PolicyResponseLanguageConfig{
				From:     policy.ResponseSourceLiteral,
				Language: language,
			},
		},
	}
}

func requestAttributeI18NResponseMessage() config.PolicyResponseMessageConfig {
	return config.PolicyResponseMessageConfig{
		From:     policy.ResponseSourceI18N,
		I18NKey:  testPolicyI18NKey,
		Fallback: testPolicyI18NFallback,
	}
}

func assertRequestAttributeDefinition(t *testing.T, snapshot *policyruntime.Snapshot, attributeID string) {
	t.Helper()

	definition, ok := snapshot.AttributeRegistry[attributeID]
	if !ok {
		t.Fatalf("request attribute %q missing", attributeID)
	}

	if definition.Type != policyregistry.AttributeTypeString {
		t.Fatalf("request attribute type = %q, want string", definition.Type)
	}

	if definition.Stage != policy.StagePreAuth {
		t.Fatalf("request attribute stage = %q, want pre_auth", definition.Stage)
	}

	if definition.Category != policyregistry.AttributeCategoryEnvironment {
		t.Fatalf("request attribute category = %q, want environment", definition.Category)
	}
}

func assertRequestAttributePlans(t *testing.T, snapshot *policyruntime.Snapshot) {
	t.Helper()

	if len(snapshot.RequestAttributes.Headers) != 1 {
		t.Fatalf("header request attributes = %d, want 1", len(snapshot.RequestAttributes.Headers))
	}

	if len(snapshot.RequestAttributes.Metadata) != 1 {
		t.Fatalf("metadata request attributes = %d, want 1", len(snapshot.RequestAttributes.Metadata))
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

// backendAttributePolicy builds an auth-decision rule that consumes one backend fact.
func backendAttributePolicy(name string, attribute string, operation policy.Operation) config.PolicyRuleConfig {
	return config.PolicyRuleConfig{
		Name:       name,
		Stage:      string(policy.StageAuthDecision),
		Operations: []string{string(operation)},
		If: config.PolicyConditionConfig{
			Attribute: attribute,
			Is:        true,
		},
		Then: config.PolicyThenConfig{
			Decision:       string(policy.DecisionDeny),
			ResponseMarker: "auth.response.fail",
		},
	}
}

func loadCompilerPluginState(t *testing.T) *pluginloader.State {
	t.Helper()

	return loadCompilerPluginStateForModule(t, testPluginPolicyModule, compilerPolicyPlugin{})
}

func loadCompilerExternalPostActionPluginState(t *testing.T) *pluginloader.State {
	t.Helper()

	return loadCompilerPluginStateForModule(t, testExternalPluginModule, compilerExternalPostActionPlugin{})
}

func loadCompilerPluginStateForModule(t *testing.T, moduleName string, plugin pluginapi.Plugin) *pluginloader.State {
	t.Helper()

	artifact := writeCompilerPluginArtifact(t)
	opener := compilerPluginOpener{
		artifact: compilerPluginHandle{
			symbol: func() (pluginapi.Plugin, error) {
				return plugin, nil
			},
		},
	}

	state, err := pluginloader.NewLoader(pluginloader.WithOpener(opener)).Load([]pluginloader.VerifiedModule{
		{
			Module: config.PluginModule{
				Name: moduleName,
				Type: config.PluginModuleTypeGo,
				Path: artifact,
			},
			ArtifactPath: artifact,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	return state
}

func publishCompilerPluginState(t *testing.T, state *pluginloader.State) {
	t.Helper()

	previous, hadPrevious := pluginloader.DefaultState()

	pluginloader.SetDefaultState(state)

	t.Cleanup(func() {
		if hadPrevious {
			pluginloader.SetDefaultState(previous)

			return
		}

		pluginloader.SetDefaultState((*pluginloader.State)(nil))
	})
}

func writeCompilerPluginArtifact(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "native_policy.so")
	if err := os.WriteFile(path, []byte("fake plugin"), 0o600); err != nil {
		t.Fatalf("write fake plugin artifact: %v", err)
	}

	return path
}

type compilerPluginOpener map[string]compilerPluginHandle

func (o compilerPluginOpener) Open(path string) (pluginloader.PluginHandle, error) {
	handle, ok := o[path]
	if !ok {
		return nil, os.ErrNotExist
	}

	return handle, nil
}

type compilerPluginHandle struct {
	symbol any
}

func (h compilerPluginHandle) Lookup(string) (any, error) {
	return h.symbol, nil
}

type compilerPolicyPlugin struct{}

type compilerGeoIPPrivacyPlugin struct{}

func (compilerGeoIPPrivacyPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: "geoip", Version: "1.0.0", APIVersion: pluginapi.APIVersion}
}

func (compilerGeoIPPrivacyPlugin) Register(registrar pluginapi.Registrar) error {
	if err := registrar.RegisterEnvironmentSource(compilerGeoIPPrivacyEnvironmentSource{}); err != nil {
		return err
	}

	for _, attribute := range []string{
		"plugin.environment.geoip.is_tor_exit_node",
		"plugin.environment.geoip.is_known_vpn_exit",
		"plugin.environment.geoip.is_public_proxy",
		"plugin.environment.geoip.privacy_data_stale",
		"plugin.environment.geoip.is_hosting_network",
		"plugin.environment.geoip.is_shared_egress",
	} {
		if err := registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
			ID:            attribute,
			Description:   "GeoIP privacy policy compiler fixture.",
			Stage:         pluginapi.PolicyStagePreAuth,
			Operations:    []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate, pluginapi.PolicyOperationLookupIdentity},
			ProducerTypes: []string{policy.CheckTypePluginEnvironment},
			Category:      pluginapi.AttributeCategoryEnvironment,
			Type:          pluginapi.AttributeTypeBool,
		}); err != nil {
			return err
		}
	}

	return nil
}

type compilerGeoIPPrivacyEnvironmentSource struct{}

func (compilerGeoIPPrivacyEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "environment"}
}

func (compilerGeoIPPrivacyEnvironmentSource) Evaluate(context.Context, pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error) {
	return pluginapi.EnvironmentResult{}, nil
}

func (p compilerPolicyPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       testPluginPolicyModule,
		Version:    "1.0.0",
		APIVersion: pluginapi.APIVersion,
	}
}

func (p compilerPolicyPlugin) Register(registrar pluginapi.Registrar) error {
	if err := registrar.RegisterSubjectSource(compilerSubjectSource{}); err != nil {
		return err
	}

	if err := registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
		ID:          testPluginPolicyAttribute,
		Description: "Native subject flag",
		Stage:       pluginapi.PolicyStageSubjectAnalysis,
		Operations:  []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		ProducerTypes: []string{
			policy.CheckTypePluginSubjectSource,
		},
		Category: pluginapi.AttributeCategorySubject,
		Type:     pluginapi.AttributeTypeBool,
	}); err != nil {
		return err
	}

	if err := registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
		ID:            testPluginNamedAttribute,
		Description:   "Native subject flag tied to an intentionally named host check.",
		Stage:         pluginapi.PolicyStageSubjectAnalysis,
		Operations:    []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		ProducerCheck: testPluginPolicyModule + ".subject",
		Category:      pluginapi.AttributeCategorySubject,
		Type:          pluginapi.AttributeTypeBool,
	}); err != nil {
		return err
	}

	if err := registrar.RegisterObligationTarget(compilerObligationTarget{}); err != nil {
		return err
	}

	return registrar.RegisterPostActionTarget(compilerPostActionTarget{})
}

type compilerSubjectSource struct{}

func (s compilerSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "subject"}
}

func (s compilerSubjectSource) Evaluate(context.Context, pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	return pluginapi.SubjectResult{}, nil
}

type compilerObligationTarget struct{}

func (t compilerObligationTarget) Name() string {
	return "sync_obligation"
}

func (t compilerObligationTarget) Execute(context.Context, pluginapi.ObligationRequest) (pluginapi.ObligationResult, error) {
	return pluginapi.ObligationResult{}, nil
}

type compilerPostActionTarget struct{}

func (t compilerPostActionTarget) Name() string {
	return "post_action"
}

func (t compilerPostActionTarget) Enqueue(context.Context, pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	return pluginapi.PostActionEnqueueResult{}, nil
}

type compilerExternalPostActionPlugin struct{}

func (p compilerExternalPostActionPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       testExternalPluginModule,
		Version:    "1.0.0",
		APIVersion: pluginapi.APIVersion,
	}
}

func (p compilerExternalPostActionPlugin) Register(registrar pluginapi.Registrar) error {
	return registrar.RegisterPostActionTarget(compilerPostActionTarget{})
}
