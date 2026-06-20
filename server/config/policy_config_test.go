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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"

	"github.com/spf13/viper"
)

const (
	testPolicyConditionFieldAttribute     = "attribute"
	testPolicySchedulerGuardTrustedSource = "trusted_source"
)

func TestAuthPolicyConfigDecodesAndDumps(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setPolicyConfigTestStorage()
	viper.Set("auth.policy", policyConfigDecodeFixture(t))

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	assertDecodedPolicyConfig(t, cfg)
	assertPolicyConfigDumps(t)
}

func policyConfigDecodeFixture(t *testing.T) map[string]any {
	t.Helper()

	registryScript := filepath.Join(t.TempDir(), "attrs.lua")
	if err := os.WriteFile(registryScript, []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return map[string]any{
		"mode":             "observe",
		"default_policy":   policy.BuiltinDefaultSet,
		"registry_scripts": []any{registryScript},
		"sets":             policyConfigFixtureSets(),
		"report":           policyConfigFixtureReport(),
		"scheduler_guards": policyConfigFixtureSchedulerGuards(),
		"checks":           policyConfigFixtureChecks(),
		"policies":         policyConfigFixturePolicies(),
	}
}

// policyConfigFixtureSets returns policy set fixtures.
func policyConfigFixtureSets() map[string]any {
	return map[string]any{
		"networks": map[string]any{
			"trusted": []any{"10.0.0.0/8"},
		},
		"time_windows": map[string]any{
			"office": map[string]any{
				"timezone":  "Europe/Berlin",
				"days":      []any{"mon"},
				"intervals": []any{map[string]any{"start": "08:00", "end": "18:00"}},
			},
		},
	}
}

// policyConfigFixtureReport returns report configuration fixtures.
func policyConfigFixtureReport() map[string]any {
	return map[string]any{
		"enabled":            true,
		"include_fsm":        true,
		"include_checks":     true,
		"include_attributes": false,
	}
}

// policyConfigFixtureSchedulerGuards returns scheduler guard fixtures.
func policyConfigFixtureSchedulerGuards() map[string]any {
	return map[string]any{
		testPolicySchedulerGuardTrustedSource: map[string]any{
			"on_missing_attribute": "run",
			"if": map[string]any{
				testPolicyConditionFieldAttribute: "request.client.ip.trusted",
				"is":                              true,
			},
		},
	}
}

// policyConfigFixtureChecks returns check fixtures.
func policyConfigFixtureChecks() []any {
	return []any{
		map[string]any{
			"name":       "brute_force",
			"type":       "builtin.brute_force",
			"stage":      "pre_auth",
			"config_ref": "auth.controls.brute_force",
			"skip_if":    []any{testPolicySchedulerGuardTrustedSource},
		},
	}
}

// policyConfigFixturePolicies returns policy fixtures.
func policyConfigFixturePolicies() []any {
	return []any{
		map[string]any{
			"name":           "deny_bruteforce",
			"stage":          "pre_auth",
			"require_checks": []any{"brute_force"},
			"if": map[string]any{
				testPolicyConditionFieldAttribute: "auth.brute_force.triggered",
				"is":                              true,
			},
			"then": map[string]any{
				"decision":         "deny",
				"fsm_event_marker": "auth.fsm.event.pre_auth_deny",
				"response_marker":  "auth.response.fail",
			},
		},
	}
}

func assertDecodedPolicyConfig(t *testing.T, cfg *FileSettings) {
	t.Helper()

	if cfg.Auth == nil {
		t.Fatal("auth config is nil")
	}

	if cfg.Auth.Policy.Mode != "observe" {
		t.Fatalf("policy mode = %q, want observe", cfg.Auth.Policy.Mode)
	}

	if got := cfg.Auth.Policy.Sets.Networks["trusted"]; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("network set = %#v, want configured CIDR", got)
	}

	guard := cfg.Auth.Policy.SchedulerGuards[testPolicySchedulerGuardTrustedSource]
	if guard.OnMissingAttribute != "run" || guard.If.Attribute != "request.client.ip.trusted" {
		t.Fatalf("scheduler guard = %#v, want decoded trusted_source guard", guard)
	}

	if got := cfg.Auth.Policy.Checks[0].SkipIf; len(got) != 1 || got[0] != testPolicySchedulerGuardTrustedSource {
		t.Fatalf("check skip_if = %#v, want trusted_source", got)
	}
}

func assertPolicyConfigDumps(t *testing.T) {
	t.Helper()

	defaultDump, err := RenderDefaultConfigDump()
	if err != nil {
		t.Fatalf("RenderDefaultConfigDump() error = %v", err)
	}

	assertContainsAll(t, defaultDump, []string{
		`auth.policy.mode = "enforce"`,
		`auth.policy.default_policy = "standard_auth"`,
		`auth.policy.registry_scripts = []`,
		`auth.policy.scheduler_guards = {}`,
	})

	nonDefaultDump, err := RenderNonDefaultConfigDump(viper.AllSettings())
	if err != nil {
		t.Fatalf("RenderNonDefaultConfigDump() error = %v", err)
	}

	assertContainsAll(t, nonDefaultDump, []string{
		`auth.policy.mode = "observe"`,
		`auth.policy.checks[0].name = "brute_force"`,
		`auth.policy.checks[0].skip_if = ["` + testPolicySchedulerGuardTrustedSource + `"]`,
		`auth.policy.scheduler_guards.` + testPolicySchedulerGuardTrustedSource + `.if.attribute = "request.client.ip.trusted"`,
		`auth.policy.scheduler_guards.` + testPolicySchedulerGuardTrustedSource + `.if.is = true`,
		`auth.policy.scheduler_guards.` + testPolicySchedulerGuardTrustedSource + `.on_missing_attribute = "run"`,
		`auth.policy.policies[0].then.fsm_event_marker = "auth.fsm.event.pre_auth_deny"`,
	})
}

func TestAuthPolicyConfigRejectsRemovedSchedulerKeys(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setPolicyConfigTestStorage()
	viper.Set("auth.policy", map[string]any{
		"checks": []any{
			map[string]any{
				"name":               "lua_subject",
				"type":               "lua.subject",
				"stage":              "subject_analysis",
				"when_authenticated": true,
			},
		},
	})

	cfg := &FileSettings{}

	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want removed scheduler key rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy.checks[0]") ||
		!strings.Contains(err.Error(), "when_authenticated") {
		t.Fatalf("HandleFile() error = %q, want removed scheduler key", err)
	}
}

func setPolicyConfigTestStorage() {
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
}
