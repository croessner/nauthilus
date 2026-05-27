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
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

const (
	testLuaBillingAccountLockedAttribute  = "lua.billing.account_locked"
	testPolicyCheckRBLConfigRef           = "auth.controls.rbl"
	testPolicyCheckRBLName                = "rbl"
	testPolicyCheckTLSEncryptionConfigRef = "auth.controls.tls_encryption"
	testPolicyCheckTLSEncryptionName      = "tls_encryption"
	testSchedulerGuardBusinessWindow      = "business_window"
	testSchedulerGuardLocalEndpoint       = "local_endpoint"
	testSchedulerGuardLocalEndpointPath   = "auth.policy.scheduler_guards.local_endpoint.if"
	testSchedulerGuardTrustedSource       = "trusted_source"
	testTrustedClientsNetworkSetRef       = "@network.trusted_clients"
)

func TestCompilerAcceptsNetworkSchedulerGuard(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardTrustedSource: networkSchedulerGuardConfig(),
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	guard, ok := snapshot.SchedulerGuards[testSchedulerGuardTrustedSource]
	if !ok {
		t.Fatal("compiled scheduler guard missing")
	}

	if guard.OnMissingAttribute != "run" {
		t.Fatalf("on_missing_attribute = %q, want run", guard.OnMissingAttribute)
	}

	if guard.Root.Kind != policyruntime.ExprKindAll {
		t.Fatalf("guard root kind = %q, want all", guard.Root.Kind)
	}
}

func TestCompilerAcceptsTimeWindowSchedulerGuard(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardBusinessWindow: timeWindowSchedulerGuardConfig(),
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	guard := snapshot.SchedulerGuards[testSchedulerGuardBusinessWindow]
	if guard.Root.Operator != schedulerGuardOperatorWithinTimeWindow {
		t.Fatalf("guard operator = %q, want within_time_window", guard.Root.Operator)
	}
}

func TestCompilerAcceptsKnownCheckSkipIfGuard(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardTrustedSource: networkSchedulerGuardConfig(),
	}
	cfg.Auth.Policy.Checks[0].SkipIf = []string{testSchedulerGuardTrustedSource}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	check := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Checks[0]
	if len(check.SkipIf) != 1 || check.SkipIf[0] != testSchedulerGuardTrustedSource {
		t.Fatalf("check skip_if = %#v, want trusted_source", check.SkipIf)
	}
}

func TestCompilerRejectsUnknownCheckSkipIfGuard(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.Checks[0].SkipIf = []string{"missing_guard"}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want unknown skip_if guard error")
	}

	if !strings.Contains(err.Error(), "auth.policy.checks[0].skip_if[0]") {
		t.Fatalf("Compile() error = %q, want skip_if path", err)
	}
}

func TestCompilerRejectsCheckProducedSchedulerGuardAttribute(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		"brute_force_bypass": {
			If: config.PolicyConditionConfig{
				Attribute: policy.AttributeBruteForceTriggered,
				Is:        true,
			},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want check-produced attribute rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy.scheduler_guards.brute_force_bypass.if.attribute") {
		t.Fatalf("Compile() error = %q, want scheduler guard attribute path", err)
	}
}

func TestCompilerRejectsLuaProducedSchedulerGuardAttribute(t *testing.T) {
	scriptPath := writeLuaRegistryScript(t, validLuaRegistryScript())
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.RegistryScripts = []string{scriptPath}
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		"lua_bypass": {
			If: config.PolicyConditionConfig{
				Attribute: testLuaBillingAccountLockedAttribute,
				Is:        true,
			},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want Lua-produced attribute rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy.scheduler_guards.lua_bypass.if.attribute") {
		t.Fatalf("Compile() error = %q, want scheduler guard attribute path", err)
	}
}

func TestCompilerRejectsUserControlledOnlySchedulerGuard(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	addRequestAttributeConfigs(cfg)
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		"company_header": {
			If: config.PolicyConditionConfig{
				Attribute: testRequestHeaderAttribute,
				Eq:        "internal",
			},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want user-controlled-only guard rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy.scheduler_guards.company_header.if") {
		t.Fatalf("Compile() error = %q, want scheduler guard condition path", err)
	}
}

func TestCompilerRejectsLocalEndpointOnlySchedulerGuard(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardLocalEndpoint: {
			If: config.PolicyConditionConfig{
				Attribute:    policy.AttributeRequestLocalIP,
				CIDRContains: testTrustedClientsNetworkSetRef,
			},
		},
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want local endpoint only guard rejection")
	}

	if !strings.Contains(err.Error(), testSchedulerGuardLocalEndpointPath) {
		t.Fatalf("Compile() error = %q, want scheduler guard condition path", err)
	}
}

func TestCompilerAcceptsLocalEndpointGuardWithCallerCriterion(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardLocalEndpoint: {
			If: config.PolicyConditionConfig{
				All: []config.PolicyConditionConfig{
					{Attribute: policy.AttributeRequestCallerIPPresent, Is: true},
					{Attribute: policy.AttributeRequestCallerIP, CIDRContains: testTrustedClientsNetworkSetRef},
					{Attribute: policy.AttributeRequestLocalIP, CIDRContains: testTrustedClientsNetworkSetRef},
				},
			},
		},
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if _, ok := snapshot.SchedulerGuards[testSchedulerGuardLocalEndpoint]; !ok {
		t.Fatal("compiled local endpoint scheduler guard missing")
	}
}

func TestCompilerRejectsAfterGuardMismatch(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardTrustedSource: networkSchedulerGuardConfig(),
	}
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		tlsEncryptionCheckWithSkipIf(testSchedulerGuardTrustedSource),
		rblCheckAfter(testPolicyCheckTLSEncryptionName),
	}

	_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err == nil {
		t.Fatal("Compile() error = nil, want after guard compatibility error")
	}

	if !strings.Contains(err.Error(), "auth.policy.checks.rbl.after[0]") {
		t.Fatalf("Compile() error = %q, want dependency path", err)
	}
}

func TestCompilerAcceptsMatchingAfterGuardSets(t *testing.T) {
	cfg := schedulerGuardCompilerConfig()
	cfg.Auth.Policy.SchedulerGuards = map[string]config.PolicySchedulerGuardConfig{
		testSchedulerGuardTrustedSource: networkSchedulerGuardConfig(),
	}
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{
		tlsEncryptionCheckWithSkipIf(testSchedulerGuardTrustedSource),
		rblCheckAfter(testPolicyCheckTLSEncryptionName, testSchedulerGuardTrustedSource),
	}

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	checks := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Checks
	if len(checks) != 2 || checks[0].Name != testPolicyCheckTLSEncryptionName || checks[1].Name != testPolicyCheckRBLName {
		t.Fatalf("ordered checks = %#v, want tls_encryption before rbl", checks)
	}
}

func TestCompilerLeavesExistingConfigWithoutSchedulerGuardsUnchanged(t *testing.T) {
	cfg := policyCompilerTestConfig()

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if len(snapshot.SchedulerGuards) != 0 {
		t.Fatalf("scheduler guards = %#v, want none", snapshot.SchedulerGuards)
	}

	for _, check := range snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Checks {
		if len(check.SkipIf) != 0 {
			t.Fatalf("check %q skip_if = %#v, want none", check.Name, check.SkipIf)
		}
	}
}

func schedulerGuardCompilerConfig() *config.FileSettings {
	cfg := policyCompilerTestConfig()
	cfg.Auth.Policy.Checks = []config.PolicyCheckConfig{rblCheck()}
	cfg.Auth.Policy.Policies = nil

	return cfg
}

func networkSchedulerGuardConfig() config.PolicySchedulerGuardConfig {
	return config.PolicySchedulerGuardConfig{
		If: config.PolicyConditionConfig{
			All: []config.PolicyConditionConfig{
				{Attribute: policy.AttributeRequestClientIPPresent, Is: true},
				{Attribute: policy.AttributeRequestClientIPTrusted, Is: true},
				{Attribute: policy.AttributeRequestClientIP, CIDRContains: testTrustedClientsNetworkSetRef},
			},
		},
	}
}

func timeWindowSchedulerGuardConfig() config.PolicySchedulerGuardConfig {
	return config.PolicySchedulerGuardConfig{
		If: config.PolicyConditionConfig{
			Attribute:        policy.AttributeRequestTime,
			WithinTimeWindow: "@time_window.business_hours",
		},
	}
}

func tlsEncryptionCheckWithSkipIf(skipIf ...string) config.PolicyCheckConfig {
	check := config.PolicyCheckConfig{
		Name:      testPolicyCheckTLSEncryptionName,
		Type:      policy.CheckTypeTLSEncryption,
		Stage:     string(policy.StagePreAuth),
		ConfigRef: testPolicyCheckTLSEncryptionConfigRef,
	}
	check.SkipIf = append([]string(nil), skipIf...)

	return check
}

func rblCheckAfter(after string, skipIf ...string) config.PolicyCheckConfig {
	check := rblCheck()
	check.After = []string{after}
	check.SkipIf = append([]string(nil), skipIf...)

	return check
}

func rblCheck() config.PolicyCheckConfig {
	return config.PolicyCheckConfig{
		Name:      testPolicyCheckRBLName,
		Type:      policy.CheckTypeRBL,
		Stage:     string(policy.StagePreAuth),
		ConfigRef: testPolicyCheckRBLConfigRef,
	}
}
