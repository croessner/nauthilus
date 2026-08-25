// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"slices"
	"strings"
	"testing"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const configuredAuthnPlanFixture = `policy:
  namespaces:
    authn:
      providers:
        primary:
          kind: native
          module: test
          targets: [{action: authenticate}]
          executions: [host_sync]
        dependent:
          kind: native
          module: test
          targets: [{action: authenticate}]
          executions: [host_sync]
        lookup_only:
          kind: native
          module: test
          targets: [{action: lookup_identity}]
          executions: [host_sync]
      domain_plans:
        migrated:
          scheduler_guards:
            known_client:
              if: {always: true}
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: dependent
                  use: authn/dependent
                  actions: [authenticate]
                  after: [primary]
                  run_if: {auth_state: unauthenticated}
                  skip_if: [known_client]
                  observe_safe: true
                  output: nauthilus.auth.rbl.threshold_reached
                - name: lookup_only
                  use: authn/lookup_only
                  actions: [lookup_identity]
                - name: tls_default
                  use: authn/builtin/tls_encryption
                  actions: [authenticate]
                - name: primary_alias
                  use: authn/primary
                  actions: [authenticate]
                  after: [primary]
                - name: primary
                  use: authn/primary
                  actions: [authenticate]
                  run_if: {auth_state: any}
                  observe_safe: false
                  output: nauthilus.auth.tls.secure
            auth_decision:
              providers: []
      policy_sets:
        configured:
          rules:
            - name: deny_from_configured_plan
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [dependent]
              if: {always: true}
              then: {decision: deny}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/migrated
      default_policy: authn/standard_auth
      mode: observe
      report:
        enabled: true
        include_fsm: false
        include_checks: true
        include_attributes: true
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`

const sharedAuthnPlanFixture = `policy:
  namespaces:
    authn:
      providers:
        shared:
          kind: native
          module: test
          targets: [{action: authenticate}, {action: lookup_identity}]
          executions: [host_sync]
        auth_only:
          kind: native
          module: test
          targets: [{action: authenticate}]
          executions: [host_sync]
        lookup_only:
          kind: native
          module: test
          targets: [{action: lookup_identity}]
          executions: [host_sync]
      domain_plans:
        migrated:
          checkpoints:
            pre_auth:
              providers:
                - name: auth_only
                  use: authn/auth_only
                  actions: [authenticate]
                  after: [shared]
                - name: lookup_only
                  use: authn/lookup_only
                  actions: [lookup_identity]
                  after: [shared]
                - name: shared
                  use: authn/shared
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/migrated
    - namespace: authn
      action: lookup_identity
      schema: authn/lookup_identity/v1
      domain_plan: authn/migrated
`

const genericRequiredProviderFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1: {facts: []}
      providers:
        primary:
          kind: native
          module: test
          targets: [{action: submit}]
          executions: [host_sync]
          failure: indeterminate
        dependent:
          kind: native
          module: test
          targets: [{action: submit}]
          executions: [host_sync]
          failure: indeterminate
      domain_plans:
        configured:
          checkpoints:
            final_decision:
              providers:
                - {name: primary, use: mail/primary}
                - {name: dependent, use: mail/dependent, after: [primary]}
      policy_sets:
        configured:
          rules:
            - name: require_dependency
              checkpoint: final_decision
              require_providers: [dependent]
              if: {always: true}
              then: {decision: deny}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      domain_plan: mail/configured
      default_policy: mail/configured
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [mail/configured]
`

const canonicalPluginProvidersFixture = `policy:
  namespaces:
    authn:
      providers:
        plugin.example.module.environment:
          kind: plugin
          module: example.module
          targets: [{action: authenticate}]
          executions: [host_sync]
        plugin.example.module.subject.profile:
          kind: plugin
          module: example.module
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        migrated:
          checkpoints:
            pre_auth:
              providers:
                - name: plugin_environment
                  use: authn/plugin.example.module.environment
            subject_analysis:
              providers:
                - name: plugin_subject
                  use: authn/plugin.example.module.subject.profile
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/migrated
`

func TestPolicyCompiledPlanBuiltinAuthnReportDefaults(t *testing.T) {
	input, err := Normalize(context.Background(), decodePolicy(t, "{}"))
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	for _, target := range builtinAuthnTargets {
		compiled := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(target.action))

		report := compiled.Report()
		if report.Enabled() || !report.IncludeFSM() || !report.IncludeChecks() || report.IncludeAttributes() {
			t.Fatalf("%s report defaults = %#v, want disabled with FSM and checks", target.action, report)
		}
	}
}

func TestPolicyCompiledPlanConfiguredAuthnReplacesOnlySelectedBuiltinPlan(t *testing.T) {
	input, err := Normalize(context.Background(), decodePolicy(t, configuredAuthnPlanFixture))
	requireNoError(t, err)

	instances := input.Policy.Namespaces[policy.AuthnNamespace].DomainPlans["migrated"].Checkpoints["pre_auth"].Providers
	if !slices.Equal(instances[0].Actions, []string{string(policy.OperationAuthenticate)}) {
		t.Fatalf("normalized provider actions = %v, want authenticate applicability", instances[0].Actions)
	}

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	authenticate := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))
	assertConfiguredAuthnActivation(t, authenticate)
	assertConfiguredAuthnPreAuth(t, authenticate)
	assertUnconfiguredBuiltinAuthnTargets(t, catalog)
}

func TestPolicyCompiledPlanOrdersEveryAuthnCheckpointDeterministically(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    authn:
      domain_plans:
        migrated:
          checkpoints:
            auth_decision: {providers: []}
            account_provider: {providers: []}
            subject_analysis: {providers: []}
            auth_backend: {providers: []}
            pre_auth: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/migrated
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	authenticate := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))

	want := []string{"pre_auth", "auth_backend", "subject_analysis", "account_provider", "auth_decision"}
	if got := checkpointNames(authenticate.DomainPlan().Checkpoints()); !slices.Equal(got, want) {
		t.Fatalf("authn checkpoints = %v, want %v", got, want)
	}
}

func TestPolicyCompiledPlanFiltersSharedAuthnPlanProvidersByTargetAction(t *testing.T) {
	document := decodePolicy(t, sharedAuthnPlanFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	tests := []struct {
		action string
		want   []string
	}{
		{action: string(policy.OperationAuthenticate), want: []string{"authn/plugin.test.shared", "authn/plugin.test.auth_only"}},
		{action: string(policy.OperationLookupIdentity), want: []string{"authn/plugin.test.shared", "authn/plugin.test.lookup_only"}},
	}

	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			target := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, test.action)

			checkpoint, ok := target.DomainPlan().Checkpoint("pre_auth")
			if !ok {
				t.Fatal("configured pre_auth checkpoint is missing")
			}

			if got := checkpoint.ProviderIDs(); !slices.Equal(got, test.want) {
				t.Fatalf("%s providers = %v, want %v", test.action, got, test.want)
			}
		})
	}
}

func TestPolicyCompiledPlanRetainsGenericRequiredProviderInstanceNames(t *testing.T) {
	document := decodePolicy(t, genericRequiredProviderFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	target := lookupCompiledTarget(t, catalog, "mail", "submit")

	configured, ok := target.LookupPolicySet(mustPolicySetID(t, "mail", "configured"))
	if !ok || len(configured.Rules()) != 1 {
		t.Fatalf("configured compiled rules = %d, want 1", len(configured.Rules()))
	}

	if got := configured.Rules()[0].RequiredProviders(); !slices.Equal(got, []string{"dependent"}) {
		t.Fatalf("generic required providers = %v, want configured instance name", got)
	}
}

func TestPolicyCompiledPlanResolvesBuiltinRequiredProviderWithoutConfiguredDomainPlan(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: deny_brute_force
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [brute_force]
              if: {always: true}
              then: {decision: deny}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	authenticate := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))

	configured, ok := authenticate.LookupPolicySet(mustPolicySetID(t, policy.AuthnNamespace, "configured"))
	if !ok || len(configured.Rules()) != 1 {
		t.Fatalf("configured compiled rules = %d, want 1", len(configured.Rules()))
	}

	if got := configured.Rules()[0].RequiredProviders(); !slices.Equal(got, []string{policy.AuthnProviderBruteForce}) {
		t.Fatalf("required providers = %v, want exact builtin brute-force identity", got)
	}
}

func TestPolicyCompiledPlanRejectsMixedConfiguredAndBuiltinRequirementIdentity(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    authn:
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: rbl, use: authn/builtin/rbl}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          rules:
            - name: shared_rbl_requirement
              checkpoint: pre_auth
              actions: [authenticate, lookup_identity]
              require_providers: [rbl]
              if: {always: true}
              then: {decision: deny}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      plans:
        pre_auth:
          policy_sets: [authn/configured]
    - namespace: authn
      action: lookup_identity
      schema: authn/lookup_identity/v1
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`)

	_, err := Normalize(context.Background(), document)
	if err == nil {
		t.Fatal("Normalize() accepted one rule with incompatible configured and builtin requirement identities")
	}

	wantPath := "policy.namespaces.authn.policy_sets.configured.rules[0].require_providers[0]"
	if !strings.HasPrefix(err.Error(), wantPath+":") || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("Normalize() error = %q, want incompatible requirement at %s", err, wantPath)
	}
}

func TestPolicyCompiledPlanRejectsUnavailableBuiltinRequiredProvider(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: invalid_tls_dependency
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [tls_encryption]
              if: {always: true}
              then: {decision: deny}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`)

	_, err := Normalize(context.Background(), document)
	if err == nil {
		t.Fatal("Normalize() accepted a builtin requirement absent from the target checkpoint")
	}

	wantPath := "policy.namespaces.authn.policy_sets.configured.rules[0].require_providers[0]"
	if !strings.HasPrefix(err.Error(), wantPath+":") {
		t.Fatalf("Normalize() error = %q, want path %q", err, wantPath)
	}
}

func TestPolicyCompiledPlanPluginProvidersUseCanonicalIdentities(t *testing.T) {
	document := decodePolicy(t, canonicalPluginProvidersFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	authenticate := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))
	tests := []struct {
		checkpoint string
		want       string
	}{
		{checkpoint: "pre_auth", want: "authn/plugin.example.module.environment"},
		{checkpoint: "subject_analysis", want: "authn/plugin.example.module.subject.profile"},
	}

	for _, test := range tests {
		checkpoint, ok := authenticate.DomainPlan().Checkpoint(test.checkpoint)
		if !ok {
			t.Fatalf("configured checkpoint %s is missing", test.checkpoint)
		}

		if got := checkpoint.ProviderIDs(); !slices.Equal(got, []string{test.want}) {
			t.Fatalf("%s providers = %v, want %s", test.checkpoint, got, test.want)
		}

		if _, ok := authenticate.LookupProvider(test.want); !ok {
			t.Fatalf("compiled provider definition %s is missing", test.want)
		}
	}
}

func TestPolicyCompiledPlanRejectsMissingCanonicalPluginProvider(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    authn:
      domain_plans:
        migrated:
          checkpoints:
            pre_auth:
              providers:
                - name: missing_plugin
                  use: authn/plugin.example.module.environment
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/migrated
`)

	_, err := Normalize(context.Background(), document)
	if err == nil {
		t.Fatal("Normalize() accepted a canonical plugin use without a provider definition")
	}

	wantPath := "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[0].use"
	if !strings.HasPrefix(err.Error(), wantPath+":") {
		t.Fatalf("Normalize() error = %q, want path %q", err, wantPath)
	}
}

func TestPolicyCompiledPlanRejectsInvalidPluginProviderDefinitions(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantPath string
	}{
		{
			name: "embedded module mismatch",
			provider: `plugin.example.module.environment:
          kind: plugin
          module: another.module
          targets: [{action: authenticate}]
          executions: [host_sync]`,
			wantPath: "policy.namespaces.authn.providers.plugin.example.module.environment.module",
		},
		{
			name: "noncanonical module",
			provider: `plugin.example.module.environment:
          kind: plugin
          module: Example.Module
          targets: [{action: authenticate}]
          executions: [host_sync]`,
			wantPath: "policy.namespaces.authn.providers.plugin.example.module.environment.module",
		},
		{
			name: "dotted non-plugin provider",
			provider: `native.example.environment:
          kind: native
          targets: [{action: authenticate}]
          executions: [host_sync]`,
			wantPath: "policy.namespaces.authn.providers.native.example.environment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertPolicyNormalizeFailsAtPath(t, invalidPluginProviderFixture(test.provider), test.wantPath)
		})
	}
}

func TestPolicyCompiledPlanRejectsInvalidProviderInstanceDependencies(t *testing.T) {
	tests := []struct {
		name      string
		providers string
		wantPath  string
	}{
		{
			name: "duplicate instance name",
			providers: `
                - {name: repeated, use: authn/primary}
                - {name: repeated, use: authn/dependent}`,
			wantPath: "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[1].name",
		},
		{
			name: "unknown after dependency",
			providers: `
                - {name: primary, use: authn/primary, after: [missing]}`,
			wantPath: "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[0].after[0]",
		},
		{
			name: "absent builtin after dependency",
			providers: `
                - {name: primary, use: authn/primary, after: [brute_force]}`,
			wantPath: "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[0].after[0]",
		},
		{
			name: "cyclic after dependency",
			providers: `
                - {name: primary, use: authn/primary, after: [dependent]}
                - {name: dependent, use: authn/dependent, after: [primary]}`,
			wantPath: "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[1].after[0]",
		},
		{
			name: "run-if incompatible dependency",
			providers: `
                - {name: primary, use: authn/primary, run_if: {auth_state: authenticated}}
                - {name: dependent, use: authn/dependent, run_if: {auth_state: unauthenticated}, after: [primary]}`,
			wantPath: "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[1].after[0]",
		},
		{
			name: "scheduler-guard incompatible dependency",
			providers: `
                - {name: primary, use: authn/primary, skip_if: [trusted]}
                - {name: dependent, use: authn/dependent, after: [primary]}`,
			wantPath: "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[1].after[0]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertPolicyNormalizeFailsAtPath(t, invalidProviderDependenciesFixture(test.providers), test.wantPath)
		})
	}
}

func TestPolicyCompiledPlanLuaActionsUseImmutableHostProviders(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    authn:
      effects:
        lua_action_security:
          kind: lua_action
          action_type: lua
          script_path: /etc/nauthilus/lua/security.lua
          execution: host_sync
        lua_action_audit:
          kind: lua_action
          action_type: post
          script_path: /etc/nauthilus/lua/audit.lua
          execution: host_post_action
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	syncEffect := findEffect(t, input, "authn/lua_action_security")
	if syncEffect.Provider() != "authn/lua_action" {
		t.Fatalf("sync Lua action provider = %q, want immutable authn/lua_action", syncEffect.Provider())
	}

	postEffect := findEffect(t, input, "authn/lua_action_audit")
	if postEffect.Provider() != "authn/post_action" {
		t.Fatalf("post Lua action provider = %q, want immutable authn/post_action", postEffect.Provider())
	}

	_, err = input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)
}

// assertConfiguredAuthnActivation verifies target-level configured-plan metadata.
func assertConfiguredAuthnActivation(t *testing.T, target policyruntime.CompiledTarget) {
	t.Helper()

	if target.AuthorityMode() != registry.AuthorityModeObserve {
		t.Fatalf("authenticate mode = %q, want observe", target.AuthorityMode())
	}

	if got := target.DefaultPolicySet().String(); got != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("authenticate default = %q, want %q", got, registry.BuiltinStandardAuthPolicySet)
	}

	if got := checkpointNames(target.DomainPlan().Checkpoints()); !slices.Equal(got, []string{"pre_auth", "auth_decision"}) {
		t.Fatalf("authenticate checkpoints = %v, want [pre_auth auth_decision]", got)
	}

	guard, ok := target.DomainPlan().SchedulerGuard("known_client")
	if !ok {
		t.Fatal("configured scheduler guard is missing")
	}

	if guard.Expression().Kind() != registry.ExpressionKindAlways || guard.OnMissingAttribute() != "run" {
		t.Fatalf("compiled scheduler guard = %#v, want normalized always/run contract", guard)
	}

	if got := guard.Path(); got != "policy.namespaces.authn.domain_plans.migrated.scheduler_guards.known_client" {
		t.Fatalf("compiled scheduler guard path = %q", got)
	}

	report := target.Report()

	gotReport := []bool{report.Enabled(), report.IncludeFSM(), report.IncludeChecks(), report.IncludeAttributes()}
	if !slices.Equal(gotReport, []bool{true, true, true, true}) {
		t.Fatalf("compiled target report = %#v, want legacy-compatible FSM/check defaults", report)
	}
}

// assertConfiguredAuthnPreAuth verifies the compiled checkpoint schedule and policy bindings.
func assertConfiguredAuthnPreAuth(t *testing.T, target policyruntime.CompiledTarget) {
	t.Helper()

	preAuth, ok := target.DomainPlan().Checkpoint("pre_auth")
	if !ok {
		t.Fatal("configured pre_auth checkpoint is missing")
	}

	wantProviders := []string{
		"authn/plugin.test.primary",
		"authn/plugin.test.dependent",
		policy.AuthnProviderTLSEncryption,
		"authn/plugin.test.primary",
	}
	if got := preAuth.ProviderIDs(); !slices.Equal(got, wantProviders) {
		t.Fatalf("pre_auth providers = %v, want stable dependency order %v", got, wantProviders)
	}

	wantLevels := [][]string{{"primary", "tls_default"}, {"dependent", "primary_alias"}}
	if got := preAuth.ProviderLevels(); !equalProviderLevels(got, wantLevels) {
		t.Fatalf("pre_auth provider levels = %v, want %v", got, wantLevels)
	}

	assertCompiledProviderInstances(t, preAuth)

	if got := preAuth.PolicySetIDs(); !slices.Equal(got, []string{"authn/configured", registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("pre_auth policy sets = %v, want configured authority before standard fallback", got)
	}

	if got := preAuth.ProductionPolicySetIDs(); !slices.Equal(got, []string{registry.BuiltinStandardAuthPolicySet}) {
		t.Fatalf("observe production sets = %v, want only standard fallback", got)
	}

	if got := preAuth.ComparisonPolicySetIDs(); !slices.Equal(got, []string{"authn/configured"}) {
		t.Fatalf("observe comparison sets = %v, want configured set", got)
	}

	configured, ok := target.LookupPolicySet(mustPolicySetID(t, "authn", "configured"))
	if !ok || len(configured.Rules()) != 1 {
		t.Fatalf("configured compiled rules = %d, want 1", len(configured.Rules()))
	}

	if got := configured.Rules()[0].RequiredProviders(); !slices.Equal(got, []string{"dependent"}) {
		t.Fatalf("required providers = %v, want configured provider instance name", got)
	}
}

// assertUnconfiguredBuiltinAuthnTargets proves the configured plan changes only its selected target.
func assertUnconfiguredBuiltinAuthnTargets(t *testing.T, catalog *policyruntime.TargetCatalog) {
	t.Helper()

	lookup := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationLookupIdentity))

	lookupPreAuth, ok := lookup.DomainPlan().Checkpoint("pre_auth")
	if !ok {
		t.Fatal("unconfigured lookup_identity pre_auth checkpoint is missing")
	}

	wantLookup := []string{policy.AuthnProviderEnvironment, policy.AuthnProviderTLSEncryption, policy.AuthnProviderRBL}
	if got := lookupPreAuth.ProviderIDs(); !slices.Equal(got, wantLookup) {
		t.Fatalf("lookup_identity providers = %v, want unaffected builtin %v", got, wantLookup)
	}

	list := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationListAccounts))

	listDecision, ok := list.DomainPlan().Checkpoint("auth_decision")
	if !ok {
		t.Fatal("unconfigured list_accounts auth_decision checkpoint is missing")
	}

	if got := listDecision.ProviderIDs(); !slices.Equal(got, []string{policy.AuthnProviderAccount}) {
		t.Fatalf("list_accounts providers = %v, want unaffected builtin account provider", got)
	}
}

// invalidPluginProviderFixture embeds one provider definition in a minimal standalone policy.
func invalidPluginProviderFixture(provider string) string {
	return `policy:
  namespaces:
    authn:
      providers:
        ` + provider + `
`
}

// invalidProviderDependenciesFixture embeds one checkpoint provider list in a compilable authn policy.
func invalidProviderDependenciesFixture(providers string) string {
	return `policy:
  namespaces:
    authn:
      providers:
        primary: {kind: native, module: test, targets: [{action: authenticate}], executions: [host_sync]}
        dependent: {kind: native, module: test, targets: [{action: authenticate}], executions: [host_sync]}
      domain_plans:
        migrated:
          scheduler_guards:
            trusted: {if: {always: true}}
          checkpoints:
            pre_auth:
              providers:` + providers + `
            auth_decision:
              providers: []
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/migrated
`
}

// assertPolicyNormalizeFailsAtPath verifies one invalid fixture against its exact authority path.
func assertPolicyNormalizeFailsAtPath(t *testing.T, source string, wantPath string) {
	t.Helper()

	document := decodePolicy(t, source)

	_, err := Normalize(context.Background(), document)
	if err == nil {
		t.Fatal("Normalize() accepted an invalid standalone policy")
	}

	if !strings.HasPrefix(err.Error(), wantPath+":") {
		t.Fatalf("Normalize() error = %q, want path %q", err, wantPath)
	}
}

// lookupCompiledTarget resolves one compiled target by exact namespace and action.
func lookupCompiledTarget(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	namespace string,
	action string,
) policyruntime.CompiledTarget {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	requireNoError(t, err)

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatalf("compiled target %s/%s not found", namespace, action)
	}

	return compiled
}

// checkpointNames projects checkpoint identities without exposing runtime internals.
func checkpointNames(checkpoints []policyruntime.CompiledCheckpoint) []string {
	names := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		names = append(names, checkpoint.Name())
	}

	return names
}

// equalProviderLevels compares deterministic provider execution layers.
func equalProviderLevels(left [][]string, right [][]string) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if !slices.Equal(left[index], right[index]) {
			return false
		}
	}

	return true
}

type providerInstanceSnapshot struct {
	name                string
	use                 string
	actions             string
	after               string
	runIfAuthState      string
	skipIf              string
	output              string
	path                string
	observeSafe         bool
	observeSafeAuthored bool
}

// assertCompiledProviderInstances proves complete metadata retention without joining instances by provider use.
func assertCompiledProviderInstances(t *testing.T, checkpoint policyruntime.CompiledCheckpoint) {
	t.Helper()

	want := []providerInstanceSnapshot{
		{
			name: "primary", use: "authn/plugin.test.primary", actions: "authenticate", runIfAuthState: policy.RunIfAny,
			output:              policy.AuthnFactTLSSecure,
			path:                "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[4]",
			observeSafeAuthored: true,
		},
		{
			name: "dependent", use: "authn/plugin.test.dependent", actions: "authenticate", after: "primary",
			runIfAuthState: "unauthenticated", skipIf: "known_client", output: policy.AuthnFactRBLThresholdReached,
			path:        "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[0]",
			observeSafe: true, observeSafeAuthored: true,
		},
		{
			name: "tls_default", use: policy.AuthnProviderTLSEncryption, actions: "authenticate",
			runIfAuthState: policy.RunIfAny,
			path:           "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[2]",
			observeSafe:    true,
		},
		{
			name: "primary_alias", use: "authn/plugin.test.primary", actions: "authenticate", after: "primary",
			runIfAuthState: policy.RunIfAny,
			path:           "policy.namespaces.authn.domain_plans.migrated.checkpoints.pre_auth.providers[3]",
		},
	}
	got := providerInstanceSnapshots(checkpoint.ProviderInstances())

	if !slices.Equal(got, want) {
		t.Fatalf("compiled provider instances = %#v, want complete metadata %#v", got, want)
	}
}

// providerInstanceSnapshots projects every retained field into one comparable test oracle.
func providerInstanceSnapshots(instances []policyruntime.CompiledProviderInstance) []providerInstanceSnapshot {
	snapshots := make([]providerInstanceSnapshot, 0, len(instances))

	for _, instance := range instances {
		snapshots = append(snapshots, providerInstanceSnapshot{
			name:                instance.Name(),
			use:                 instance.Use(),
			actions:             strings.Join(instance.Actions(), ","),
			after:               strings.Join(instance.After(), ","),
			runIfAuthState:      instance.RunIfAuthState(),
			skipIf:              strings.Join(instance.SkipIf(), ","),
			output:              instance.Output(),
			path:                instance.Path(),
			observeSafe:         instance.ObserveSafe(),
			observeSafeAuthored: instance.ObserveSafeAuthored(),
		})
	}

	return snapshots
}

// mustPolicySetID constructs one exact set identity for compiled lookup assertions.
func mustPolicySetID(t *testing.T, namespace string, name string) registry.PolicySetID {
	t.Helper()

	identity, err := registry.NewPolicySetID(namespace, name)
	requireNoError(t, err)

	return identity
}

// findEffect resolves one normalized configured effect by exact identity.
func findEffect(t *testing.T, input UnifiedPolicyInput, identity string) registry.EffectDefinition {
	t.Helper()

	_, effect := findProviderAndEffectOptional(input, "", identity)
	if effect.ID() == "" {
		t.Fatalf("normalized effect %s not found", identity)
	}

	return effect
}
