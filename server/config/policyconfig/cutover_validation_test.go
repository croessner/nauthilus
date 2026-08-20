// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"
)

type cutoverValidationCase struct {
	mutate func(*Document)
	name   string
	path   string
}

func TestPolicyCutoverValidationParity(t *testing.T) {
	tests := cutoverValidationCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validCutoverDocument()
			test.mutate(&document)

			err := Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

// cutoverValidationCases returns one exact-path case for each migrated validation family.
func cutoverValidationCases() []cutoverValidationCase {
	families := [][]cutoverValidationCase{
		cutoverLocalizationValidationCases(),
		cutoverConditionSetValidationCases(),
		cutoverSchedulerGuardValidationCases(),
		cutoverFactSourceValidationCases(),
		cutoverLuaProviderValidationCases(),
		cutoverLuaEffectValidationCases(),
		cutoverProviderReferenceValidationCases(),
	}

	var cases []cutoverValidationCase
	for _, family := range families {
		cases = append(cases, family...)
	}

	return cases
}

// cutoverLocalizationValidationCases covers catalog identity and message validation.
func cutoverLocalizationValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "invalid localization language",
			path: "policy.namespaces.authn.localization.catalogs[0].language",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Localization.Catalogs = []TranslationCatalogConfig{{Namespace: "auth", Language: "en--US", Entries: map[string]string{"deny": "Denied"}}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "duplicate localization catalog",
			path: "policy.namespaces.authn.localization.catalogs[1]",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				catalog := TranslationCatalogConfig{Namespace: "auth", Language: "en", Entries: map[string]string{"deny": "Denied"}}
				authn.Localization.Catalogs = []TranslationCatalogConfig{catalog, catalog}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "blank localization message",
			path: "policy.namespaces.authn.localization.catalogs[0].entries.deny",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Localization.Catalogs = []TranslationCatalogConfig{{Namespace: "auth", Language: "en", Entries: map[string]string{"deny": " "}}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
	}
}

// cutoverConditionSetValidationCases covers typed network, string, and time operands.
func cutoverConditionSetValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "invalid network set entry",
			path: "policy.namespaces.authn.condition_sets.networks.trusted[0]",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.ConditionSets.Networks = map[string][]string{"trusted": {"invalid"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "duplicate string set entry",
			path: "policy.namespaces.authn.condition_sets.strings.services[1]",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.ConditionSets.Strings = map[string][]string{"services": {"imap", "imap"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "invalid time window timezone",
			path: "policy.namespaces.authn.condition_sets.time_windows.office.timezone",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.ConditionSets.TimeWindows = map[string]TimeWindowConfig{"office": {Timezone: "Invalid/Zone", Days: []string{"mon"}, Intervals: []TimeIntervalConfig{{Start: "09:00", End: "17:00"}}}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "invalid time window weekday",
			path: "policy.namespaces.authn.condition_sets.time_windows.office.days[0]",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.ConditionSets.TimeWindows = map[string]TimeWindowConfig{"office": {Timezone: "UTC", Days: []string{"monday"}, Intervals: []TimeIntervalConfig{{Start: "09:00", End: "17:00"}}}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "time interval crosses midnight",
			path: "policy.namespaces.authn.condition_sets.time_windows.office.intervals[0]",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.ConditionSets.TimeWindows = map[string]TimeWindowConfig{"office": {Timezone: "UTC", Days: []string{"mon"}, Intervals: []TimeIntervalConfig{{Start: "17:00", End: "09:00"}}}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
	}
}

// cutoverSchedulerGuardValidationCases covers guard expressions and missing-fact behavior.
func cutoverSchedulerGuardValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "unsupported scheduler guard missing-attribute behavior",
			path: "policy.namespaces.authn.domain_plans.password.scheduler_guards.trusted.on_missing_attribute",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				plan := authn.DomainPlans["password"]
				always := true
				plan.SchedulerGuards = map[string]SchedulerGuardConfig{
					"trusted": {If: ConditionConfig{Always: &always}, OnMissingAttribute: "skip"},
				}
				authn.DomainPlans["password"] = plan
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "invalid scheduler guard condition",
			path: "policy.namespaces.authn.domain_plans.password.scheduler_guards.trusted.if",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				plan := authn.DomainPlans["password"]
				plan.SchedulerGuards = map[string]SchedulerGuardConfig{"trusted": {OnMissingAttribute: "run"}}
				authn.DomainPlans["password"] = plan
				document.Policy.Namespaces["authn"] = authn
			},
		},
	}
}

// cutoverFactSourceValidationCases covers request-source safety and projection bounds.
func cutoverFactSourceValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "unsafe request header",
			path: "policy.namespaces.authn.fact_sources.http_headers[0].header",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.FactSources.HTTPHeaders = []HTTPHeaderFactSourceConfig{{Header: "Authorization", Attribute: "request.header.authorization", Visibility: "public"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "uppercase metadata key",
			path: "policy.namespaces.authn.fact_sources.grpc_metadata[0].key",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.FactSources.GRPCMetadata = []GRPCMetadataFactSourceConfig{{Key: "X-Client", Attribute: "request.metadata.client", Visibility: "public"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "duplicate request fact",
			path: "policy.namespaces.authn.fact_sources.grpc_metadata[0].attribute",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.FactSources.HTTPHeaders = []HTTPHeaderFactSourceConfig{{Header: "X-Client", Attribute: "request.header.client", Visibility: "public"}}
				authn.FactSources.GRPCMetadata = []GRPCMetadataFactSourceConfig{{Key: "x-client", Attribute: "request.header.client", Visibility: "public"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "invalid request normalization",
			path: "policy.namespaces.authn.fact_sources.http_headers[0].normalize.case",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.FactSources.HTTPHeaders = []HTTPHeaderFactSourceConfig{{Header: "X-Client", Attribute: "request.header.client", Visibility: "public", Normalize: NormalizeConfig{Case: "fold"}}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "invalid request visibility",
			path: "policy.namespaces.authn.fact_sources.http_headers[0].visibility",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.FactSources.HTTPHeaders = []HTTPHeaderFactSourceConfig{{Header: "X-Client", Attribute: "request.header.client", Visibility: "secret"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
	}
}

// cutoverLuaProviderValidationCases covers qualified Lua source identities and scripts.
func cutoverLuaProviderValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "Lua environment provider prefix",
			path: "policy.namespaces.authn.providers.shared",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Providers = map[string]ProviderConfig{"shared": {Kind: "lua_environment", ScriptPath: "/tmp/environment.lua"}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "Lua provider script path",
			path: "policy.namespaces.authn.providers.lua_environment_shared.script_path",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				provider := authn.Providers["lua_environment_shared"]
				provider.ScriptPath = ""
				authn.Providers["lua_environment_shared"] = provider
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "reserved Lua environment provider kind",
			path: "policy.namespaces.authn.providers.lua_environment_shared.kind",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				provider := authn.Providers["lua_environment_shared"]
				provider.Kind = "native"
				authn.Providers["lua_environment_shared"] = provider
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "reserved Lua subject provider kind",
			path: "policy.namespaces.authn.providers.lua_subject_shared.kind",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				delete(authn.Providers, "lua_environment_shared")
				authn.Providers["lua_subject_shared"] = ProviderConfig{Kind: "plugin"}
				plan := authn.DomainPlans["password"]
				checkpoint := plan.Checkpoints["pre_auth"]
				checkpoint.Providers[0].Use = "authn/lua_subject_shared"
				plan.Checkpoints["pre_auth"] = checkpoint
				authn.DomainPlans["password"] = plan
				document.Policy.Namespaces["authn"] = authn
			},
		},
	}
}

// cutoverLuaEffectValidationCases covers host-owned Lua action identities and scripts.
func cutoverLuaEffectValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "Lua effect prefix",
			path: "policy.namespaces.authn.effects.security",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Effects = map[string]EffectConfig{"security": {Kind: "lua_action", ActionType: "lua", ScriptPath: "/tmp/action.lua", Execution: executionHostSync}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "Lua effect action type",
			path: "policy.namespaces.authn.effects.lua_action_security.action_type",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Effects = map[string]EffectConfig{"lua_action_security": {Kind: "lua_action", ScriptPath: "/tmp/action.lua", Execution: executionHostSync}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "Lua effect script path",
			path: "policy.namespaces.authn.effects.lua_action_security.script_path",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Effects = map[string]EffectConfig{"lua_action_security": {Kind: "lua_action", ActionType: "lua", Execution: executionHostSync}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
		{
			name: "reserved Lua effect kind",
			path: "policy.namespaces.authn.effects.lua_action_security.kind",
			mutate: func(document *Document) {
				authn := document.Policy.Namespaces["authn"]
				authn.Effects = map[string]EffectConfig{"lua_action_security": {Kind: "obligation", Execution: executionReturnOnly}}
				document.Policy.Namespaces["authn"] = authn
			},
		},
	}
}

// cutoverProviderReferenceValidationCases covers provider identity and schedule resolution.
func cutoverProviderReferenceValidationCases() []cutoverValidationCase {
	return []cutoverValidationCase{
		{
			name: "unsupported observe-safe assertion",
			path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].observe_safe",
			mutate: mutateCutoverProvider(func(provider *ProviderInstanceConfig) {
				enabled := true
				provider.Use = policy.AuthnProviderBruteForce
				provider.ObserveSafe = &enabled
			}),
		},
		{
			name: "unknown configured provider use",
			path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].use",
			mutate: mutateCutoverProvider(func(provider *ProviderInstanceConfig) {
				provider.Use = "authn/missing"
			}),
		},
		{
			name: "unknown provider dependency",
			path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].after[0]",
			mutate: mutateCutoverProvider(func(provider *ProviderInstanceConfig) {
				provider.After = []string{"missing"}
			}),
		},
		{
			name: "absent builtin provider dependency",
			path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].after[0]",
			mutate: mutateCutoverProvider(func(provider *ProviderInstanceConfig) {
				provider.After = []string{"brute_force"}
			}),
		},
		{
			name: "unknown scheduler guard reference",
			path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].skip_if[0]",
			mutate: mutateCutoverProvider(func(provider *ProviderInstanceConfig) {
				provider.SkipIf = []string{"missing"}
			}),
		},
		{
			name:   "unknown required provider",
			path:   "policy.namespaces.authn.policy_sets.configured.rules[0].require_providers[0]",
			mutate: mutateCutoverRequiredProviders("missing"),
		},
		{
			name:   "absent builtin required provider",
			path:   "policy.namespaces.authn.policy_sets.configured.rules[0].require_providers[0]",
			mutate: mutateCutoverRequiredProviders("brute_force"),
		},
	}
}

// mutateCutoverProvider applies one focused mutation to the first configured checkpoint provider.
func mutateCutoverProvider(mutate func(*ProviderInstanceConfig)) func(*Document) {
	return func(document *Document) {
		authn := document.Policy.Namespaces["authn"]
		plan := authn.DomainPlans["password"]
		checkpoint := plan.Checkpoints["pre_auth"]

		mutate(&checkpoint.Providers[0])

		plan.Checkpoints["pre_auth"] = checkpoint
		authn.DomainPlans["password"] = plan
		document.Policy.Namespaces["authn"] = authn
	}
}

// mutateCutoverRequiredProviders replaces the first configured rule's provider requirements.
func mutateCutoverRequiredProviders(requirements ...string) func(*Document) {
	return func(document *Document) {
		authn := document.Policy.Namespaces["authn"]
		set := authn.PolicySets["configured"]

		set.Rules[0].RequireProviders = requirements

		authn.PolicySets["configured"] = set
		document.Policy.Namespaces["authn"] = authn
	}
}

// validCutoverDocument returns the smallest configured authn plan used by parity mutations.
func validCutoverDocument() Document {
	always := true

	return Document{Policy: PolicyConfig{
		Namespaces: map[string]NamespaceConfig{
			"authn": {
				Providers: map[string]ProviderConfig{
					"lua_environment_shared": {
						Kind:       "lua_environment",
						ScriptPath: "/etc/nauthilus/lua/environment/shared.lua",
					},
				},
				DomainPlans: map[string]DomainPlanConfig{
					"password": {
						Checkpoints: map[string]CheckpointConfig{
							"pre_auth": {
								Providers: []ProviderInstanceConfig{{
									Name:    "lua_environment_shared",
									Use:     "authn/lua_environment_shared",
									Actions: []string{"authenticate"},
								}},
							},
						},
					},
				},
				PolicySets: map[string]PolicySetConfig{
					"configured": {
						Rules: []PolicyRuleConfig{{
							Name:             "deny_shared",
							Checkpoint:       "pre_auth",
							Actions:          []string{"authenticate"},
							RequireProviders: []string{"lua_environment_shared"},
							If:               ConditionConfig{Always: &always},
							Then:             ThenConfig{Decision: "deny"},
						}},
					},
				},
			},
		},
		Targets: []TargetConfig{{
			Namespace:     "authn",
			Action:        "authenticate",
			Schema:        "authn/authenticate/v1",
			DomainPlan:    "authn/password",
			DefaultPolicy: standardAuthPolicy,
			Plans: map[string]TargetPlanConfig{
				"pre_auth": {PolicySets: []string{"authn/configured"}},
			},
		}},
	}}
}
