// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
)

type migrationEvidenceClass uint8

const (
	migrationEvidenceActualCatalog migrationEvidenceClass = iota + 1
	migrationEvidenceNormalizedSource
	migrationEvidenceTestOwnedSchemaSource
)

type migrationEvidenceField uint8

const (
	migrationFieldMode migrationEvidenceField = iota + 1
	migrationFieldDefaultPolicy
	migrationFieldLocalization
	migrationFieldNetworks
	migrationFieldStrings
	migrationFieldTimeWindows
	migrationFieldSchedulerGuards
	migrationFieldReport
	migrationFieldLuaEnvironment
	migrationFieldLuaSubject
	migrationFieldLuaEffect
	migrationFieldRegistryScripts
	migrationFieldHTTPHeaders
	migrationFieldGRPCMetadata
	migrationFieldBackendAttributes
	migrationFieldChecks
	migrationFieldRules
)

type migrationInvalidMutation uint8

const (
	migrationInvalidMode migrationInvalidMutation = iota + 1
	migrationInvalidDefaultPolicy
	migrationInvalidLocalization
	migrationInvalidNetworks
	migrationInvalidStrings
	migrationInvalidTimeWindows
	migrationInvalidSchedulerGuard
	migrationInvalidReport
	migrationInvalidLuaEnvironment
	migrationInvalidLuaSubject
	migrationInvalidLuaEffect
	migrationInvalidRegistryScript
	migrationInvalidHTTPHeader
	migrationInvalidGRPCMetadata
	migrationInvalidBackendAttribute
	migrationInvalidCheck
	migrationInvalidRule
)

// policyMigrationContractCase freezes one manually authored old/new mapping family.
type policyMigrationContractCase struct {
	canonicalValue                 any
	legacyValue                    any
	expectedEvidenceValue          any
	expectedDefaultOrIdentityValue any
	name                           string
	oldPath                        string
	oldInput                       string
	legacyEvidencePath             string
	newInput                       string
	expectedPath                   string
	expectedDefaultOrIdentity      string
	validationRule                 string
	canonicalPath                  string
	authorityPath                  string
	expectedErrorPath              string
	secretPath                     string
	secretPlaintext                string
	evidenceClass                  migrationEvidenceClass
	evidenceField                  migrationEvidenceField
	invalidMutation                migrationInvalidMutation
}

// nestedMigrationRule freezes one nested spelling change in the manual contract.
type nestedMigrationRule struct {
	oldField string
	newField string
	rule     string
}

var policyMigrationContractCases = []policyMigrationContractCase{
	{
		name:    "mode",
		oldPath: "auth.policy.mode",
		oldInput: `auth:
  policy:
    mode: observe
`,
		legacyEvidencePath: "auth.policy.mode",
		legacyValue:        "observe",
		newInput: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      mode: observe
`,
		expectedPath:                   "policy.targets[].mode",
		expectedDefaultOrIdentity:      "Default `enforce`; copy the old value to every migrated authn target.",
		validationRule:                 "Only `enforce` and `observe` are valid authn target modes.",
		canonicalPath:                  "policy.targets[0].mode",
		authorityPath:                  "policy.targets[].mode",
		canonicalValue:                 "observe",
		expectedEvidenceValue:          "observe",
		expectedDefaultOrIdentityValue: "enforce",
		expectedErrorPath:              "policy.targets[0].mode",
		evidenceClass:                  migrationEvidenceActualCatalog,
		evidenceField:                  migrationFieldMode,
		invalidMutation:                migrationInvalidMode,
	},
	{
		name:    "default policy",
		oldPath: "auth.policy.default_policy",
		oldInput: `auth:
  policy:
    default_policy: standard_auth
`,
		legacyEvidencePath: "auth.policy.default_policy",
		legacyValue:        "standard_auth",
		newInput: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: authn/standard_auth
`,
		expectedPath:                   "policy.targets[].default_policy",
		expectedDefaultOrIdentity:      "The only builtin fallback identity is `authn/standard_auth`.",
		validationRule:                 "The unqualified `standard_auth` spelling is rejected.",
		canonicalPath:                  "policy.targets[0].default_policy",
		authorityPath:                  "policy.targets[].default_policy",
		canonicalValue:                 "authn/standard_auth",
		expectedEvidenceValue:          "authn/standard_auth",
		expectedDefaultOrIdentityValue: "authn/standard_auth",
		expectedErrorPath:              "policy.targets[0].default_policy",
		evidenceClass:                  migrationEvidenceActualCatalog,
		evidenceField:                  migrationFieldDefaultPolicy,
		invalidMutation:                migrationInvalidDefaultPolicy,
	},
	{
		name:    "localization catalogs",
		oldPath: "auth.policy.localization.catalogs",
		oldInput: `auth:
  policy:
    localization:
      catalogs:
        - namespace: login
          language: en
          entries: {denied: Access denied}
`,
		newInput: `policy:
  namespaces:
    authn:
      localization:
        catalogs:
          - namespace: login
            language: en
            entries: {denied: Access denied}
`,
		legacyEvidencePath:             "auth.policy.localization.catalogs[0].entries.denied",
		legacyValue:                    "Access denied",
		expectedPath:                   "policy.namespaces.authn.localization.catalogs",
		expectedDefaultOrIdentity:      "Default empty; the translation namespace remains distinct from `authn`.",
		validationRule:                 "Every catalog requires a namespace, language, and entries map.",
		canonicalPath:                  "policy.namespaces.authn.localization.catalogs[0].entries.denied",
		authorityPath:                  "policy.namespaces.<name>.localization.catalogs[].entries.<name>",
		canonicalValue:                 "Access denied",
		expectedEvidenceValue:          "Access denied",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.localization.catalogs[0].language",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldLocalization,
		invalidMutation:                migrationInvalidLocalization,
	},
	{
		name:    "network condition sets",
		oldPath: "auth.policy.sets.networks",
		oldInput: `auth:
  policy:
    sets:
      networks:
        trusted: [10.0.0.0/8]
`,
		legacyEvidencePath: "auth.policy.sets.networks.trusted[0]",
		legacyValue:        "10.0.0.0/8",
		newInput: `policy:
  namespaces:
    authn:
      condition_sets:
        networks:
          trusted: [10.0.0.0/8]
`,
		expectedPath:                   "policy.namespaces.authn.condition_sets.networks",
		expectedDefaultOrIdentity:      "Default empty; `@network.<name>` references retain their meaning.",
		validationRule:                 "Network sets remain namespace-owned operands of the compiled source policy set.",
		canonicalPath:                  "policy.namespaces.authn.condition_sets.networks.trusted[0]",
		authorityPath:                  "policy.namespaces.<name>.condition_sets.networks.<name>[]",
		canonicalValue:                 "10.0.0.0/8",
		expectedEvidenceValue:          "10.0.0.0/8",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.condition_sets.networks.trusted[0]",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldNetworks,
		invalidMutation:                migrationInvalidNetworks,
	},
	{
		name:    "string condition sets",
		oldPath: "auth.policy.sets.strings",
		oldInput: `auth:
  policy:
    sets:
      strings:
        privileged: [admin]
`,
		legacyEvidencePath: "auth.policy.sets.strings.privileged[0]",
		legacyValue:        "admin",
		newInput: `policy:
  namespaces:
    authn:
      condition_sets:
        strings:
          privileged: [admin]
`,
		expectedPath:                   "policy.namespaces.authn.condition_sets.strings",
		expectedDefaultOrIdentity:      "Default empty; `@string.<name>` references retain their meaning.",
		validationRule:                 "String sets remain namespace-owned operands of the compiled source policy set.",
		canonicalPath:                  "policy.namespaces.authn.condition_sets.strings.privileged[0]",
		authorityPath:                  "policy.namespaces.<name>.condition_sets.strings.<name>[]",
		canonicalValue:                 "admin",
		expectedEvidenceValue:          "admin",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.condition_sets.strings.privileged[1]",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldStrings,
		invalidMutation:                migrationInvalidStrings,
	},
	{
		name:    "time-window condition sets",
		oldPath: "auth.policy.sets.time_windows",
		oldInput: `auth:
  policy:
    sets:
      time_windows:
        office:
          timezone: Europe/Berlin
          days: [Mon]
          intervals: [{start: "08:00", end: "18:00"}]
`,
		legacyEvidencePath: "auth.policy.sets.time_windows.office.timezone",
		legacyValue:        "Europe/Berlin",
		newInput: `policy:
  namespaces:
    authn:
      condition_sets:
        time_windows:
          office:
            timezone: Europe/Berlin
            days: [Mon]
            intervals: [{start: "08:00", end: "18:00"}]
`,
		expectedPath:                   "policy.namespaces.authn.condition_sets.time_windows",
		expectedDefaultOrIdentity:      "Default empty; `@time_window.<name>` references retain their meaning.",
		validationRule:                 "Each configured interval requires non-empty `start` and `end` values.",
		canonicalPath:                  "policy.namespaces.authn.condition_sets.time_windows.office.timezone",
		authorityPath:                  "policy.namespaces.<name>.condition_sets.time_windows.<name>.timezone",
		canonicalValue:                 "Europe/Berlin",
		expectedEvidenceValue:          "Europe/Berlin",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.condition_sets.time_windows.office.timezone",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldTimeWindows,
		invalidMutation:                migrationInvalidTimeWindows,
	},
	{
		name:    "scheduler guards",
		oldPath: "auth.policy.scheduler_guards",
		oldInput: `auth:
  policy:
    scheduler_guards:
      known_client:
        if: {always: true}
        on_missing_attribute: run
`,
		legacyEvidencePath: "auth.policy.scheduler_guards.known_client.on_missing_attribute",
		legacyValue:        "run",
		newInput: `policy:
  namespaces:
    authn:
      domain_plans:
        password:
          scheduler_guards:
            known_client:
              if: {always: true}
              on_missing_attribute: run
`,
		expectedPath:                   "policy.namespaces.authn.domain_plans.<plan>.scheduler_guards",
		expectedDefaultOrIdentity:      "Default empty; guards are visible only inside their exact domain plan.",
		validationRule:                 "`on_missing_attribute` is omitted or exactly `run`, preserving the legacy compiler contract.",
		canonicalPath:                  "policy.namespaces.authn.domain_plans.password.scheduler_guards.known_client.on_missing_attribute",
		authorityPath:                  "policy.namespaces.<name>.domain_plans.<name>.scheduler_guards.<name>.on_missing_attribute",
		canonicalValue:                 "run",
		expectedEvidenceValue:          "run",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.domain_plans.password.scheduler_guards.known_client.on_missing_attribute",
		evidenceClass:                  migrationEvidenceActualCatalog,
		evidenceField:                  migrationFieldSchedulerGuards,
		invalidMutation:                migrationInvalidSchedulerGuard,
	},
	{
		name:    "report settings",
		oldPath: "auth.policy.report",
		oldInput: `auth:
  policy:
    report:
      enabled: true
      include_attributes: true
`,
		legacyEvidencePath: "auth.policy.report.include_attributes",
		legacyValue:        true,
		newInput: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      report:
        enabled: true
        include_fsm: true
        include_checks: true
        include_attributes: true
`,
		expectedPath:                   "policy.targets[].report",
		expectedDefaultOrIdentity:      "Defaults are `enabled: false`, `include_fsm: true`, `include_checks: true`, and `include_attributes: false`.",
		validationRule:                 "Authn-only report detail fields are rejected on non-authn targets.",
		canonicalPath:                  "policy.targets[0].report.include_attributes",
		authorityPath:                  "policy.targets[].report.include_attributes",
		canonicalValue:                 true,
		expectedEvidenceValue:          true,
		expectedDefaultOrIdentityValue: reportMeaning{Enabled: false, IncludeFSM: true, IncludeChecks: true, IncludeAttributes: false},
		expectedErrorPath:              "policy.targets[0].report.include_fsm",
		evidenceClass:                  migrationEvidenceActualCatalog,
		evidenceField:                  migrationFieldReport,
		invalidMutation:                migrationInvalidReport,
	},
	{
		name:    "Lua environment providers",
		oldPath: "auth.policy.attribute_sources.lua.environment",
		oldInput: `auth:
  policy:
    attribute_sources:
      lua:
        environment:
          - name: risk
            script_path: /etc/nauthilus/lua/risk.lua
`,
		legacyEvidencePath: "auth.policy.attribute_sources.lua.environment[0].name",
		legacyValue:        "risk",
		newInput: `policy:
  namespaces:
    authn:
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: /etc/nauthilus/lua/risk.lua
          secrets:
            token: environment-provider-secret
`,
		expectedPath:                   "policy.namespaces.authn.providers.lua_environment_<old-name>",
		expectedDefaultOrIdentity:      "The exact provider identity is `authn/lua_environment_<old-name>`.",
		validationRule:                 "The provider kind is `lua_environment`; strict production decoding accepts only the canonical `script_path` field, which production validation requires to be non-empty; file/source resolvability belongs to candidate compilation.",
		canonicalPath:                  "policy.namespaces.authn.providers.lua_environment_risk.kind",
		authorityPath:                  "policy.namespaces.<name>.providers.<name>.kind",
		canonicalValue:                 "lua_environment",
		expectedEvidenceValue:          "authn/lua_environment_risk",
		expectedDefaultOrIdentityValue: "authn/lua_environment_risk",
		expectedErrorPath:              "policy.namespaces.authn.providers.lua_environment_risk.script_path",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldLuaEnvironment,
		invalidMutation:                migrationInvalidLuaEnvironment,
		secretPath:                     "policy.namespaces.authn.providers.lua_environment_risk.secrets.token",
		secretPlaintext:                "environment-provider-secret",
	},
	{
		name:    "Lua subject providers",
		oldPath: "auth.policy.attribute_sources.lua.subject",
		oldInput: `auth:
  policy:
    attribute_sources:
      lua:
        subject:
          - name: risk
            script_path: /etc/nauthilus/lua/subject-risk.lua
`,
		legacyEvidencePath: "auth.policy.attribute_sources.lua.subject[0].name",
		legacyValue:        "risk",
		newInput: `policy:
  namespaces:
    authn:
      providers:
        lua_subject_risk:
          kind: lua_subject
          script_path: /etc/nauthilus/lua/subject-risk.lua
          secrets:
            token: subject-provider-secret
`,
		expectedPath:                   "policy.namespaces.authn.providers.lua_subject_<old-name>",
		expectedDefaultOrIdentity:      "The exact provider identity is `authn/lua_subject_<old-name>`.",
		validationRule:                 "The provider kind is `lua_subject`; strict production decoding accepts only the canonical `script_path` field, which production validation requires to be non-empty; file/source resolvability belongs to candidate compilation.",
		canonicalPath:                  "policy.namespaces.authn.providers.lua_subject_risk.kind",
		authorityPath:                  "policy.namespaces.<name>.providers.<name>.kind",
		canonicalValue:                 "lua_subject",
		expectedEvidenceValue:          "authn/lua_subject_risk",
		expectedDefaultOrIdentityValue: "authn/lua_subject_risk",
		expectedErrorPath:              "policy.namespaces.authn.providers.lua_subject_risk.script_path",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldLuaSubject,
		invalidMutation:                migrationInvalidLuaSubject,
		secretPath:                     "policy.namespaces.authn.providers.lua_subject_risk.secrets.token",
		secretPlaintext:                "subject-provider-secret",
	},
	{
		name:    "Lua action effects",
		oldPath: "auth.policy.obligation_targets.lua.actions",
		oldInput: `auth:
  policy:
    obligation_targets:
      lua:
        actions:
          - name: security
            type: lua
            script_path: /etc/nauthilus/lua/security.lua
`,
		legacyEvidencePath: "auth.policy.obligation_targets.lua.actions[0].type",
		legacyValue:        "lua",
		newInput: `policy:
  namespaces:
    authn:
      effects:
        lua_action_security:
          kind: lua_action
          action_type: lua
          script_path: /etc/nauthilus/lua/security.lua
          execution: host_sync
          secrets:
            token: lua-action-secret
`,
		expectedPath:                   "policy.namespaces.authn.effects.lua_action_<old-name>",
		expectedDefaultOrIdentity:      "The exact effect identity is `authn/lua_action_<old-name>`, with mandatory `execution`.",
		validationRule:                 "`post` requires `host_post_action`; all other retained Lua action types require `host_sync`.",
		canonicalPath:                  "policy.namespaces.authn.effects.lua_action_security.action_type",
		authorityPath:                  "policy.namespaces.<name>.effects.<name>.action_type",
		canonicalValue:                 "lua",
		expectedEvidenceValue:          "authn/lua_action_security",
		expectedDefaultOrIdentityValue: "authn/lua_action_security",
		expectedErrorPath:              "policy.namespaces.authn.effects.lua_action_security.action_type",
		evidenceClass:                  migrationEvidenceNormalizedSource,
		evidenceField:                  migrationFieldLuaEffect,
		invalidMutation:                migrationInvalidLuaEffect,
		secretPath:                     "policy.namespaces.authn.effects.lua_action_security.secrets.token",
		secretPlaintext:                "lua-action-secret",
	},
	{
		name:    "Lua registry scripts",
		oldPath: "auth.policy.registry_scripts",
		oldInput: `auth:
  policy:
    registry_scripts: [testdata/policy_migration/registry.lua]
`,
		legacyEvidencePath: "auth.policy.registry_scripts[0]",
		legacyValue:        "testdata/policy_migration/registry.lua",
		newInput: `policy:
  namespaces:
    authn:
      schema_contributions:
        lua:
          registry_scripts: [testdata/policy_migration/registry.lua]
`,
		expectedPath:                   "policy.namespaces.authn.schema_contributions.lua.registry_scripts",
		expectedDefaultOrIdentity:      "Default empty; scripts contribute bounded authn-owned fact definitions only during candidate compilation.",
		validationRule:                 "Every configured registry-script path is non-empty.",
		canonicalPath:                  "policy.namespaces.authn.schema_contributions.lua.registry_scripts[0]",
		authorityPath:                  "policy.namespaces.<name>.schema_contributions.lua.registry_scripts[]",
		canonicalValue:                 "testdata/policy_migration/registry.lua",
		expectedEvidenceValue:          "lua.contract.registry_flag",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.schema_contributions.lua.registry_scripts[0]",
		evidenceClass:                  migrationEvidenceTestOwnedSchemaSource,
		evidenceField:                  migrationFieldRegistryScripts,
		invalidMutation:                migrationInvalidRegistryScript,
	},
	{
		name:    "HTTP header fact sources",
		oldPath: "auth.policy.request_headers",
		oldInput: `auth:
  policy:
    request_headers:
      - header: X-Forwarded-For
        attribute: request.header.forwarded_for
        visibility: public
        normalize: {trim: true, case: lower, max_length: 256}
`,
		legacyEvidencePath: "auth.policy.request_headers[0].attribute",
		legacyValue:        "request.header.forwarded_for",
		newInput: `policy:
  namespaces:
    authn:
      fact_sources:
        http_headers:
          - header: X-Forwarded-For
            attribute: request.header.forwarded_for
            visibility: public
            normalize: {trim: true, case: lower, max_length: 256}
`,
		expectedPath:                   "policy.namespaces.authn.fact_sources.http_headers",
		expectedDefaultOrIdentity:      "Default empty; source, fact, normalization, visibility, and bounds retain their meaning.",
		validationRule:                 "Each entry requires a non-empty header and a canonical fact identity.",
		canonicalPath:                  "policy.namespaces.authn.fact_sources.http_headers[0].attribute",
		authorityPath:                  "policy.namespaces.<name>.fact_sources.http_headers[].attribute",
		canonicalValue:                 "request.header.forwarded_for",
		expectedEvidenceValue:          "request.header.forwarded_for",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.fact_sources.http_headers[0].header",
		evidenceClass:                  migrationEvidenceTestOwnedSchemaSource,
		evidenceField:                  migrationFieldHTTPHeaders,
		invalidMutation:                migrationInvalidHTTPHeader,
	},
	{
		name:    "gRPC metadata fact sources",
		oldPath: "auth.policy.request_metadata",
		oldInput: `auth:
  policy:
    request_metadata:
      - key: x-client-id
        attribute: request.metadata.client_id
        visibility: public
        normalize: {trim: true, case: lower, max_length: 256}
`,
		legacyEvidencePath: "auth.policy.request_metadata[0].attribute",
		legacyValue:        "request.metadata.client_id",
		newInput: `policy:
  namespaces:
    authn:
      fact_sources:
        grpc_metadata:
          - key: x-client-id
            attribute: request.metadata.client_id
            visibility: public
            normalize: {trim: true, case: lower, max_length: 256}
`,
		expectedPath:                   "policy.namespaces.authn.fact_sources.grpc_metadata",
		expectedDefaultOrIdentity:      "Default empty; source, fact, normalization, visibility, and bounds retain their meaning.",
		validationRule:                 "Each entry requires a non-empty metadata key and a canonical fact identity.",
		canonicalPath:                  "policy.namespaces.authn.fact_sources.grpc_metadata[0].attribute",
		authorityPath:                  "policy.namespaces.<name>.fact_sources.grpc_metadata[].attribute",
		canonicalValue:                 "request.metadata.client_id",
		expectedEvidenceValue:          "request.metadata.client_id",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.fact_sources.grpc_metadata[0].key",
		evidenceClass:                  migrationEvidenceTestOwnedSchemaSource,
		evidenceField:                  migrationFieldGRPCMetadata,
		invalidMutation:                migrationInvalidGRPCMetadata,
	},
	{
		name:    "backend attribute fact sources",
		oldPath: "auth.policy.attribute_exports",
		oldInput: `auth:
  policy:
    attribute_exports:
      - name: department
        attribute: subject.department
        type: string
        sensitivity: internal
`,
		legacyEvidencePath: "auth.policy.attribute_exports[0].sensitivity",
		legacyValue:        "internal",
		newInput: `policy:
  namespaces:
    authn:
      fact_sources:
        backend_attributes:
          - name: department
            attribute: subject.department
            type: string
            sensitivity: internal
`,
		expectedPath:                   "policy.namespaces.authn.fact_sources.backend_attributes",
		expectedDefaultOrIdentity:      "Default empty; backend name, fact, type, and sensitivity retain their meaning.",
		validationRule:                 "Each entry requires a name, canonical fact identity, exact value kind, and supported sensitivity.",
		canonicalPath:                  "policy.namespaces.authn.fact_sources.backend_attributes[0].sensitivity",
		authorityPath:                  "policy.namespaces.<name>.fact_sources.backend_attributes[].sensitivity",
		canonicalValue:                 "internal",
		expectedEvidenceValue:          "internal",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.fact_sources.backend_attributes[0].sensitivity",
		evidenceClass:                  migrationEvidenceTestOwnedSchemaSource,
		evidenceField:                  migrationFieldBackendAttributes,
		invalidMutation:                migrationInvalidBackendAttribute,
	},
	{
		name:    "checks",
		oldPath: "auth.policy.checks",
		oldInput: `auth:
  policy:
    attribute_sources:
      lua:
        environment:
          - name: risk
            script_path: /etc/nauthilus/lua/risk.lua
    checks:
      - name: risk
        type: lua.environment
        stage: pre_auth
        config_ref: auth.policy.attribute_sources.lua.environment.risk
        operations: [authenticate]
        output: nauthilus.auth.tls.secure
`,
		legacyEvidencePath: "auth.policy.checks[0].config_ref",
		legacyValue:        "auth.policy.attribute_sources.lua.environment.risk",
		newInput: `policy:
  namespaces:
    authn:
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: /etc/nauthilus/lua/risk.lua
      domain_plans:
        password:
          checkpoints:
            pre_auth:
              providers:
                - name: risk
                  use: authn/lua_environment_risk
                  actions: [authenticate]
                  run_if: {auth_state: any}
                  output: nauthilus.auth.tls.secure
`,
		expectedPath:                   "policy.namespaces.authn.domain_plans.<plan>.checkpoints.<checkpoint>.providers[]",
		expectedDefaultOrIdentity:      "Check `type` plus `config_ref` becomes one deterministic exact `use` identity.",
		validationRule:                 "The containing checkpoint owns the removed check stage, and `use` must be exact.",
		canonicalPath:                  "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].use",
		authorityPath:                  "policy.namespaces.<name>.domain_plans.<name>.checkpoints.<name>.providers[].use",
		canonicalValue:                 "authn/lua_environment_risk",
		expectedEvidenceValue:          "authn/lua_environment_risk",
		expectedDefaultOrIdentityValue: "authn/lua_environment_risk",
		expectedErrorPath:              "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].use",
		evidenceClass:                  migrationEvidenceActualCatalog,
		evidenceField:                  migrationFieldChecks,
		invalidMutation:                migrationInvalidCheck,
	},
	{
		name:    "rules",
		oldPath: "auth.policy.policies",
		oldInput: `auth:
  policy:
    policies:
      - name: deny_risk
        stage: pre_auth
        operations: [authenticate]
        require_checks: [risk]
        if: {always: true}
        then: {decision: deny, reason: risk}
`,
		legacyEvidencePath: "auth.policy.policies[0].stage",
		legacyValue:        "pre_auth",
		newInput: `policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          rules:
            - name: deny_risk
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [risk]
              if: {always: true}
              then:
                decision: deny
                reason: risk
                fsm_event_marker: auth.fsm.event.pre_auth_deny
                response_marker: auth.response.fail
`,
		expectedPath:                   "policy.namespaces.authn.policy_sets.configured.rules[]",
		expectedDefaultOrIdentity:      "Default empty; migrated rules are authored once in private `authn/configured`.",
		validationRule:                 "Every imported rule is validated against its exact target action and checkpoint.",
		canonicalPath:                  "policy.namespaces.authn.policy_sets.configured.rules[0].checkpoint",
		authorityPath:                  "policy.namespaces.<name>.policy_sets.<name>.rules[].checkpoint",
		canonicalValue:                 "pre_auth",
		expectedEvidenceValue:          "pre_auth",
		expectedDefaultOrIdentityValue: 0,
		expectedErrorPath:              "policy.namespaces.authn.policy_sets.configured.rules[0].checkpoint",
		evidenceClass:                  migrationEvidenceActualCatalog,
		evidenceField:                  migrationFieldRules,
		invalidMutation:                migrationInvalidRule,
	},
}

var nestedMigrationRules = []nestedMigrationRule{
	{"rule `stage`", "`checkpoint`", "The exact checkpoint replaces the removed rule stage."},
	{"rule `operations`", "`actions`", "Actions are checked against every importing target."},
	{"`require_checks`", "`require_providers`", "Provider names resolve inside the same domain plan and compatible checkpoint."},
	{"rule `name` and `if`", "unchanged", "The complete condition-tree semantics are retained."},
	{"decision, reason, markers, response message, and response language", "unchanged", "Their field names and behavior are retained."},
	{"`skip_remaining_stage_checks`", "`skip_remaining_checkpoint_providers`", "Control remains local to the containing checkpoint."},
	{"effect `id`", "exact qualified effect `id`", "Obligation and advice identities must resolve in the target effect registry."},
	{"effect `args`", "typed `parameters`", "Parameters are schema-validated instead of remaining opaque."},
	{"check `name`", "provider-instance `name`", "The scheduler-visible instance name is retained."},
	{"check `type` plus `config_ref`", "exact qualified `use`", "No `config_ref` field exists in the new model."},
	{"check `stage`", "removed", "The containing checkpoint owns provider placement."},
	{"check `operations`", "provider-instance `actions`", "Actions are explicit when one domain plan serves several actions."},
	{"`run_if`, `after`, `skip_if`, `observe_safe`, and `output`", "unchanged", "Their scheduling semantics are retained subject to target-aware validation."},
	{"`run_if.auth_state`", "unchanged", "Its values remain valid only for authn domain plans."},
	{"nested localization, time-window, scheduler, normalization, and backend-export fields", "unchanged", "Field names and validation semantics remain under the new owner path."},
}

func TestPolicyMigrationContractDocumentsEveryMappingFamily(t *testing.T) {
	guide := readPolicyMigrationGuide(t)

	if len(policyMigrationContractCases) != 17 {
		t.Fatalf("mapping families = %d, want 17", len(policyMigrationContractCases))
	}

	seenOldPaths := make(map[string]struct{}, len(policyMigrationContractCases))
	for _, test := range policyMigrationContractCases {
		t.Run(test.name, func(t *testing.T) {
			assertPolicyMigrationCaseIsComplete(t, test)

			if _, exists := seenOldPaths[test.oldPath]; exists {
				t.Fatalf("duplicate old mapping path %q", test.oldPath)
			}

			seenOldPaths[test.oldPath] = struct{}{}

			assertRemovedPolicyFragmentRejected(t, test.oldInput)

			document, err := policyconfig.Decode("yaml", strings.NewReader(test.newInput))
			requireNoError(t, err)

			normalized := policyconfig.Normalize(document)
			requireNoError(t, policyconfig.Validate(normalized))
			assertPolicyMigrationDefaultOrIdentity(t, normalized, test)
			assertPolicyMigrationInvalidMutation(t, test)
			assertPolicyMigrationFrozenEvidence(t, normalized, test)

			canonical, err := policyconfig.Canonical(normalized)
			requireNoError(t, err)

			if got := canonical.Value(test.canonicalPath); !reflect.DeepEqual(got, test.canonicalValue) {
				t.Fatalf("canonical %s = %#v, want %#v", test.canonicalPath, got, test.canonicalValue)
			}

			if !contains(policyconfig.FieldPaths(), test.authorityPath) {
				t.Fatalf("field authority does not contain %q", test.authorityPath)
			}

			assertMigrationDocumentationEvidence(t, guide, test)
			assertMigrationSecretRedaction(t, guide, canonical, test)
		})
	}
}

// assertRemovedPolicyFragmentRejected proves historical examples cannot execute as unified input.
func assertRemovedPolicyFragmentRejected(t *testing.T, source string) {
	t.Helper()

	_, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err == nil {
		t.Fatal("removed auth.policy fragment decoded successfully")
	}

	var pathError *policyconfig.PathError
	if !errors.As(err, &pathError) {
		t.Fatalf("removed auth.policy fragment error = %v, want PathError", err)
	}

	if pathError.Path != "auth" {
		t.Fatalf("removed auth.policy fragment path = %q, want auth", pathError.Path)
	}
}

// class identifies the executable boundary that owns one mapping field.
func (field migrationEvidenceField) class() migrationEvidenceClass {
	switch field {
	case migrationFieldMode, migrationFieldDefaultPolicy, migrationFieldSchedulerGuards,
		migrationFieldReport, migrationFieldChecks, migrationFieldRules:
		return migrationEvidenceActualCatalog
	case migrationFieldLocalization, migrationFieldNetworks, migrationFieldStrings, migrationFieldTimeWindows,
		migrationFieldLuaEnvironment, migrationFieldLuaSubject, migrationFieldLuaEffect:
		return migrationEvidenceNormalizedSource
	case migrationFieldRegistryScripts, migrationFieldHTTPHeaders, migrationFieldGRPCMetadata, migrationFieldBackendAttributes:
		return migrationEvidenceTestOwnedSchemaSource
	default:
		return 0
	}
}

// assertPolicyMigrationInvalidMutation proves one exact validation path for a mapping row.
func assertPolicyMigrationInvalidMutation(t *testing.T, test policyMigrationContractCase) {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(test.newInput))
	requireNoError(t, err)

	invalid := policyconfig.Normalize(document)
	test.invalidMutation.apply(&invalid)

	err = policyconfig.Validate(invalid)

	var pathError *policyconfig.PathError
	if !errors.As(err, &pathError) {
		t.Fatalf("invalid mutation error = %v, want PathError at %s", err, test.expectedErrorPath)
	}

	if pathError.Path != test.expectedErrorPath {
		t.Fatalf("invalid mutation path = %q, want %q", pathError.Path, test.expectedErrorPath)
	}
}

// apply introduces one table-owned invalid standalone value without changing its sibling evidence.
func (mutation migrationInvalidMutation) apply(document *policyconfig.Document) {
	if document.Policy.Namespaces == nil {
		document.Policy.Namespaces = make(map[string]policyconfig.NamespaceConfig)
	}

	if mutation <= migrationInvalidReport {
		mutation.applyTargetAndSetMutation(document)

		return
	}

	mutation.applyBindingAndSourceMutation(document)
}

// applyTargetAndSetMutation invalidates one target, condition set, or scheduler field.
func (mutation migrationInvalidMutation) applyTargetAndSetMutation(document *policyconfig.Document) {
	authn := document.Policy.Namespaces["authn"]

	switch mutation {
	case migrationInvalidMode:
		document.Policy.Targets[0].Mode = "audit"
	case migrationInvalidDefaultPolicy:
		document.Policy.Targets[0].DefaultPolicy = "standard_auth"
	case migrationInvalidLocalization:
		authn.Localization.Catalogs[0].Language = "en--US"
	case migrationInvalidNetworks:
		authn.ConditionSets.Networks["trusted"] = []string{"invalid"}
	case migrationInvalidStrings:
		authn.ConditionSets.Strings["privileged"] = []string{"admin", "admin"}
	case migrationInvalidTimeWindows:
		window := authn.ConditionSets.TimeWindows["office"]
		window.Timezone = "Invalid/Zone"
		authn.ConditionSets.TimeWindows["office"] = window
	case migrationInvalidSchedulerGuard:
		plan := authn.DomainPlans["password"]
		guard := plan.SchedulerGuards["known_client"]
		guard.OnMissingAttribute = "skip"
		plan.SchedulerGuards["known_client"] = guard
		authn.DomainPlans["password"] = plan
	case migrationInvalidReport:
		document.Policy.Targets[0] = invalidGenericReportTarget()
	}

	document.Policy.Namespaces["authn"] = authn
}

// applyBindingAndSourceMutation invalidates one provider, effect, source, or rule field.
func (mutation migrationInvalidMutation) applyBindingAndSourceMutation(document *policyconfig.Document) {
	authn := document.Policy.Namespaces["authn"]

	switch mutation {
	case migrationInvalidLuaEnvironment:
		provider := authn.Providers["lua_environment_risk"]
		provider.ScriptPath = ""
		authn.Providers["lua_environment_risk"] = provider
	case migrationInvalidLuaSubject:
		provider := authn.Providers["lua_subject_risk"]
		provider.ScriptPath = ""
		authn.Providers["lua_subject_risk"] = provider
	case migrationInvalidLuaEffect:
		effect := authn.Effects["lua_action_security"]
		effect.ActionType = ""
		authn.Effects["lua_action_security"] = effect
	case migrationInvalidRegistryScript:
		authn.SchemaContributions.Lua.RegistryScripts[0] = ""
	case migrationInvalidHTTPHeader:
		authn.FactSources.HTTPHeaders[0].Header = "Authorization"
	case migrationInvalidGRPCMetadata:
		authn.FactSources.GRPCMetadata[0].Key = "X-Client"
	case migrationInvalidBackendAttribute:
		authn.FactSources.BackendAttributes[0].Sensitivity = "restricted"
	case migrationInvalidCheck:
		plan := authn.DomainPlans["password"]
		checkpoint := plan.Checkpoints["pre_auth"]
		checkpoint.Providers[0].Use = "authn/missing"
		plan.Checkpoints["pre_auth"] = checkpoint
		authn.DomainPlans["password"] = plan
	case migrationInvalidRule:
		set := authn.PolicySets["configured"]
		set.Rules[0].Checkpoint = ""
		authn.PolicySets["configured"] = set
	}

	document.Policy.Namespaces["authn"] = authn
}

// invalidGenericReportTarget isolates the authn-only report validation rule.
func invalidGenericReportTarget() policyconfig.TargetConfig {
	return policyconfig.TargetConfig{
		Namespace: "dkim2", Action: "sign-message-instance", Schema: "dkim2/sign-message-instance/v1",
		Mode: "enforce", NoMatch: "deny",
		Timeouts: policyconfig.TargetTimeoutsConfig{Evaluation: 2 * time.Second, ProviderDefault: time.Second},
		Report:   policyconfig.ReportConfig{IncludeFSM: true},
	}
}

func TestPolicyConfigRefMigrationIdentitiesAreDocumented(t *testing.T) {
	guide := readPolicyMigrationGuide(t)

	if len(cutoverCheckMappings) != 12 {
		t.Fatalf("config_ref identities = %d, want 12", len(cutoverCheckMappings))
	}

	seenTypes := make(map[string]struct{}, len(cutoverCheckMappings))
	seenUses := make(map[string]struct{}, len(cutoverCheckMappings))

	for _, test := range cutoverCheckMappings {
		t.Run(test.checkType, func(t *testing.T) {
			if _, exists := seenTypes[test.checkType]; exists {
				t.Fatalf("duplicate check type %q", test.checkType)
			}

			seenTypes[test.checkType] = struct{}{}

			if _, exists := seenUses[test.canonicalUse]; exists {
				t.Fatalf("duplicate use identity %q", test.canonicalUse)
			}

			seenUses[test.canonicalUse] = struct{}{}

			if missing := missingConfigRefDocumentationEvidence(guide, test); missing != "" {
				t.Fatalf("migration guide does not contain %q", missing)
			}
		})
	}
}

// missingConfigRefDocumentationEvidence returns the first absent field from one shared identity row.
func missingConfigRefDocumentationEvidence(guide string, mapping cutoverCheckMapping) string {
	for _, evidence := range []string{
		mapping.checkType,
		mapping.acceptedOldForm,
		documentedProviderUse(mapping),
		mapping.migrationRule,
	} {
		if !strings.Contains(guide, evidence) {
			return evidence
		}
	}

	return ""
}

// documentedProviderUse renders the generic manual identity from one executable mapping row.
func documentedProviderUse(mapping cutoverCheckMapping) string {
	switch mapping.kind {
	case migrationReferenceFixed:
		return mapping.canonicalUse
	case migrationReferenceLua:
		return mapping.usePrefix + "<source>"
	case migrationReferencePluginEnvironment:
		return mapping.usePrefix + "<module>.environment"
	case migrationReferencePluginSubject:
		return mapping.usePrefix + "<module>.subject.<local>"
	default:
		return ""
	}
}

func TestPolicyMigrationNestedRulesAndHardCutAreDocumented(t *testing.T) {
	guide := readPolicyMigrationGuide(t)

	for _, test := range nestedMigrationRules {
		for _, evidence := range []string{test.oldField, test.newField, test.rule} {
			if !strings.Contains(guide, evidence) {
				t.Fatalf("migration guide does not contain %q", evidence)
			}
		}
	}

	requiredEvidence := []string{
		"Equal old Lua names remain distinct",
		"authn/lua_environment_shared",
		"authn/lua_subject_shared",
		"No runtime, startup, library, supported converter, or offline translator from",
		"Top-level `policy` is the sole production configuration and runtime authority",
		"## Paired old and new examples",
		"### Old `auth.policy` input",
		"### New production `policy` input",
		"Unresolvable old references",
		"## Production loading and migration evidence",
		"`nauthilus:policy`",
		"`nauthilus:backchannel`",
		"`invalid_scope` before token generation",
		"two independently issued tokens",
		"Policy-Basic",
		"prepare -> validate -> commit",
	}

	for _, evidence := range requiredEvidence {
		if !strings.Contains(guide, evidence) {
			t.Fatalf("migration guide does not contain %q", evidence)
		}
	}
}

func TestPolicyMigrationEnabledReportRetainsCompiledDefaults(t *testing.T) {
	document := policyconfig.Document{Policy: policyconfig.PolicyConfig{Targets: []policyconfig.TargetConfig{{
		Namespace: "authn", Action: "authenticate", Schema: "authn/authenticate/v1",
		Report: policyconfig.ReportConfig{Enabled: true},
	}}}}

	report := policyconfig.Normalize(document).Policy.Targets[0].Report
	if !report.Enabled || !report.IncludeFSM || !report.IncludeChecks || report.IncludeAttributes {
		t.Fatalf("normalized report = %#v, want enabled with FSM/check defaults and attributes disabled", report)
	}
}

// assertPolicyMigrationCaseIsComplete rejects incomplete contract-table rows.
func assertPolicyMigrationCaseIsComplete(t *testing.T, test policyMigrationContractCase) {
	t.Helper()

	values := []string{
		test.name,
		test.oldPath,
		test.oldInput,
		test.legacyEvidencePath,
		test.newInput,
		test.expectedPath,
		test.expectedDefaultOrIdentity,
		test.validationRule,
		test.canonicalPath,
		test.authorityPath,
		test.expectedErrorPath,
	}

	for index, value := range values {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("contract field %d is empty", index)
		}
	}

	if !strings.HasPrefix(test.oldInput, "auth:\n") {
		t.Fatal("old fixture must be an independently authored auth-root input")
	}

	if !strings.HasPrefix(test.newInput, "policy:\n") {
		t.Fatal("new fixture must be an independently authored production-policy input")
	}

	if test.oldInput == test.newInput {
		t.Fatal("old and new fixtures must remain an explicit pair")
	}

	if test.expectedEvidenceValue == nil || test.expectedDefaultOrIdentityValue == nil ||
		test.evidenceClass == 0 || test.evidenceField == 0 || test.invalidMutation == 0 {
		t.Fatal("row must declare executable evidence, expected meaning, and one invalid mutation")
	}

	if err := validatePolicyMigrationEvidenceDescriptor(test); err != nil {
		t.Fatal(err)
	}
}

// validatePolicyMigrationEvidenceDescriptor rejects class labels not owned by the row's executable field.
func validatePolicyMigrationEvidenceDescriptor(test policyMigrationContractCase) error {
	if got := test.evidenceField.class(); got != test.evidenceClass {
		return fmt.Errorf("evidence field class = %d, want %d", got, test.evidenceClass)
	}

	return nil
}

// assertMigrationDocumentationEvidence ties each fixture to the manual authority.
func assertMigrationDocumentationEvidence(t *testing.T, guide string, test policyMigrationContractCase) {
	t.Helper()

	for _, evidence := range []string{test.oldPath, test.expectedPath, test.expectedDefaultOrIdentity, test.validationRule} {
		if !strings.Contains(guide, evidence) {
			t.Fatalf("migration guide does not contain %q", evidence)
		}
	}
}

// assertMigrationSecretRedaction proves secret-bearing mapping rows remain canonical-safe.
func assertMigrationSecretRedaction(t *testing.T, guide string, canonical policyconfig.CanonicalDocument, test policyMigrationContractCase) {
	t.Helper()

	if test.secretPath == "" {
		return
	}

	if got := canonical.Value(test.secretPath); got != policyconfig.RedactedValue {
		t.Fatalf("canonical %s = %#v, want %q", test.secretPath, got, policyconfig.RedactedValue)
	}

	if strings.Contains(canonical.String(), test.secretPlaintext) {
		t.Fatalf("canonical projection exposed secret for %s", test.oldPath)
	}

	documented := test.secretPath + "=\"" + policyconfig.RedactedValue + "\""
	if !strings.Contains(guide, documented) {
		t.Fatalf("migration guide does not contain exact redaction evidence %q", documented)
	}
}

// readPolicyMigrationGuide loads the repository-owned manual migration authority.
func readPolicyMigrationGuide(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not resolve the migration contract test")
	}

	path := filepath.Join(filepath.Dir(filename), "..", "docs", "policy_configuration_migration.md")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration guide %s: %v", path, err)
	}

	return string(content)
}

// requireNoError fails one contract assertion with its originating error.
func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// contains reports whether one exact authority path is present.
func contains(values []string, expected string) bool {
	return slices.Contains(values, expected)
}
