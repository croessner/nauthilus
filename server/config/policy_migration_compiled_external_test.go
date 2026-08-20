// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/textproto"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/go-viper/mapstructure/v2"
	"go.yaml.in/yaml/v3"
)

const (
	legacyMigrationFixture  = "testdata/policy_migration/old.yaml"
	unifiedMigrationFixture = "testdata/policy_migration/new.yaml"
)

type migrationReferenceKind uint8

const (
	migrationReferenceFixed migrationReferenceKind = iota
	migrationReferenceLua
	migrationReferencePluginEnvironment
	migrationReferencePluginSubject
)

type legacyCheckMapping struct {
	checkType       string
	prefix          string
	usePrefix       string
	checkName       string
	canonicalRef    string
	canonicalUse    string
	invalidRef      string
	emptyUse        string
	missingRef      string
	missingCheck    string
	missingUse      string
	acceptedOldForm string
	migrationRule   string
	kind            migrationReferenceKind
	checkpoint      policy.Stage
	action          policy.Operation
	observeSafe     bool
}

var legacyCheckMappings = []legacyCheckMapping{
	{
		checkType: policy.CheckTypeBruteForce, prefix: "auth.controls.brute_force",
		checkName: "brute_force", canonicalRef: "auth.controls.brute_force.buckets", canonicalUse: "authn/builtin/brute_force",
		invalidRef: "auth.controls.rbl", emptyUse: "authn/builtin/brute_force", kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.controls.brute_force...`",
		migrationRule:   "Discard any suffix; the builtin binding owns typed brute-force configuration.",
	},
	{
		checkType: policy.CheckTypeTLSEncryption, prefix: "auth.controls.tls_encryption",
		checkName: "tls_encryption", canonicalRef: "auth.controls.tls_encryption.allowlist", canonicalUse: "authn/builtin/tls_encryption",
		invalidRef: "auth.controls.relay_domains", emptyUse: "authn/builtin/tls_encryption", kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate, observeSafe: true,
		acceptedOldForm: "empty or `auth.controls.tls_encryption...`", migrationRule: "Discard any suffix.",
	},
	{
		checkType: policy.CheckTypeRelayDomains, prefix: "auth.controls.relay_domains",
		checkName: "relay_domains", canonicalRef: "auth.controls.relay_domains.static", canonicalUse: "authn/builtin/relay_domains",
		invalidRef: "auth.controls.rbl", emptyUse: "authn/builtin/relay_domains", kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate, observeSafe: true,
		acceptedOldForm: "empty or `auth.controls.relay_domains...`", migrationRule: "Discard any suffix.",
	},
	{
		checkType: policy.CheckTypeRBL, prefix: "auth.controls.rbl",
		checkName: "rbl", canonicalRef: "auth.controls.rbl.lists", canonicalUse: "authn/builtin/rbl",
		invalidRef: "auth.controls.brute_force", emptyUse: "authn/builtin/rbl", kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.controls.rbl...`", migrationRule: "Discard any suffix.",
	},
	{
		checkType: policy.CheckTypeLuaEnvironment, prefix: "auth.policy.attribute_sources.lua.environment.", usePrefix: "authn/lua_environment_",
		checkName: "shared", canonicalRef: "auth.policy.attribute_sources.lua.environment.shared", canonicalUse: "authn/lua_environment_shared",
		invalidRef: "auth.policy.attribute_sources.lua.environment.shared.extra", emptyUse: "authn/lua_environment_shared",
		missingRef: "auth.policy.attribute_sources.lua.environment.missing", missingCheck: "missing", kind: migrationReferenceLua,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.policy.attribute_sources.lua.environment.<source>`",
		migrationRule:   "An empty reference uses the old check name; the migrated provider must exist.",
	},
	{
		checkType: policy.CheckTypePluginEnvironment, prefix: "plugins.modules.", usePrefix: "authn/plugin.",
		checkName: "plugin_environment_acme", canonicalRef: "plugins.modules.acme.environment", canonicalUse: "authn/plugin.acme.environment",
		invalidRef: "plugins.modules.acme.environment.extra", missingRef: "plugins.modules.missing.environment",
		missingCheck: "plugin_environment_missing", missingUse: "authn/plugin.missing.environment", kind: migrationReferencePluginEnvironment,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "exactly `plugins.modules.<module>.environment`",
		migrationRule:   "Empty, non-canonical, or unresolvable references are rejected.",
	},
	{
		checkType: policy.CheckTypeLDAPBackend, prefix: "auth.backends.ldap",
		checkName: "ldap_backend", canonicalRef: "auth.backends.ldap.default", canonicalUse: "authn/builtin/ldap_backend",
		invalidRef: "auth.backends.lua", emptyUse: "authn/builtin/ldap_backend", kind: migrationReferenceFixed,
		checkpoint: policy.StageAuthBackend, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.backends.ldap...`",
		migrationRule:   "Discard any suffix; the builtin binding owns typed LDAP configuration.",
	},
	{
		checkType: policy.CheckTypeLuaBackend, prefix: "auth.backends.lua.backend",
		checkName: "lua_backend", canonicalRef: "auth.backends.lua.backend.default", canonicalUse: "authn/builtin/lua_backend",
		invalidRef: "auth.backends.ldap", emptyUse: "authn/builtin/lua_backend", kind: migrationReferenceFixed,
		checkpoint: policy.StageAuthBackend, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.backends.lua.backend...`",
		migrationRule:   "Discard any suffix; the builtin binding owns the configured Lua backend.",
	},
	{
		checkType: policy.CheckTypePluginBackend, prefix: "auth.backends.order",
		checkName: "plugin_backend", canonicalRef: "auth.backends.order.primary", canonicalUse: "authn/builtin/plugin_backend_order",
		invalidRef: "plugins.modules.acme.backend", emptyUse: "authn/builtin/plugin_backend_order", kind: migrationReferenceFixed,
		checkpoint: policy.StageAuthBackend, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.backends.order...`",
		migrationRule:   "Discard any suffix; the builtin binding owns backend order and plugin capabilities.",
	},
	{
		checkType: policy.CheckTypeLuaSubjectSource, prefix: "auth.policy.attribute_sources.lua.subject.", usePrefix: "authn/lua_subject_",
		checkName: "shared", canonicalRef: "auth.policy.attribute_sources.lua.subject.shared", canonicalUse: "authn/lua_subject_shared",
		invalidRef: "auth.policy.attribute_sources.lua.subject.shared.extra", emptyUse: "authn/lua_subject_shared",
		missingRef: "auth.policy.attribute_sources.lua.subject.missing", missingCheck: "missing", kind: migrationReferenceLua,
		checkpoint: policy.StageSubjectAnalysis, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.policy.attribute_sources.lua.subject.<source>`",
		migrationRule:   "An empty reference uses the old check name; the migrated provider must exist.",
	},
	{
		checkType: policy.CheckTypePluginSubjectSource, prefix: "plugins.modules.", usePrefix: "authn/plugin.",
		checkName: "plugin_subject_acme_risk", canonicalRef: "plugins.modules.acme.subject", canonicalUse: "authn/plugin.acme.subject.risk",
		invalidRef: "plugins.modules.acme.environment", missingRef: "plugins.modules.missing.subject",
		missingCheck: "plugin_subject_missing_risk", missingUse: "authn/plugin.missing.subject.risk", kind: migrationReferencePluginSubject,
		checkpoint: policy.StageSubjectAnalysis, action: policy.OperationAuthenticate,
		acceptedOldForm: "`plugins.modules.<module>.subject` plus a derivable check-local suffix",
		migrationRule:   "Empty, non-canonical, non-derivable, or unresolvable references are rejected.",
	},
	{
		checkType: policy.CheckTypeAccountProvider, prefix: "auth.backends",
		checkName: "account_provider", canonicalRef: "auth.backends.order", canonicalUse: "authn/builtin/account_provider",
		invalidRef: "identity.backends", emptyUse: "authn/builtin/account_provider", kind: migrationReferenceFixed,
		checkpoint: policy.StageAccountProvider, action: policy.OperationListAccounts,
		acceptedOldForm: "empty or `auth.backends...`",
		migrationRule:   "Discard any suffix; the builtin binding owns typed backend selection.",
	},
}

type normalizedInputMeaning struct {
	Localization   []string
	Networks       []string
	Strings        []string
	TimeWindows    []string
	SchedulerGuard []string
	RegistryScript []string
	Providers      []string
	Effects        []string
	Headers        []string
	Metadata       []string
	BackendExports []string
	Mode           string
	DefaultPolicy  string
	Report         reportMeaning
}

type compiledPlanMeaning struct {
	Target        string
	Mode          string
	DefaultPolicy string
	Report        reportMeaning
	Checkpoints   []checkpointMeaning
}

type reportMeaning struct {
	Enabled           bool
	IncludeFSM        bool
	IncludeChecks     bool
	IncludeAttributes bool
}

type checkpointMeaning struct {
	Name                string
	Providers           []providerMeaning
	ProviderLevels      [][]string
	Rules               []ruleMeaning
	ProductionPolicySet []string
	ComparisonPolicySet []string
}

type compiledCheckIdentityMeaning struct {
	CheckpointOrder       []string
	ProviderInstanceOrder []string
	ProviderUseOrder      []string
	ProviderActions       []string
	ProviderLevels        [][]string
	RequiredInstances     []string
	RequiredProviderUses  []string
	ProductionPolicySet   []string
	ComparisonPolicySet   []string
	Checkpoint            string
	RuleCheckpoint        string
	Action                string
	RunIf                 string
	ObserveSafe           bool
}

type compiledAuxiliaryMeaning struct {
	SchedulerGuard []compiledGuardMeaning
}

type testOwnedSchemaSourceMeaning struct {
	RegistryFacts  []attributeDefinitionMeaning
	BackendFacts   []attributeDefinitionMeaning
	RequestSources []compiledRequestSourceMeaning
}

type attributeDefinitionMeaning struct {
	ID         string
	Stage      string
	Category   string
	Type       string
	Source     string
	Operations []string
	Details    []string
}

type compiledGuardMeaning struct {
	Name      string
	Fact      string
	FactKind  string
	Operator  string
	Reference string
	OnMissing string
	Values    []string
}

type compiledRequestSourceMeaning struct {
	Transport string
	Source    string
	Fact      string
	Case      string
	MaxLength int
	Trim      bool
}

type providerMeaning struct {
	Name         string
	Use          string
	RunIf        string
	Output       string
	Actions      []string
	After        []string
	Dependencies []string
	SkipIf       []string
	ObserveSafe  bool
}

type ruleMeaning struct {
	Expression        expressionMeaning
	ResponseMessage   responseMessageMeaning
	ResponseLanguage  responseLanguageMeaning
	Name              string
	Action            string
	Decision          string
	Reason            string
	OutcomeMarker     string
	FSMEventMarker    string
	ResponseMarker    string
	RequiredInstances []string
	RequiredProviders []string
	Effects           []effectUseMeaning
	Advice            []effectUseMeaning
	SkipRemaining     bool
}

type expressionMeaning struct {
	Kind      string
	Fact      string
	FactKind  string
	Operator  string
	Reference string
	Values    []string
	Children  []expressionMeaning
}

type effectUseMeaning struct {
	ID         string
	Parameters []string
}

type responseMessageMeaning struct {
	From      string
	Text      string
	I18NKey   string
	Fact      string
	Detail    string
	Fallback  string
	MaxLength int
}

type responseLanguageMeaning struct {
	From     string
	Language string
	Fact     string
	Fallback string
}

type migrationAcceptance struct{}

type migrationEvidencePair struct {
	oldMeaning  any
	newMeaning  any
	oldSelected any
	newSelected any
}

// Accept supplies the capability required to compile immutable builtin post actions.
func (migrationAcceptance) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

// assertPolicyMigrationExecutableEvidence binds one mapping row to its declared executable boundary.
func assertPolicyMigrationExecutableEvidence(
	t *testing.T,
	legacy *config.FileSettings,
	unified policyconfig.Document,
	test policyMigrationContractCase,
) {
	t.Helper()

	if got := test.evidenceField.class(); got != test.evidenceClass {
		t.Fatalf("evidence field %d belongs to class %d, not %d", test.evidenceField, got, test.evidenceClass)
	}

	pair := executePolicyMigrationEvidence(t, legacy, unified, test.evidenceField)
	assertMigrationMeaningEqual(t, pair.newMeaning, pair.oldMeaning)

	if !reflect.DeepEqual(pair.oldSelected, test.expectedEvidenceValue) {
		t.Fatalf("old selected evidence = %#v, want %#v", pair.oldSelected, test.expectedEvidenceValue)
	}

	if !reflect.DeepEqual(pair.newSelected, test.expectedEvidenceValue) {
		t.Fatalf("new selected evidence = %#v, want %#v", pair.newSelected, test.expectedEvidenceValue)
	}
}

// assertPolicyMigrationDefaultOrIdentity executes the table's default or exact-identity expectation.
func assertPolicyMigrationDefaultOrIdentity(
	t *testing.T,
	document policyconfig.Document,
	test policyMigrationContractCase,
) {
	t.Helper()

	got := policyMigrationDefaultOrIdentity(document, test.evidenceField)
	if !reflect.DeepEqual(got, test.expectedDefaultOrIdentityValue) {
		t.Fatalf("default or identity = %#v, want %#v", got, test.expectedDefaultOrIdentityValue)
	}
}

// policyMigrationDefaultOrIdentity returns one executable default or exact qualified identity.
func policyMigrationDefaultOrIdentity(document policyconfig.Document, field migrationEvidenceField) any {
	if value, ok := policyMigrationTargetDefault(field); ok {
		return value
	}

	if value, ok := policyMigrationEmptyDefault(field); ok {
		return value
	}

	return policyMigrationQualifiedIdentity(document, field)
}

// policyMigrationTargetDefault returns normalized authn target defaults.
func policyMigrationTargetDefault(field migrationEvidenceField) (any, bool) {
	document := policyconfig.Normalize(policyconfig.Document{Policy: policyconfig.PolicyConfig{
		Targets: []policyconfig.TargetConfig{{
			Namespace: policy.AuthnNamespace,
			Action:    string(policy.OperationAuthenticate),
			Schema:    "authn/authenticate/v1",
		}},
	}})
	target := document.Policy.Targets[0]

	switch field {
	case migrationFieldMode:
		return target.Mode, true
	case migrationFieldDefaultPolicy:
		return target.DefaultPolicy, true
	case migrationFieldReport:
		return unifiedReportMeaning(target.Report), true
	default:
		return nil, false
	}
}

// policyMigrationEmptyDefault proves source-owned collections default to empty.
func policyMigrationEmptyDefault(field migrationEvidenceField) (any, bool) {
	namespace := policyconfig.Normalize(policyconfig.Document{Policy: policyconfig.PolicyConfig{
		Namespaces: map[string]policyconfig.NamespaceConfig{policy.AuthnNamespace: {}},
	}}).Policy.Namespaces[policy.AuthnNamespace]

	switch field {
	case migrationFieldLocalization:
		return len(namespace.Localization.Catalogs), true
	case migrationFieldNetworks:
		return len(namespace.ConditionSets.Networks), true
	case migrationFieldStrings:
		return len(namespace.ConditionSets.Strings), true
	case migrationFieldTimeWindows:
		return len(namespace.ConditionSets.TimeWindows), true
	case migrationFieldSchedulerGuards:
		return len(namespace.DomainPlans), true
	case migrationFieldRegistryScripts:
		return len(namespace.SchemaContributions.Lua.RegistryScripts), true
	case migrationFieldHTTPHeaders:
		return len(namespace.FactSources.HTTPHeaders), true
	case migrationFieldGRPCMetadata:
		return len(namespace.FactSources.GRPCMetadata), true
	case migrationFieldBackendAttributes:
		return len(namespace.FactSources.BackendAttributes), true
	case migrationFieldRules:
		return len(namespace.PolicySets), true
	default:
		return nil, false
	}
}

// policyMigrationQualifiedIdentity reads one exact provider or effect identity from the authored row.
func policyMigrationQualifiedIdentity(document policyconfig.Document, field migrationEvidenceField) any {
	namespace := document.Policy.Namespaces[policy.AuthnNamespace]

	switch field {
	case migrationFieldLuaEnvironment, migrationFieldLuaSubject:
		names := sortedKeys(namespace.Providers)
		if len(names) != 1 {
			return ""
		}

		return policy.AuthnNamespace + "/" + names[0]
	case migrationFieldLuaEffect:
		names := sortedKeys(namespace.Effects)
		if len(names) != 1 {
			return ""
		}

		return policy.AuthnNamespace + "/" + names[0]
	case migrationFieldChecks:
		return namespace.DomainPlans["password"].Checkpoints[string(policy.StagePreAuth)].Providers[0].Use
	default:
		return nil
	}
}

// executePolicyMigrationEvidence runs the class-specific old/new comparison for one table field.
func executePolicyMigrationEvidence(
	t *testing.T,
	legacy *config.FileSettings,
	unified policyconfig.Document,
	field migrationEvidenceField,
) migrationEvidencePair {
	t.Helper()

	switch field.class() {
	case migrationEvidenceActualCatalog:
		return actualCatalogMigrationEvidence(t, legacy, unified, field)
	case migrationEvidenceNormalizedSource:
		return normalizedSourceMigrationEvidence(t, legacy, unified, field)
	case migrationEvidenceTestOwnedSchemaSource:
		return testOwnedSchemaSourceMigrationEvidence(t, legacy, unified, field)
	default:
		t.Fatalf("migration evidence field %d has no executable class", field)

		return migrationEvidencePair{}
	}
}

// normalizedSourceMigrationEvidence compares one row before the immutable target-catalog boundary.
func normalizedSourceMigrationEvidence(
	t *testing.T,
	legacy *config.FileSettings,
	unified policyconfig.Document,
	field migrationEvidenceField,
) migrationEvidencePair {
	t.Helper()

	oldPolicy := legacy.GetAuthPolicy()
	newNamespace := unified.Policy.Namespaces[policy.AuthnNamespace]

	switch field {
	case migrationFieldLocalization:
		oldMeaning := legacyLocalizationMeaning(oldPolicy.Localization)
		newMeaning := unifiedLocalizationMeaning(newNamespace.Localization)

		return migrationEvidencePair{oldMeaning, newMeaning, oldPolicy.Localization.Catalogs[0].Entries["denied"], newNamespace.Localization.Catalogs[0].Entries["denied"]}
	case migrationFieldNetworks:
		oldMeaning := networkSetMeaning(oldPolicy.Sets.Networks)
		newMeaning := networkSetMeaning(newNamespace.ConditionSets.Networks)

		return migrationEvidencePair{oldMeaning, newMeaning, oldPolicy.Sets.Networks["trusted"][0], newNamespace.ConditionSets.Networks["trusted"][0]}
	case migrationFieldStrings:
		oldMeaning := stringSetMeaning(oldPolicy.Sets.Strings)
		newMeaning := stringSetMeaning(newNamespace.ConditionSets.Strings)

		return migrationEvidencePair{oldMeaning, newMeaning, oldPolicy.Sets.Strings["privileged"][0], newNamespace.ConditionSets.Strings["privileged"][0]}
	case migrationFieldTimeWindows:
		oldMeaning := legacyTimeWindowMeaning(oldPolicy.Sets.TimeWindows)
		newMeaning := unifiedTimeWindowMeaning(newNamespace.ConditionSets.TimeWindows)

		return migrationEvidencePair{oldMeaning, newMeaning, oldPolicy.Sets.TimeWindows["office"].Timezone, newNamespace.ConditionSets.TimeWindows["office"].Timezone}
	case migrationFieldLuaEnvironment:
		oldMeaning := legacyLuaProviderMeaning(oldPolicy.AttributeSources.Lua)
		newMeaning := unifiedLuaProviderMeaning(newNamespace.Providers)

		return migrationEvidencePair{oldMeaning, newMeaning, migrationIdentityFromMeaning(oldMeaning), migrationIdentityFromMeaning(newMeaning)}
	case migrationFieldLuaSubject:
		oldMeaning := legacyLuaProviderMeaning(oldPolicy.AttributeSources.Lua)
		newMeaning := unifiedLuaProviderMeaning(newNamespace.Providers)

		return migrationEvidencePair{oldMeaning, newMeaning, migrationIdentityFromMeaning(oldMeaning), migrationIdentityFromMeaning(newMeaning)}
	case migrationFieldLuaEffect:
		oldMeaning := legacyLuaEffectMeaning(oldPolicy.ObligationTargets.Lua)
		newMeaning := unifiedLuaEffectMeaning(newNamespace.Effects)

		return migrationEvidencePair{oldMeaning, newMeaning, migrationIdentityFromMeaning(oldMeaning), migrationIdentityFromMeaning(newMeaning)}
	default:
		t.Fatalf("field %d is not normalized-source evidence", field)

		return migrationEvidencePair{}
	}
}

// migrationIdentityFromMeaning selects the exact qualified identity from one single-row projection.
func migrationIdentityFromMeaning(values []string) string {
	if len(values) != 1 {
		return ""
	}

	identity, _, _ := strings.Cut(values[0], "|")

	return identity
}

// actualCatalogMigrationEvidence compiles one old snapshot and one standalone target catalog.
func actualCatalogMigrationEvidence(
	t *testing.T,
	legacy *config.FileSettings,
	unified policyconfig.Document,
	field migrationEvidenceField,
) migrationEvidencePair {
	t.Helper()

	prepareLegacyMigrationRow(legacy, field)
	prepared := prepareUnifiedMigrationRow(unified, field)

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{Config: legacy, Generation: 1})
	if err != nil {
		t.Fatalf("compile old row evidence: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), prepared)
	if err != nil {
		t.Fatalf("normalize new row evidence: %v", err)
	}

	catalog := compileUnifiedMigrationFixture(t, input)
	target := mustCatalogTarget(t, catalog, "authn/authenticate")

	switch field {
	case migrationFieldMode:
		return migrationEvidencePair{snapshot.Mode, string(target.AuthorityMode()), snapshot.Mode, string(target.AuthorityMode())}
	case migrationFieldDefaultPolicy:
		oldDefault := qualifyStandardAuth(snapshot.DefaultPolicy)
		newDefault := target.DefaultPolicySet().String()

		return migrationEvidencePair{oldDefault, newDefault, oldDefault, newDefault}
	case migrationFieldSchedulerGuards:
		oldMeaning := legacyCompiledAuxiliaryMeaning(snapshot).SchedulerGuard
		newMeaning := unifiedCompiledAuxiliaryMeaning(t, catalog).SchedulerGuard

		return migrationEvidencePair{oldMeaning, newMeaning, oldMeaning[0].OnMissing, newMeaning[0].OnMissing}
	case migrationFieldReport:
		oldMeaning := snapshotReportMeaning(snapshot.Report)
		newMeaning := compiledTargetReportMeaning(target.Report())

		return migrationEvidencePair{oldMeaning, newMeaning, oldMeaning.IncludeAttributes, newMeaning.IncludeAttributes}
	case migrationFieldChecks:
		return compiledCheckRowEvidence(t, legacy, snapshot, target)
	case migrationFieldRules:
		return compiledRuleRowEvidence(t, snapshot, target)
	default:
		t.Fatalf("field %d is not actual-catalog evidence", field)

		return migrationEvidencePair{}
	}
}

// prepareLegacyMigrationRow completes only the executable context absent from a focused old rule row.
func prepareLegacyMigrationRow(legacy *config.FileSettings, field migrationEvidenceField) {
	if field != migrationFieldRules {
		return
	}

	legacy.Auth.Policy.Checks = []config.PolicyCheckConfig{{
		Name: "risk", Type: policy.CheckTypeBruteForce, Stage: string(policy.StagePreAuth),
		Operations: []string{string(policy.OperationAuthenticate)}, ConfigRef: "auth.controls.brute_force.buckets",
	}}
}

// prepareUnifiedMigrationRow completes target activation around one focused standalone row.
func prepareUnifiedMigrationRow(document policyconfig.Document, field migrationEvidenceField) policyconfig.Document {
	if len(document.Policy.Targets) > 0 {
		return policyconfig.Normalize(document)
	}

	authn := document.Policy.Namespaces[policy.AuthnNamespace]
	target := policyconfig.TargetConfig{
		Namespace: policy.AuthnNamespace, Action: string(policy.OperationAuthenticate),
		Schema: "authn/authenticate/v1", DefaultPolicy: registry.BuiltinStandardAuthPolicySet,
	}

	switch field {
	case migrationFieldSchedulerGuards:
		plan := authn.DomainPlans["password"]
		plan.Checkpoints = map[string]policyconfig.CheckpointConfig{
			string(policy.StagePreAuth): {},
		}
		authn.DomainPlans["password"] = plan
		target.DomainPlan = "authn/password"
	case migrationFieldChecks:
		target.DomainPlan = "authn/password"
	case migrationFieldRules:
		authn.DomainPlans = map[string]policyconfig.DomainPlanConfig{
			"password": {Checkpoints: map[string]policyconfig.CheckpointConfig{
				string(policy.StagePreAuth): {Providers: []policyconfig.ProviderInstanceConfig{{
					Name: "risk", Use: policy.AuthnProviderBruteForce,
					Actions: []string{string(policy.OperationAuthenticate)},
				}}},
			}},
		}
		target.DomainPlan = "authn/password"
		target.Plans = map[string]policyconfig.TargetPlanConfig{
			string(policy.StagePreAuth): {PolicySets: []string{"authn/configured"}},
		}
	}

	document.Policy.Namespaces[policy.AuthnNamespace] = authn
	document.Policy.Targets = []policyconfig.TargetConfig{target}

	return policyconfig.Normalize(document)
}

// compiledCheckRowEvidence compares every scheduled field of one focused check/provider row.
func compiledCheckRowEvidence(
	t *testing.T,
	legacy *config.FileSettings,
	snapshot *policyruntime.Snapshot,
	target policyruntime.CompiledTarget,
) migrationEvidencePair {
	t.Helper()

	oldCheckpoint := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	if len(oldCheckpoint.Checks) != 1 {
		t.Fatalf("old focused check count = %d, want 1", len(oldCheckpoint.Checks))
	}

	oldCheck := oldCheckpoint.Checks[0]

	available := availableMigrationProviderUses()
	for identity := range availableLegacyLuaSources(legacy.GetAuthPolicy().AttributeSources.Lua) {
		available[identity] = struct{}{}
	}

	use, err := resolveLegacyProviderUse(
		oldCheck.Type,
		oldCheck.Name,
		oldCheck.ConfigRef,
		available,
	)
	if err != nil {
		t.Fatalf("resolve focused old check: %v", err)
	}

	newCheckpoint, exists := target.DomainPlan().Checkpoint(string(policy.StagePreAuth))
	if !exists {
		t.Fatal("new focused pre_auth checkpoint is missing")
	}

	instances := newCheckpoint.ProviderInstances()
	if len(instances) != 1 {
		t.Fatalf("new focused provider count = %d, want 1", len(instances))
	}

	oldMeaning := legacyProviderMeaning(oldCheck, use)
	newMeaning := unifiedProviderMeaning(instances[0])

	return migrationEvidencePair{oldMeaning, newMeaning, oldMeaning.Use, newMeaning.Use}
}

// compiledRuleRowEvidence compares one rule after both focused fixtures receive execution context.
func compiledRuleRowEvidence(
	t *testing.T,
	snapshot *policyruntime.Snapshot,
	target policyruntime.CompiledTarget,
) migrationEvidencePair {
	t.Helper()

	oldCheckpoint := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	if len(oldCheckpoint.Policies) != 1 {
		t.Fatalf("old focused rule count = %d, want 1", len(oldCheckpoint.Policies))
	}

	newCheckpoint, exists := target.DomainPlan().Checkpoint(string(policy.StagePreAuth))
	if !exists {
		t.Fatal("new focused rule checkpoint is missing")
	}

	set, exists := lookupCompiledPolicySet(target, "authn/configured")
	if !exists || len(set.Rules()) != 1 {
		t.Fatal("new focused configured rule is missing")
	}

	newRule := set.Rules()[0]
	oldMeaning := legacyRuleMeaning(oldCheckpoint.Policies[0], map[string]string{
		"risk": policy.AuthnProviderBruteForce,
	})
	newMeaning := unifiedRuleMeaning(t, newRule, string(policy.OperationAuthenticate), newCheckpoint)

	return migrationEvidencePair{oldMeaning, newMeaning, string(oldCheckpoint.Policies[0].Stage), newRule.Checkpoint()}
}

// testOwnedSchemaSourceMigrationEvidence executes carrier-less row projections without catalog claims.
func testOwnedSchemaSourceMigrationEvidence(
	t *testing.T,
	legacy *config.FileSettings,
	unified policyconfig.Document,
	field migrationEvidenceField,
) migrationEvidencePair {
	t.Helper()

	newNamespace := unified.Policy.Namespaces[policy.AuthnNamespace]

	switch field {
	case migrationFieldRegistryScripts:
		oldMeaning := compileLegacyRowSchemaSources(t, legacy).RegistryFacts
		newMeaning := compileUnifiedRegistryFacts(t, newNamespace.SchemaContributions.Lua.RegistryScripts)

		return migrationEvidencePair{oldMeaning, newMeaning, oldMeaning[0].ID, newMeaning[0].ID}
	case migrationFieldHTTPHeaders:
		oldMeaning := compileLegacyRowSchemaSources(t, legacy).RequestSources
		newMeaning := compileUnifiedRequestSources(newNamespace.FactSources)

		return migrationEvidencePair{oldMeaning, newMeaning, oldMeaning[0].Fact, newMeaning[0].Fact}
	case migrationFieldGRPCMetadata:
		oldMeaning := compileLegacyRowSchemaSources(t, legacy).RequestSources
		newMeaning := compileUnifiedRequestSources(newNamespace.FactSources)

		return migrationEvidencePair{oldMeaning, newMeaning, oldMeaning[0].Fact, newMeaning[0].Fact}
	case migrationFieldBackendAttributes:
		oldMeaning := compileLegacyRowSchemaSources(t, legacy).BackendFacts
		newMeaning := compileUnifiedBackendFacts(newNamespace.FactSources.BackendAttributes)

		return migrationEvidencePair{
			oldMeaning, newMeaning,
			migrationCompiledSensitivity(oldMeaning[0]), migrationCompiledSensitivity(newMeaning[0]),
		}
	default:
		t.Fatalf("field %d is not test-owned schema/source evidence", field)

		return migrationEvidencePair{}
	}
}

// compileLegacyRowSchemaSources selects actual old compiler outputs for a focused schema/source row.
func compileLegacyRowSchemaSources(t *testing.T, legacy *config.FileSettings) testOwnedSchemaSourceMeaning {
	t.Helper()

	return legacyTestOwnedSchemaSourceMeaning(t, legacy)
}

// migrationCompiledSensitivity selects the value-detail sensitivity from one compiled backend fact.
func migrationCompiledSensitivity(attribute attributeDefinitionMeaning) string {
	for _, detail := range attribute.Details {
		parts := strings.Split(detail, "|")
		if len(parts) == 5 && (parts[0] == "value" || parts[0] == "values") {
			return parts[2]
		}
	}

	return ""
}

func TestPolicyMigrationNormalizedInputParity(t *testing.T) {
	legacy := loadLegacyMigrationFixture(t)
	unified := loadUnifiedMigrationInput(t)

	want := legacyNormalizedInputMeaning(t, legacy)
	got := unifiedNormalizedInputMeaning(t, unified)

	assertMigrationMeaningEqual(t, got, want)
}

func TestPolicyMigrationCompiledPlanParity(t *testing.T) {
	legacy := loadLegacyMigrationFixture(t)
	unified := loadUnifiedMigrationInput(t)
	catalog := compileUnifiedMigrationFixture(t, unified)

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{Config: legacy, Generation: 1})
	if err != nil {
		t.Fatalf("compile legacy fixture: %v", err)
	}

	want := legacyCompiledPlanMeaning(t, legacy, snapshot)
	got := unifiedCompiledPlanMeaning(t, catalog)

	assertMigrationMeaningEqual(t, got, want)
}

func TestPolicyMigrationCompiledCheckIdentityParity(t *testing.T) {
	for _, mapping := range legacyCheckMappings {
		t.Run(mapping.checkType, func(t *testing.T) {
			want := compileLegacyCheckIdentityVariant(t, mapping)
			got := compileUnifiedCheckIdentityVariant(t, mapping)

			assertMigrationMeaningEqual(t, got, want)

			if got.ObserveSafe != mapping.observeSafe {
				t.Fatalf("compiled observe_safe = %t, want normative default %t", got.ObserveSafe, mapping.observeSafe)
			}
		})
	}
}

func TestPolicyMigrationCompiledAuxiliarySemantics(t *testing.T) {
	legacy := loadLegacyMigrationFixture(t)
	unified := loadUnifiedMigrationInput(t)
	catalog := compileUnifiedMigrationFixture(t, unified)

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{Config: legacy, Generation: 1})
	if err != nil {
		t.Fatalf("compile legacy auxiliary fixture: %v", err)
	}

	want := legacyCompiledAuxiliaryMeaning(snapshot)
	got := unifiedCompiledAuxiliaryMeaning(t, catalog)

	assertMigrationMeaningEqual(t, got, want)
}

func TestPolicyMigrationTestOwnedSchemaSourceProjection(t *testing.T) {
	legacy := loadLegacyMigrationFixture(t)
	unified := loadUnifiedMigrationInput(t)

	want := legacyTestOwnedSchemaSourceMeaning(t, legacy)
	got := unifiedTestOwnedSchemaSourceMeaning(t, unified)

	assertMigrationMeaningEqual(t, got, want)
}

func TestConfigRefMigrationUseIdentities(t *testing.T) {
	available := availableMigrationProviderUses()

	for _, mapping := range legacyCheckMappings {
		t.Run(mapping.checkType, func(t *testing.T) {
			assertConfigRefResolution(t, mapping, available)
		})
	}
}

func TestPolicyMigrationCanonicalMissingPluginCapabilityRejected(t *testing.T) {
	for _, mapping := range legacyCheckMappings {
		if mapping.kind != migrationReferencePluginEnvironment && mapping.kind != migrationReferencePluginSubject {
			continue
		}

		t.Run(mapping.checkType, func(t *testing.T) {
			missing := mapping
			missing.checkName = mapping.missingCheck
			missing.canonicalRef = mapping.missingRef
			missing.canonicalUse = mapping.missingUse

			document := unifiedCheckIdentityDocument(missing)
			namespace := document.Policy.Namespaces[policy.AuthnNamespace]
			namespace.Providers = nil
			addUnifiedProvider(mapping, &namespace)

			availableLocal := strings.TrimPrefix(mapping.canonicalUse, policy.AuthnNamespace+"/")

			missingLocal := strings.TrimPrefix(missing.canonicalUse, policy.AuthnNamespace+"/")
			if _, exists := namespace.Providers[availableLocal]; !exists {
				t.Fatalf("available plugin capability %s is missing", mapping.canonicalUse)
			}

			if _, exists := namespace.Providers[missingLocal]; exists {
				t.Fatalf("missing plugin capability %s was unexpectedly declared", missing.canonicalUse)
			}

			document.Policy.Namespaces[policy.AuthnNamespace] = namespace

			_, err := configinput.Normalize(context.Background(), document)
			if err == nil || !strings.Contains(err.Error(), ".providers[0].use") {
				t.Fatalf("normalize canonical unavailable plugin provider = %v, want exact provider-use rejection", err)
			}
		})
	}
}

func TestPolicyMigrationLuaProviderIdentitiesRemainQualifiedAndDistinct(t *testing.T) {
	unified := loadUnifiedMigrationInput(t)
	catalog := compileUnifiedMigrationFixture(t, unified)
	namespace := unified.Policy.Namespaces[policy.AuthnNamespace]

	if _, exists := namespace.Providers["lua_environment_shared"]; !exists {
		t.Fatal("qualified Lua environment provider source is missing")
	}

	if _, exists := namespace.Providers["lua_subject_shared"]; !exists {
		t.Fatal("qualified Lua subject provider source is missing")
	}

	target := mustCatalogTarget(t, catalog, "authn/authenticate")
	for _, identity := range []string{"authn/lua_environment_shared", "authn/lua_subject_shared"} {
		if _, exists := target.LookupProvider(identity); !exists {
			t.Fatalf("compiled provider %q is missing", identity)
		}
	}
}

func TestStandardAuthMigrationDefaultIsQualified(t *testing.T) {
	legacy := loadLegacyMigrationFixture(t)
	unified := loadUnifiedMigrationInput(t)
	catalog := compileUnifiedMigrationFixture(t, unified)
	target := mustCatalogTarget(t, catalog, "authn/authenticate")

	if legacy.GetAuthPolicy().DefaultPolicy != policy.BuiltinDefaultSet {
		t.Fatalf("legacy default = %q, want %q", legacy.GetAuthPolicy().DefaultPolicy, policy.BuiltinDefaultSet)
	}

	if got := target.DefaultPolicySet().String(); got != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("unified default = %q, want %q", got, registry.BuiltinStandardAuthPolicySet)
	}
}

// assertConfigRefResolution proves empty, canonical, and unresolvable reference behavior for one row.
func assertConfigRefResolution(t *testing.T, mapping legacyCheckMapping, available map[string]struct{}) {
	t.Helper()

	got, err := resolveLegacyProviderUse(mapping.checkType, mapping.checkName, "", available)
	if mapping.emptyUse == "" {
		if err == nil {
			t.Fatalf("empty config_ref resolved to %q, want an explicit migration correction", got)
		}
	} else if err != nil || got != mapping.emptyUse {
		t.Fatalf("empty config_ref = %q, %v; want %q", got, err, mapping.emptyUse)
	}

	got, err = resolveLegacyProviderUse(mapping.checkType, mapping.checkName, mapping.canonicalRef, available)
	if err != nil || got != mapping.canonicalUse {
		t.Fatalf("canonical config_ref = %q, %v; want %q", got, err, mapping.canonicalUse)
	}

	if got, err = resolveLegacyProviderUse(mapping.checkType, mapping.checkName, mapping.invalidRef, available); err == nil {
		t.Fatalf("unresolvable config_ref resolved to %q", got)
	}

	if mapping.missingRef == "" {
		return
	}

	missingCheck := mapping.missingCheck
	if missingCheck == "" {
		missingCheck = mapping.checkName
	}

	if got, err = resolveLegacyProviderUse(mapping.checkType, missingCheck, mapping.missingRef, available); err == nil {
		t.Fatalf("canonical missing config_ref resolved to %q", got)
	}
}

// resolveLegacyProviderUse is the test-only oracle for the normative hard-cut identity table.
func resolveLegacyProviderUse(checkType string, checkName string, reference string, available map[string]struct{}) (string, error) {
	mapping, exists := findLegacyCheckMapping(checkType)
	if !exists {
		return "", fmt.Errorf("unknown legacy check type %q", checkType)
	}

	switch mapping.kind {
	case migrationReferenceFixed:
		return resolveFixedProviderUse(mapping, reference)
	case migrationReferenceLua:
		return resolveLuaProviderUse(mapping, checkName, reference, available)
	case migrationReferencePluginEnvironment:
		return resolvePluginEnvironmentUse(mapping, reference, available)
	case migrationReferencePluginSubject:
		return resolvePluginSubjectUse(mapping, checkName, reference, available)
	default:
		return "", errors.New("unsupported migration reference kind")
	}
}

// findLegacyCheckMapping resolves one row from the sole test-owned mapping authority.
func findLegacyCheckMapping(checkType string) (legacyCheckMapping, bool) {
	for _, mapping := range legacyCheckMappings {
		if mapping.checkType == checkType {
			return mapping, true
		}
	}

	return legacyCheckMapping{}, false
}

// resolveFixedProviderUse discards only suffixes below the exact accepted old owner.
func resolveFixedProviderUse(mapping legacyCheckMapping, reference string) (string, error) {
	if reference == "" || reference == mapping.prefix || strings.HasPrefix(reference, mapping.prefix+".") {
		return mapping.canonicalUse, nil
	}

	return "", fmt.Errorf("reference %q is outside %s", reference, mapping.prefix)
}

// resolveLuaProviderUse qualifies one existing environment or subject source without collisions.
func resolveLuaProviderUse(mapping legacyCheckMapping, checkName string, reference string, available map[string]struct{}) (string, error) {
	source := checkName

	if reference != "" {
		if !strings.HasPrefix(reference, mapping.prefix) {
			return "", fmt.Errorf("reference %q is outside %s", reference, mapping.prefix)
		}

		source = strings.TrimPrefix(reference, mapping.prefix)
	}

	kind := "environment"
	if mapping.checkType == policy.CheckTypeLuaSubjectSource {
		kind = "subject"
	}

	if source == "" || strings.Contains(source, ".") {
		return "", fmt.Errorf("source %q is not canonical", source)
	}

	use := mapping.usePrefix + source
	if _, exists := available[use]; !exists {
		return "", fmt.Errorf("source %s/%s does not exist", kind, source)
	}

	return use, nil
}

// resolvePluginEnvironmentUse retains the exact module identity from a canonical old reference.
func resolvePluginEnvironmentUse(
	mapping legacyCheckMapping,
	reference string,
	available map[string]struct{},
) (string, error) {
	module, suffix, ok := splitPluginReference(mapping.prefix, reference)
	if !ok || suffix != "environment" {
		return "", fmt.Errorf("plugin environment reference %q is unresolvable", reference)
	}

	use := mapping.usePrefix + module + ".environment"
	if _, exists := available[use]; !exists {
		return "", fmt.Errorf("plugin environment capability %q does not exist", use)
	}

	return use, nil
}

// resolvePluginSubjectUse combines the canonical module with the generated check-local suffix.
func resolvePluginSubjectUse(
	mapping legacyCheckMapping,
	checkName string,
	reference string,
	available map[string]struct{},
) (string, error) {
	module, suffix, ok := splitPluginReference(mapping.prefix, reference)
	if !ok || suffix != "subject" {
		return "", fmt.Errorf("plugin subject reference %q is unresolvable", reference)
	}

	local, ok := strings.CutPrefix(checkName, "plugin_subject_"+module+"_")
	if !ok || local == "" || strings.Contains(local, ".") {
		return "", fmt.Errorf("plugin subject check %q has no local identity", checkName)
	}

	use := mapping.usePrefix + module + ".subject." + local
	if _, exists := available[use]; !exists {
		return "", fmt.Errorf("plugin subject capability %q does not exist", use)
	}

	return use, nil
}

// availableMigrationProviderUses returns the exact capability set declared by the sole identity table.
func availableMigrationProviderUses() map[string]struct{} {
	result := make(map[string]struct{}, len(legacyCheckMappings))
	for _, mapping := range legacyCheckMappings {
		result[mapping.canonicalUse] = struct{}{}
	}

	return result
}

// splitPluginReference extracts one module and one terminal capability from an exact old path.
func splitPluginReference(prefix string, reference string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(reference, prefix)
	if !ok {
		return "", "", false
	}

	parts := strings.Split(remainder, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// loadLegacyMigrationFixture decodes the frozen old root without invoking production loading.
func loadLegacyMigrationFixture(t *testing.T) *config.FileSettings {
	t.Helper()

	source, err := os.ReadFile(legacyMigrationFixture)
	if err != nil {
		t.Fatalf("read legacy fixture: %v", err)
	}

	var settings map[string]any
	if err = yaml.Unmarshal(source, &settings); err != nil {
		t.Fatalf("decode legacy YAML: %v", err)
	}

	result := &config.FileSettings{}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		Result:           result,
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
	})
	if err != nil {
		t.Fatalf("create legacy fixture decoder: %v", err)
	}

	if err = decoder.Decode(settings); err != nil {
		t.Fatalf("decode legacy fixture: %v", err)
	}

	return result
}

// loadUnifiedMigrationInput decodes and normalizes the standalone root without conflating catalog evidence.
func loadUnifiedMigrationInput(t *testing.T) configinput.UnifiedPolicyInput {
	t.Helper()

	source, err := os.Open(unifiedMigrationFixture)
	if err != nil {
		t.Fatalf("open unified fixture: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := source.Close(); closeErr != nil {
			t.Errorf("close unified fixture: %v", closeErr)
		}
	})

	document, err := policyconfig.Decode("yaml", source)
	if err != nil {
		t.Fatalf("decode unified fixture: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize unified fixture: %v", err)
	}

	return input
}

// compileUnifiedMigrationFixture builds the separately asserted actual unified catalog plan.
func compileUnifiedMigrationFixture(t *testing.T, input configinput.UnifiedPolicyInput) *policyruntime.TargetCatalog {
	t.Helper()

	catalog, err := input.Compile(context.Background(), migrationAcceptance{})
	if err != nil {
		t.Fatalf("compile unified fixture: %v", err)
	}

	return catalog
}

// compileLegacyCheckIdentityVariant compiles one old check row into detached identity semantics.
func compileLegacyCheckIdentityVariant(t *testing.T, mapping legacyCheckMapping) compiledCheckIdentityMeaning {
	t.Helper()

	configured := legacyCheckIdentityConfig(mapping)

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{Config: configured, Generation: 1})
	if err != nil {
		t.Fatalf("compile legacy %s variant: %v", mapping.checkType, err)
	}

	checkpoint, exists := snapshot.StagePlans[mapping.action][mapping.checkpoint]
	if !exists {
		t.Fatalf("legacy %s checkpoint %s is missing", mapping.checkType, mapping.checkpoint)
	}

	if len(checkpoint.Checks) != 1 || len(checkpoint.Policies) != 1 {
		t.Fatalf("legacy %s checkpoint has %d checks and %d rules, want 1/1", mapping.checkType, len(checkpoint.Checks), len(checkpoint.Policies))
	}

	use, err := resolveLegacyProviderUse(
		checkpoint.Checks[0].Type,
		checkpoint.Checks[0].Name,
		checkpoint.Checks[0].ConfigRef,
		availableMigrationProviderUses(),
	)
	if err != nil {
		t.Fatalf("resolve compiled legacy %s check: %v", mapping.checkType, err)
	}

	production, comparison := legacyPolicySetAuthority(snapshot.Mode, true)

	check := checkpoint.Checks[0]
	rule := checkpoint.Policies[0]

	return compiledCheckIdentityMeaning{
		CheckpointOrder:       legacyCheckpointOrder(snapshot, mapping.action),
		ProviderInstanceOrder: []string{check.Name},
		ProviderUseOrder:      []string{use},
		ProviderActions:       policyOperationsMeaning(check.Operations),
		ProviderLevels:        legacyProviderLevels(checkpoint.Checks),
		RequiredInstances:     append([]string(nil), rule.RequireChecks...),
		RequiredProviderUses:  []string{use},
		ProductionPolicySet:   production,
		ComparisonPolicySet:   comparison,
		Checkpoint:            string(checkpoint.Stage),
		RuleCheckpoint:        string(rule.Stage),
		Action:                string(mapping.action),
		RunIf:                 normalizedRunIf(check.RunIf.AuthState),
		ObserveSafe:           check.ObserveSafe,
	}
}

// legacyCheckIdentityConfig builds one isolated old compiler fixture from a normative row.
func legacyCheckIdentityConfig(mapping legacyCheckMapping) *config.FileSettings {
	always := true
	policySection := config.AuthPolicySection{
		Mode:          string(registry.AuthorityModeObserve),
		DefaultPolicy: policy.BuiltinDefaultSet,
		Checks: []config.PolicyCheckConfig{{
			Name: mapping.checkName, Type: mapping.checkType, Stage: string(mapping.checkpoint),
			Operations: []string{string(mapping.action)}, ConfigRef: mapping.canonicalRef,
		}},
		Policies: []config.PolicyRuleConfig{{
			Name: "requires_" + mapping.checkName, Stage: string(mapping.checkpoint),
			Operations: []string{string(mapping.action)}, RequireChecks: []string{mapping.checkName},
			If: config.PolicyConditionConfig{Always: &always},
			Then: config.PolicyThenConfig{
				Decision:       string(policy.DecisionDeny),
				ResponseMarker: policy.ResponseMarkerFail,
			},
		}},
	}

	switch mapping.checkType {
	case policy.CheckTypeLuaEnvironment:
		policySection.AttributeSources.Lua.Environment = []config.LuaEnvironmentSource{{
			Name: mapping.checkName, ScriptPath: "/test/migration_environment.lua",
		}}
	case policy.CheckTypeLuaSubjectSource:
		policySection.AttributeSources.Lua.Subject = []config.LuaSubjectSource{{
			Name: mapping.checkName, ScriptPath: "/test/migration_subject.lua",
		}}
	}

	return &config.FileSettings{Auth: &config.AuthSection{Policy: policySection}}
}

// legacyCheckpointOrder returns the actual ordered old checkpoints present for one action.
func legacyCheckpointOrder(snapshot *policyruntime.Snapshot, action policy.Operation) []string {
	result := make([]string, 0)

	for _, checkpoint := range authnCheckpointOrder() {
		if _, exists := snapshot.StagePlans[action][checkpoint]; exists {
			result = append(result, string(checkpoint))
		}
	}

	return result
}

// compileUnifiedCheckIdentityVariant compiles one standalone row through the actual target catalog.
func compileUnifiedCheckIdentityVariant(t *testing.T, mapping legacyCheckMapping) compiledCheckIdentityMeaning {
	t.Helper()

	input := normalizeUnifiedCheckIdentityVariant(t, mapping)

	catalog, err := input.Compile(context.Background(), migrationAcceptance{})
	if err != nil {
		t.Fatalf("compile unified %s variant: %v", mapping.checkType, err)
	}

	target := mustCatalogTarget(t, catalog, policy.AuthnNamespace+"/"+string(mapping.action))
	checkpoints := target.DomainPlan().Checkpoints()

	checkpoint, exists := target.DomainPlan().Checkpoint(string(mapping.checkpoint))
	if !exists {
		t.Fatalf("unified %s checkpoint %s is missing", mapping.checkType, mapping.checkpoint)
	}

	set, exists := lookupCompiledPolicySet(target, "authn/configured")
	if !exists || len(set.Rules()) != 1 {
		t.Fatalf("unified %s configured rules = %d, want 1", mapping.checkType, len(set.Rules()))
	}

	rule := set.Rules()[0]

	instances := checkpoint.ProviderInstances()
	if len(instances) != 1 {
		t.Fatalf("unified %s provider instances = %d, want 1", mapping.checkType, len(instances))
	}

	requiredInstances := rule.RequiredProviders()

	return compiledCheckIdentityMeaning{
		CheckpointOrder:       compiledCheckpointNames(checkpoints),
		ProviderInstanceOrder: compiledProviderInstanceNames(instances),
		ProviderUseOrder:      checkpoint.ProviderIDs(),
		ProviderActions:       instances[0].Actions(),
		ProviderLevels:        checkpoint.ProviderLevels(),
		RequiredInstances:     requiredInstances,
		RequiredProviderUses:  compiledRequiredProviderUses(t, checkpoint, requiredInstances),
		ProductionPolicySet:   checkpoint.ProductionPolicySetIDs(),
		ComparisonPolicySet:   checkpoint.ComparisonPolicySetIDs(),
		Checkpoint:            checkpoint.Name(),
		RuleCheckpoint:        rule.Checkpoint(),
		Action:                target.Target().Action(),
		RunIf:                 normalizedRunIf(instances[0].RunIfAuthState()),
		ObserveSafe:           instances[0].ObserveSafe(),
	}
}

// normalizeUnifiedCheckIdentityVariant builds and normalizes one isolated standalone row.
func normalizeUnifiedCheckIdentityVariant(t *testing.T, mapping legacyCheckMapping) configinput.UnifiedPolicyInput {
	t.Helper()

	document := unifiedCheckIdentityDocument(mapping)

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize unified %s variant: %v", mapping.checkType, err)
	}

	return input
}

// unifiedCheckIdentityDocument maps one normative row into one isolated standalone authority.
func unifiedCheckIdentityDocument(mapping legacyCheckMapping) policyconfig.Document {
	always := true
	provider := policyconfig.ProviderInstanceConfig{
		Name: mapping.checkName, Use: mapping.canonicalUse, Actions: []string{string(mapping.action)},
	}
	namespace := policyconfig.NamespaceConfig{
		DomainPlans: map[string]policyconfig.DomainPlanConfig{
			"migration_identity": {
				Checkpoints: map[string]policyconfig.CheckpointConfig{
					string(mapping.checkpoint): {Providers: []policyconfig.ProviderInstanceConfig{provider}},
				},
			},
		},
		PolicySets: map[string]policyconfig.PolicySetConfig{
			"configured": {
				Visibility: policyconfig.VisibilityPrivate,
				Rules: []policyconfig.PolicyRuleConfig{{
					Name: "requires_" + mapping.checkName, Checkpoint: string(mapping.checkpoint),
					Actions: []string{string(mapping.action)}, RequireProviders: []string{mapping.checkName},
					If: policyconfig.ConditionConfig{Always: &always},
					Then: policyconfig.ThenConfig{
						Decision:       string(decision.EffectDeny),
						ResponseMarker: policy.ResponseMarkerFail,
					},
				}},
			},
		},
	}

	addUnifiedProvider(mapping, &namespace)

	return policyconfig.Document{Policy: policyconfig.PolicyConfig{
		Namespaces: map[string]policyconfig.NamespaceConfig{policy.AuthnNamespace: namespace},
		Targets: []policyconfig.TargetConfig{{
			Namespace: policy.AuthnNamespace, Action: string(mapping.action), Schema: authnSchema(mapping.action),
			DomainPlan: "authn/migration_identity", Mode: string(registry.AuthorityModeObserve),
			DefaultPolicy: registry.BuiltinStandardAuthPolicySet,
			Plans: map[string]policyconfig.TargetPlanConfig{
				string(mapping.checkpoint): {PolicySets: []string{"authn/configured"}},
			},
		}},
	}}
}

// addUnifiedProvider supplies the config-owned definition required by extensible identity rows.
func addUnifiedProvider(mapping legacyCheckMapping, namespace *policyconfig.NamespaceConfig) {
	if mapping.kind == migrationReferenceFixed {
		return
	}

	kind := "plugin"
	scriptPath := ""
	module := ""

	if mapping.kind == migrationReferenceLua {
		kind = "lua_environment"
		if mapping.checkType == policy.CheckTypeLuaSubjectSource {
			kind = "lua_subject"
		}

		scriptPath = "/test/" + strings.TrimPrefix(mapping.canonicalUse, policy.AuthnNamespace+"/") + ".lua"
	} else {
		module, _, _ = splitPluginReference(mapping.prefix, mapping.canonicalRef)
	}

	local := strings.TrimPrefix(mapping.canonicalUse, policy.AuthnNamespace+"/")
	namespace.Providers = map[string]policyconfig.ProviderConfig{
		local: {
			Kind: kind, ScriptPath: scriptPath, Module: module,
			Targets:    []policyconfig.TargetReferenceConfig{{Action: string(mapping.action)}},
			Executions: []string{string(registry.ExecutionHostSync)},
		},
	}
}

// compiledCheckpointNames returns the exact catalog checkpoint order.
func compiledCheckpointNames(checkpoints []policyruntime.CompiledCheckpoint) []string {
	result := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		result = append(result, checkpoint.Name())
	}

	return result
}

// compiledProviderInstanceNames returns exact checkpoint-local identities in catalog order.
func compiledProviderInstanceNames(instances []policyruntime.CompiledProviderInstance) []string {
	result := make([]string, 0, len(instances))
	for _, instance := range instances {
		result = append(result, instance.Name())
	}

	return result
}

// legacyProviderLevels detaches the old authored dependency graph into deterministic execution levels.
func legacyProviderLevels(checks []policyruntime.CompiledCheck) [][]string {
	remaining := make(map[string]int, len(checks))
	dependants := make(map[string][]string, len(checks))

	for _, check := range checks {
		remaining[check.Name] = len(check.After)
		for _, dependency := range check.After {
			dependants[dependency] = append(dependants[dependency], check.Name)
		}
	}

	levels := make([][]string, 0)
	for len(remaining) > 0 {
		level := make([]string, 0)

		for name, count := range remaining {
			if count == 0 {
				level = append(level, name)
			}
		}

		if len(level) == 0 {
			return nil
		}

		sort.Strings(level)

		levels = append(levels, level)

		for _, name := range level {
			delete(remaining, name)

			for _, dependant := range dependants[name] {
				remaining[dependant]--
			}
		}
	}

	return levels
}

// compiledRequiredProviderUses resolves rule dependencies through checkpoint-local instance identities.
func compiledRequiredProviderUses(
	t *testing.T,
	checkpoint policyruntime.CompiledCheckpoint,
	required []string,
) []string {
	t.Helper()

	result := make([]string, 0, len(required))
	if len(required) == 0 {
		return nil
	}

	instances := checkpoint.ProviderInstances()
	for _, identity := range required {
		if instance, exists := checkpoint.LookupProviderInstance(identity); exists {
			result = append(result, instance.Use())

			continue
		}

		matched := ""

		for _, instance := range instances {
			if instance.Use() != identity {
				continue
			}

			if matched != "" {
				t.Fatalf("required provider %s is ambiguous at checkpoint %s", identity, checkpoint.Name())
			}

			matched = instance.Use()
		}

		if matched == "" {
			t.Fatalf("required provider %s is unscheduled at checkpoint %s", identity, checkpoint.Name())
		}

		result = append(result, matched)
	}

	return result
}

// authnSchema returns the immutable schema identity for one supported authn action.
func authnSchema(action policy.Operation) string {
	switch action {
	case policy.OperationAuthenticate:
		return "authn/authenticate/v1"
	case policy.OperationLookupIdentity:
		return "authn/lookup_identity/v1"
	case policy.OperationListAccounts:
		return "authn/list_accounts/v1"
	default:
		return ""
	}
}

// legacyCompiledAuxiliaryMeaning projects scheduler semantics from the actual old compiled snapshot.
func legacyCompiledAuxiliaryMeaning(snapshot *policyruntime.Snapshot) compiledAuxiliaryMeaning {
	return compiledAuxiliaryMeaning{
		SchedulerGuard: legacyCompiledGuardMeaning(snapshot.SchedulerGuards, snapshot.Sets.Strings),
	}
}

// unifiedCompiledAuxiliaryMeaning projects scheduler semantics only from the actual unified catalog.
func unifiedCompiledAuxiliaryMeaning(t *testing.T, catalog *policyruntime.TargetCatalog) compiledAuxiliaryMeaning {
	t.Helper()

	target := mustCatalogTarget(t, catalog, "authn/authenticate")

	return compiledAuxiliaryMeaning{
		SchedulerGuard: unifiedCompiledGuardMeaning(target.DomainPlan().SchedulerGuards()),
	}
}

// legacyTestOwnedSchemaSourceMeaning projects old compiled outputs without claiming a unified runtime carrier.
func legacyTestOwnedSchemaSourceMeaning(t *testing.T, file *config.FileSettings) testOwnedSchemaSourceMeaning {
	t.Helper()

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{Config: file, Generation: 1})
	if err != nil {
		t.Fatalf("compile legacy schema/source fixture: %v", err)
	}

	meaning := testOwnedSchemaSourceMeaning{
		RegistryFacts:  legacyLuaRegistryFactMeaning(snapshot.AttributeRegistry),
		RequestSources: legacyCompiledRequestSourceMeaning(snapshot.RequestAttributes),
	}

	for _, export := range file.GetAuthPolicy().AttributeExports {
		identity := policy.SubjectAttributeID(policy.IdentifierSegment(export.Name))

		definition, exists := snapshot.AttributeRegistry[identity]
		if !exists {
			t.Fatalf("compiled backend fact %s is missing", identity)
		}

		meaning.BackendFacts = append(meaning.BackendFacts, attributeMeaning(definition))
	}

	sortAttributeMeanings(meaning.BackendFacts)

	return meaning
}

// unifiedTestOwnedSchemaSourceMeaning runs carrier-less standalone inputs through test-only semantic compilers.
func unifiedTestOwnedSchemaSourceMeaning(t *testing.T, input configinput.UnifiedPolicyInput) testOwnedSchemaSourceMeaning {
	t.Helper()

	namespace := input.Policy.Namespaces[policy.AuthnNamespace]

	return testOwnedSchemaSourceMeaning{
		RegistryFacts:  compileUnifiedRegistryFacts(t, namespace.SchemaContributions.Lua.RegistryScripts),
		BackendFacts:   compileUnifiedBackendFacts(namespace.FactSources.BackendAttributes),
		RequestSources: compileUnifiedRequestSources(namespace.FactSources),
	}
}

// legacyLuaRegistryFactMeaning selects actual Lua-created schema definitions from the old snapshot.
func legacyLuaRegistryFactMeaning(definitions map[string]registry.AttributeDefinition) []attributeDefinitionMeaning {
	result := make([]attributeDefinitionMeaning, 0)

	for _, definition := range definitions {
		if definition.Source == registry.SourceLua {
			result = append(result, attributeMeaning(definition))
		}
	}

	sortAttributeMeanings(result)

	return result
}

// attributeMeaning detaches one compiled attribute definition into comparison semantics.
func attributeMeaning(definition registry.AttributeDefinition) attributeDefinitionMeaning {
	operations := make([]string, 0, len(definition.Operations))
	for _, operation := range definition.Operations {
		operations = append(operations, string(operation))
	}

	details := make([]string, 0, len(definition.Details))
	for _, name := range sortedKeys(definition.Details) {
		detail := definition.Details[name]
		details = append(details, fmt.Sprintf(
			"%s|%s|%s|%s|%d",
			name,
			detail.Type,
			detail.Sensitivity,
			detail.Purpose,
			detail.MaxLength,
		))
	}

	return attributeDefinitionMeaning{
		ID: definition.ID, Stage: string(definition.Stage), Category: string(definition.Category),
		Type: string(definition.Type), Source: string(definition.Source), Operations: operations, Details: details,
	}
}

// sortAttributeMeanings orders detached schema output by exact fact identity.
func sortAttributeMeanings(values []attributeDefinitionMeaning) {
	sort.Slice(values, func(left int, right int) bool {
		return values[left].ID < values[right].ID
	})
}

// compileUnifiedRegistryFacts executes standalone script paths through the frozen test-only registry oracle.
func compileUnifiedRegistryFacts(t *testing.T, scripts []string) []attributeDefinitionMeaning {
	t.Helper()

	settings := &config.FileSettings{Auth: &config.AuthSection{Policy: config.AuthPolicySection{
		Mode: string(registry.AuthorityModeEnforce), DefaultPolicy: policy.BuiltinDefaultSet,
		RegistryScripts: append([]string(nil), scripts...),
	}}}

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{Config: settings, Generation: 1})
	if err != nil {
		t.Fatalf("compile unified registry script output: %v", err)
	}

	return legacyLuaRegistryFactMeaning(snapshot.AttributeRegistry)
}

// compileUnifiedBackendFacts projects standalone backend sources into their generated subject schema.
func compileUnifiedBackendFacts(configured []policyconfig.BackendAttributeFactSourceConfig) []attributeDefinitionMeaning {
	result := make([]attributeDefinitionMeaning, 0, len(configured))

	for _, source := range configured {
		valueType := source.Type

		valueDetail := "value"
		if valueType == "string_list" {
			valueDetail = "values"
		}

		result = append(result, attributeDefinitionMeaning{
			ID: policy.SubjectAttributeID(policy.IdentifierSegment(source.Name)), Stage: string(policy.StageAuthBackend),
			Category: string(registry.AttributeCategorySubject), Type: string(registry.AttributeTypeBool),
			Source:     string(registry.SourceBuiltin),
			Operations: []string{string(policy.OperationAuthenticate), string(policy.OperationLookupIdentity)},
			Details: []string{
				"attribute|string|internal||0",
				"count|number|internal||0",
				fmt.Sprintf("%s|%s|%s||0", valueDetail, valueType, normalizedSensitivity(source.Sensitivity)),
			},
		})
	}

	sortAttributeMeanings(result)

	return result
}

// normalizedSensitivity applies the old compiler default for backend fact details.
func normalizedSensitivity(value string) string {
	if value == "" {
		return registry.DetailSensitivityInternal
	}

	return value
}

// legacyCompiledGuardMeaning restores set identities around actual old typed scheduler guards.
func legacyCompiledGuardMeaning(
	guards map[string]policyruntime.CompiledSchedulerGuard,
	stringSets map[string][]string,
) []compiledGuardMeaning {
	result := make([]compiledGuardMeaning, 0, len(guards))

	for _, name := range sortedKeys(guards) {
		guard := guards[name]
		values := compiledGuardValues(guard.Root.Expected.Value)

		operator := string(guard.Root.Operator)
		if guard.Root.Kind == policyruntime.ExprKindAlways {
			operator = string(registry.ExpressionOperatorAlways)
		}

		reference := legacyCompiledGuardReference(values, stringSets)
		if reference != "" {
			values = nil
		}

		result = append(result, compiledGuardMeaning{
			Name: name, Fact: guard.Root.AttributeID, FactKind: canonicalLegacyFactKind(guard.Root.ValueType),
			Operator: operator, Reference: reference, OnMissing: guard.OnMissingAttribute,
			Values: values,
		})
	}

	return result
}

// unifiedCompiledGuardMeaning projects immutable guard expressions from the actual target catalog.
func unifiedCompiledGuardMeaning(guards []registry.SchedulerGuardDefinition) []compiledGuardMeaning {
	result := make([]compiledGuardMeaning, 0, len(guards))
	for _, guard := range guards {
		expression := guard.Expression()

		var values []string
		for _, value := range expression.Values() {
			values = append(values, decisionValueMeaning(value))
		}

		result = append(result, compiledGuardMeaning{
			Name: guard.Name(), Fact: expression.FactID(), FactKind: string(expression.FactKind()),
			Operator: string(expression.Operator()), Reference: expression.Reference(),
			OnMissing: guard.OnMissingAttribute(), Values: values,
		})
	}

	sort.Slice(result, func(left int, right int) bool {
		return result[left].Name < result[right].Name
	})

	return result
}

// legacyCompiledGuardReference identifies the compiled old string set by exact detached members.
func legacyCompiledGuardReference(values []string, stringSets map[string][]string) string {
	for _, name := range sortedKeys(stringSets) {
		if slices.Equal(values, compiledGuardValues(stringSets[name])) {
			return "@string." + name
		}
	}

	return ""
}

// compiledGuardValues detaches one compiled scalar or string-set operand.
func compiledGuardValues(value any) []string {
	if values, ok := value.([]string); ok {
		result := make([]string, 0, len(values))
		for _, member := range values {
			result = append(result, semanticValue(member))
		}

		return result
	}

	if value == nil {
		return nil
	}

	return []string{semanticValue(value)}
}

// legacyCompiledRequestSourceMeaning projects actual old header and metadata normalization plans.
func legacyCompiledRequestSourceMeaning(settings policyruntime.RequestAttributeSettings) []compiledRequestSourceMeaning {
	result := make([]compiledRequestSourceMeaning, 0, len(settings.Headers)+len(settings.Metadata))
	for _, source := range settings.Headers {
		result = append(result, compiledRequestSourceMeaning{
			Transport: "http_header", Source: source.Header, Fact: source.Attribute,
			Trim: source.Normalize.Trim, Case: source.Normalize.Case, MaxLength: source.Normalize.MaxLength,
		})
	}

	for _, source := range settings.Metadata {
		result = append(result, compiledRequestSourceMeaning{
			Transport: "grpc_metadata", Source: source.Key, Fact: source.Attribute,
			Trim: source.Normalize.Trim, Case: source.Normalize.Case, MaxLength: source.Normalize.MaxLength,
		})
	}

	sortRequestSourceMeanings(result)

	return result
}

// compileUnifiedRequestSources applies transport canonicalization to standalone source declarations.
func compileUnifiedRequestSources(configured policyconfig.FactSourcesConfig) []compiledRequestSourceMeaning {
	result := make([]compiledRequestSourceMeaning, 0, len(configured.HTTPHeaders)+len(configured.GRPCMetadata))
	for _, source := range configured.HTTPHeaders {
		result = append(result, compiledRequestSourceMeaning{
			Transport: "http_header", Source: textproto.CanonicalMIMEHeaderKey(source.Header), Fact: source.Attribute,
			Trim: source.Normalize.Trim, Case: source.Normalize.Case, MaxLength: source.Normalize.MaxLength,
		})
	}

	for _, source := range configured.GRPCMetadata {
		result = append(result, compiledRequestSourceMeaning{
			Transport: "grpc_metadata", Source: strings.ToLower(source.Key), Fact: source.Attribute,
			Trim: source.Normalize.Trim, Case: source.Normalize.Case, MaxLength: source.Normalize.MaxLength,
		})
	}

	sortRequestSourceMeanings(result)

	return result
}

// sortRequestSourceMeanings orders compiled request projections independently from decoder order.
func sortRequestSourceMeanings(values []compiledRequestSourceMeaning) {
	sort.Slice(values, func(left int, right int) bool {
		if values[left].Transport == values[right].Transport {
			return values[left].Source < values[right].Source
		}

		return values[left].Transport < values[right].Transport
	})
}

// legacyNormalizedInputMeaning projects fields retained before the old runtime plan boundary.
func legacyNormalizedInputMeaning(t *testing.T, file *config.FileSettings) normalizedInputMeaning {
	t.Helper()

	configured := file.GetAuthPolicy()
	meaning := normalizedInputMeaning{
		Localization:   legacyLocalizationMeaning(configured.Localization),
		Networks:       networkSetMeaning(configured.Sets.Networks),
		Strings:        stringSetMeaning(configured.Sets.Strings),
		TimeWindows:    legacyTimeWindowMeaning(configured.Sets.TimeWindows),
		SchedulerGuard: legacySchedulerGuardMeaning(configured.SchedulerGuards),
		RegistryScript: append([]string(nil), configured.RegistryScripts...),
		Providers:      legacyLuaProviderMeaning(configured.AttributeSources.Lua),
		Effects:        legacyLuaEffectMeaning(configured.ObligationTargets.Lua),
		Headers:        legacyHeaderMeaning(configured.RequestHeaders),
		Metadata:       legacyMetadataMeaning(configured.RequestMetadata),
		BackendExports: legacyBackendExportMeaning(configured.AttributeExports),
		Mode:           configured.Mode,
		DefaultPolicy:  qualifyStandardAuth(configured.DefaultPolicy),
		Report:         legacyReportMeaning(configured.Report),
	}

	return meaning
}

// unifiedNormalizedInputMeaning projects the normalized standalone compiler envelope.
func unifiedNormalizedInputMeaning(t *testing.T, input configinput.UnifiedPolicyInput) normalizedInputMeaning {
	t.Helper()

	namespace := input.Policy.Namespaces[policy.AuthnNamespace]
	target := mustConfiguredTarget(t, input.Policy, "authn/authenticate")

	return normalizedInputMeaning{
		Localization:   unifiedLocalizationMeaning(namespace.Localization),
		Networks:       networkSetMeaning(namespace.ConditionSets.Networks),
		Strings:        stringSetMeaning(namespace.ConditionSets.Strings),
		TimeWindows:    unifiedTimeWindowMeaning(namespace.ConditionSets.TimeWindows),
		SchedulerGuard: unifiedSchedulerGuardMeaning(namespace.DomainPlans["migrated_authenticate"].SchedulerGuards),
		RegistryScript: append([]string(nil), namespace.SchemaContributions.Lua.RegistryScripts...),
		Providers:      unifiedLuaProviderMeaning(namespace.Providers),
		Effects:        unifiedLuaEffectMeaning(namespace.Effects),
		Headers:        unifiedHeaderMeaning(namespace.FactSources.HTTPHeaders),
		Metadata:       unifiedMetadataMeaning(namespace.FactSources.GRPCMetadata),
		BackendExports: unifiedBackendExportMeaning(namespace.FactSources.BackendAttributes),
		Mode:           target.Mode,
		DefaultPolicy:  target.DefaultPolicy,
		Report:         unifiedReportMeaning(target.Report),
	}
}

// legacyCompiledPlanMeaning projects the frozen old runtime snapshot into hard-cut semantics.
func legacyCompiledPlanMeaning(t *testing.T, file *config.FileSettings, snapshot *policyruntime.Snapshot) compiledPlanMeaning {
	t.Helper()

	plan := compiledPlanMeaning{
		Target:        "authn/authenticate",
		Mode:          snapshot.Mode,
		DefaultPolicy: qualifyStandardAuth(snapshot.DefaultPolicy),
		Report:        snapshotReportMeaning(snapshot.Report),
	}

	available := availableLegacyLuaSources(file.GetAuthPolicy().AttributeSources.Lua)

	for _, stage := range authnCheckpointOrder() {
		checkpoint, exists := snapshot.StagePlans[policy.OperationAuthenticate][stage]
		if !exists {
			continue
		}

		plan.Checkpoints = append(plan.Checkpoints, legacyCheckpointMeaning(t, checkpoint, available, snapshot.Mode))
	}

	return plan
}

// unifiedCompiledPlanMeaning projects only immutable metadata carried by the actual unified catalog.
func unifiedCompiledPlanMeaning(t *testing.T, catalog *policyruntime.TargetCatalog) compiledPlanMeaning {
	t.Helper()

	target := mustCatalogTarget(t, catalog, "authn/authenticate")

	plan := compiledPlanMeaning{
		Target:        target.Target().String(),
		Mode:          string(target.AuthorityMode()),
		DefaultPolicy: target.DefaultPolicySet().String(),
		Report:        compiledTargetReportMeaning(target.Report()),
	}

	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		plan.Checkpoints = append(plan.Checkpoints, unifiedCheckpointMeaning(t, target, checkpoint))
	}

	return plan
}

// legacyCheckpointMeaning maps one old stage plan through the test-only identity oracle.
func legacyCheckpointMeaning(
	t *testing.T,
	checkpoint policyruntime.CompiledStagePlan,
	available map[string]struct{},
	mode string,
) checkpointMeaning {
	t.Helper()

	meaning := checkpointMeaning{
		Name:           string(checkpoint.Stage),
		ProviderLevels: legacyProviderLevels(checkpoint.Checks),
	}
	providerUses := make(map[string]string, len(checkpoint.Checks))

	for _, check := range checkpoint.Checks {
		use, err := resolveLegacyProviderUse(check.Type, check.Name, check.ConfigRef, available)
		if err != nil {
			t.Fatalf("resolve check %s: %v", check.Name, err)
		}

		providerUses[check.Name] = use
		meaning.Providers = append(meaning.Providers, legacyProviderMeaning(check, use))
	}

	for _, rule := range checkpoint.Policies {
		meaning.Rules = append(meaning.Rules, legacyRuleMeaning(rule, providerUses))
	}

	meaning.ProductionPolicySet, meaning.ComparisonPolicySet = legacyPolicySetAuthority(mode, len(checkpoint.Policies) > 0)

	return meaning
}

// unifiedCheckpointMeaning projects provider, rule, and authority metadata from one compiled checkpoint.
func unifiedCheckpointMeaning(
	t *testing.T,
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
) checkpointMeaning {
	t.Helper()

	meaning := checkpointMeaning{
		Name:                checkpoint.Name(),
		ProviderLevels:      checkpoint.ProviderLevels(),
		ProductionPolicySet: checkpoint.ProductionPolicySetIDs(),
		ComparisonPolicySet: checkpoint.ComparisonPolicySetIDs(),
	}

	for _, instance := range checkpoint.ProviderInstances() {
		meaning.Providers = append(meaning.Providers, unifiedProviderMeaning(instance))
	}

	for _, policySetID := range checkpoint.PolicySetIDs() {
		set, exists := lookupCompiledPolicySet(target, policySetID)
		if !exists || set.ID().String() != "authn/configured" {
			continue
		}

		for _, rule := range set.Rules() {
			if rule.Checkpoint() == checkpoint.Name() {
				meaning.Rules = append(meaning.Rules, unifiedRuleMeaning(t, rule, target.Target().Action(), checkpoint))
			}
		}
	}

	return meaning
}

// legacyPolicySetAuthority projects the old global mode into the unified checkpoint authority split.
func legacyPolicySetAuthority(mode string, configured bool) ([]string, []string) {
	if mode == string(registry.AuthorityModeObserve) {
		var comparison []string
		if configured {
			comparison = []string{"authn/configured"}
		}

		return []string{registry.BuiltinStandardAuthPolicySet}, comparison
	}

	if configured {
		return []string{"authn/configured"}, nil
	}

	return []string{registry.BuiltinStandardAuthPolicySet}, nil
}

// lookupCompiledPolicySet parses one catalog-returned exact identity through the public constructor.
func lookupCompiledPolicySet(target policyruntime.CompiledTarget, identity string) (policyruntime.CompiledPolicySet, bool) {
	namespace, name, ok := strings.Cut(identity, "/")
	if !ok {
		return policyruntime.CompiledPolicySet{}, false
	}

	policySetID, err := registry.NewPolicySetID(namespace, name)
	if err != nil {
		return policyruntime.CompiledPolicySet{}, false
	}

	return target.LookupPolicySet(policySetID)
}

// legacyProviderMeaning retains every executable old check field after identity migration.
func legacyProviderMeaning(check policyruntime.CompiledCheck, use string) providerMeaning {
	return providerMeaning{
		Name: check.Name, Use: use, RunIf: normalizedRunIf(check.RunIf.AuthState), Output: check.Output,
		Actions: policyOperationsMeaning(check.Operations), After: append([]string(nil), check.After...),
		Dependencies: append([]string(nil), check.After...), SkipIf: append([]string(nil), check.SkipIf...),
		ObserveSafe: check.ObserveSafe,
	}
}

// policyOperationsMeaning detaches old compiled operations into target-action spellings.
func policyOperationsMeaning(operations []policy.Operation) []string {
	result := make([]string, 0, len(operations))
	for _, operation := range operations {
		result = append(result, string(operation))
	}

	return result
}

// unifiedProviderMeaning detaches one actual compiled checkpoint-local provider instance.
func unifiedProviderMeaning(provider policyruntime.CompiledProviderInstance) providerMeaning {
	return providerMeaning{
		Name: provider.Name(), Use: provider.Use(), RunIf: normalizedRunIf(provider.RunIfAuthState()), Output: provider.Output(),
		Actions: provider.Actions(), After: provider.After(), Dependencies: provider.Dependencies(),
		SkipIf: provider.SkipIf(), ObserveSafe: provider.ObserveSafe(),
	}
}

// legacyRuleMeaning maps one old compiled rule into exact target-specific semantics.
func legacyRuleMeaning(rule policyruntime.CompiledPolicy, providerUses map[string]string) ruleMeaning {
	var required []string
	for _, name := range rule.RequireChecks {
		required = append(required, providerUses[name])
	}

	return ruleMeaning{
		Name: rule.Name, Action: string(policy.OperationAuthenticate), Expression: legacyExpressionMeaning(rule.Root),
		Decision: string(rule.Then.Decision), Reason: rule.Then.Reason, OutcomeMarker: rule.Then.OutcomeMarker,
		FSMEventMarker: rule.Then.FSMEventMarker, ResponseMarker: rule.Then.ResponseMarker,
		ResponseMessage:   legacyResponseMessageMeaning(rule.Then.ResponseMessage),
		ResponseLanguage:  legacyResponseLanguageMeaning(rule.Then.ResponseLanguage),
		RequiredInstances: append([]string(nil), rule.RequireChecks...),
		RequiredProviders: required, Effects: legacyEffectUses(rule.Then.Obligations), Advice: legacyEffectUses(rule.Then.Advice),
		SkipRemaining: rule.Then.Control.SkipRemainingStageChecks,
	}
}

// unifiedRuleMeaning projects one actual catalog rule into the same target-specific DTO.
func unifiedRuleMeaning(
	t *testing.T,
	rule policyruntime.CompiledRule,
	action string,
	checkpoint policyruntime.CompiledCheckpoint,
) ruleMeaning {
	t.Helper()

	requiredInstances := rule.RequiredProviders()
	requiredProviders := compiledRequiredProviderUses(t, checkpoint, requiredInstances)

	return ruleMeaning{
		Name: rule.Name(), Action: action, Expression: unifiedExpressionMeaning(rule.Expression()),
		Decision: string(rule.Decision()), Reason: rule.Reason(), OutcomeMarker: rule.OutcomeMarker(),
		FSMEventMarker: rule.FSMEventMarker(), ResponseMarker: rule.ResponseMarker(),
		ResponseMessage:   unifiedResponseMessageMeaning(rule.ResponseMessage()),
		ResponseLanguage:  unifiedResponseLanguageMeaning(rule.ResponseLanguage()),
		RequiredInstances: requiredInstances, RequiredProviders: requiredProviders,
		Effects: unifiedEffectUses(rule.Effects()), Advice: unifiedEffectUses(rule.Advice()),
		SkipRemaining: rule.SkipRemainingCheckpointProviders(),
	}
}

// legacyExpressionMeaning canonicalizes established auth facts and old typed values.
func legacyExpressionMeaning(expression policyruntime.CompiledExpr) expressionMeaning {
	meaning := expressionMeaning{
		Kind: string(expression.Kind), Fact: canonicalLegacyFact(expression.AttributeID),
		FactKind: canonicalLegacyFactKind(expression.ValueType), Operator: string(expression.Operator),
	}

	if expression.Kind == policyruntime.ExprKindAlways {
		meaning.Operator = "always"
	}

	if expression.Expected.Value != nil {
		meaning.Values = []string{semanticValue(expression.Expected.Value)}
	}

	for _, child := range expression.Children {
		meaning.Children = append(meaning.Children, legacyExpressionMeaning(child))
	}

	return meaning
}

// unifiedExpressionMeaning projects one strict catalog expression without textual YAML comparison.
func unifiedExpressionMeaning(expression registry.PolicyExpression) expressionMeaning {
	meaning := expressionMeaning{
		Kind: string(expression.Kind()), Fact: expression.FactID(), FactKind: string(expression.FactKind()),
		Operator: string(expression.Operator()), Reference: expression.Reference(),
	}

	for _, value := range expression.Values() {
		meaning.Values = append(meaning.Values, decisionValueMeaning(value))
	}

	for _, child := range expression.Children() {
		meaning.Children = append(meaning.Children, unifiedExpressionMeaning(child))
	}

	return meaning
}

// canonicalLegacyFact applies the existing old-attribute to unified-fact authority mapping.
func canonicalLegacyFact(attribute string) string {
	if attribute == "" {
		return ""
	}

	if fact, _, ok := policy.AuthnCanonicalFactIdentity(attribute, "builtin"); ok {
		return fact
	}

	return attribute
}

// canonicalLegacyFactKind aligns the old attribute vocabulary with strict decision kinds.
func canonicalLegacyFactKind(value registry.AttributeType) string {
	switch value {
	case registry.AttributeTypeBool:
		return string(decision.ValueKindBoolean)
	case registry.AttributeTypeString:
		return string(decision.ValueKindString)
	case registry.AttributeTypeStringList:
		return string(decision.ValueKindStrings)
	case registry.AttributeTypeNumber:
		return string(decision.ValueKindDouble)
	default:
		return string(value)
	}
}

// legacyEffectUses qualifies builtin old selections and preserves typed argument meaning.
func legacyEffectUses(requests []policyruntime.EffectRequest) []effectUseMeaning {
	result := make([]effectUseMeaning, 0, len(requests))
	for _, request := range requests {
		identity := request.ID
		switch request.ID {
		case policy.ObligationBruteForceUpdate:
			identity = "authn/brute_force_update"
		case "auth.advice.audit_reason":
			identity = "authn/audit_reason"
		}

		result = append(result, effectUseMeaning{ID: identity, Parameters: anyMapMeaning(request.Args)})
	}

	return result
}

// unifiedEffectUses preserves strict parameter kinds and values in deterministic key order.
func unifiedEffectUses(uses []registry.EffectUse) []effectUseMeaning {
	result := make([]effectUseMeaning, 0, len(uses))
	for _, use := range uses {
		values := use.Parameters().Values()
		keys := sortedKeys(values)

		parameters := make([]string, 0, len(keys))
		for _, key := range keys {
			parameters = append(parameters, key+"="+decisionValueMeaning(values[key]))
		}

		result = append(result, effectUseMeaning{ID: use.ID(), Parameters: parameters})
	}

	return result
}

// anyMapMeaning renders old effect arguments with the same strict scalar kind names.
func anyMapMeaning(values map[string]any) []string {
	keys := sortedKeys(values)

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+semanticValue(values[key]))
	}

	return result
}

// semanticValue returns a stable strict-kind representation for test-only comparison.
func semanticValue(value any) string {
	switch typed := value.(type) {
	case string:
		return "string:" + typed
	case bool:
		return fmt.Sprintf("boolean:%t", typed)
	case int:
		return fmt.Sprintf("integer:%d", typed)
	case int64:
		return fmt.Sprintf("integer:%d", typed)
	case float64:
		return fmt.Sprintf("double:%g", typed)
	default:
		return fmt.Sprintf("%T:%v", value, value)
	}
}

// decisionValueMeaning returns one detached strict decision value representation.
func decisionValueMeaning(value decision.Value) string {
	member, ok := value.Any()
	if !ok {
		return "invalid"
	}

	return string(value.Kind()) + ":" + fmt.Sprint(member)
}

// legacyResponseMessageMeaning maps the old compiled response source fields.
func legacyResponseMessageMeaning(message policyruntime.ResponseMessagePlan) responseMessageMeaning {
	return responseMessageMeaning{
		From: message.Source, Text: message.Literal, I18NKey: message.I18NKey, Fact: canonicalLegacyFact(message.AttributeID),
		Detail: message.Detail, Fallback: message.Fallback, MaxLength: message.MaxLength,
	}
}

// unifiedResponseMessageMeaning maps the strict immutable response source fields.
func unifiedResponseMessageMeaning(message registry.PolicyResponseMessage) responseMessageMeaning {
	from := message.From()
	if from == "" {
		from = policy.ResponseSourceDefault
	}

	return responseMessageMeaning{
		From: from, Text: message.Text(), I18NKey: message.I18NKey(), Fact: message.FactID(),
		Detail: message.Detail(), Fallback: message.Fallback(), MaxLength: message.MaxLength(),
	}
}

// legacyResponseLanguageMeaning maps the old compiled response-language fields.
func legacyResponseLanguageMeaning(language policyruntime.ResponseLanguagePlan) responseLanguageMeaning {
	return responseLanguageMeaning{
		From: language.Source, Language: language.Language, Fact: canonicalLegacyFact(language.AttributeID), Fallback: language.Fallback,
	}
}

// unifiedResponseLanguageMeaning maps strict immutable response-language fields.
func unifiedResponseLanguageMeaning(language registry.PolicyResponseLanguage) responseLanguageMeaning {
	return responseLanguageMeaning{
		From: language.From(), Language: language.Language(), Fact: language.FactID(), Fallback: language.Fallback(),
	}
}

// authnCheckpointOrder freezes the established semantic stage order for snapshot projection.
func authnCheckpointOrder() []policy.Stage {
	return []policy.Stage{
		policy.StagePreAuth,
		policy.StageAuthBackend,
		policy.StageSubjectAnalysis,
		policy.StageAccountProvider,
		policy.StageAuthDecision,
	}
}

// normalizedRunIf aligns the old compiler default with the omitted standalone spelling.
func normalizedRunIf(value string) string {
	if value == "" {
		return policy.RunIfAny
	}

	return value
}

// availableLegacyLuaSources builds exact qualified source existence evidence.
func availableLegacyLuaSources(configured config.PolicyLuaAttributeSourcesConfig) map[string]struct{} {
	result := make(map[string]struct{}, len(configured.Environment)+len(configured.Subject))
	for _, source := range configured.Environment {
		result["authn/lua_environment_"+source.Name] = struct{}{}
	}

	for _, source := range configured.Subject {
		result["authn/lua_subject_"+source.Name] = struct{}{}
	}

	return result
}

// qualifyStandardAuth is the only default-policy identity change in this test oracle.
func qualifyStandardAuth(value string) string {
	if value == policy.BuiltinDefaultSet {
		return registry.BuiltinStandardAuthPolicySet
	}

	return value
}

// mustConfiguredTarget resolves one normalized target without relying on fixture order.
func mustConfiguredTarget(t *testing.T, configured policyconfig.PolicyConfig, identity string) policyconfig.TargetConfig {
	t.Helper()

	for _, target := range configured.Targets {
		if target.Namespace+"/"+target.Action == identity {
			return target
		}
	}

	t.Fatalf("configured target %s not found", identity)

	return policyconfig.TargetConfig{}
}

// mustCatalogTarget resolves one compiled target without weakening exact identity checks.
func mustCatalogTarget(t *testing.T, catalog *policyruntime.TargetCatalog, identity string) policyruntime.CompiledTarget {
	t.Helper()

	for _, target := range catalog.Targets() {
		if target.Target().String() == identity {
			return target
		}
	}

	t.Fatalf("compiled target %s not found", identity)

	return policyruntime.CompiledTarget{}
}

// assertMigrationMeaningEqual provides readable semantic DTO diagnostics.
func assertMigrationMeaningEqual(t *testing.T, got any, want any) {
	t.Helper()

	if reflect.DeepEqual(got, want) {
		return
	}

	gotJSON, _ := json.MarshalIndent(got, "", "  ")
	wantJSON, _ := json.MarshalIndent(want, "", "  ")
	t.Fatalf("migration meaning differs\ngot:\n%s\nwant:\n%s", gotJSON, wantJSON)
}

// sortedKeys returns deterministic keys for test-only semantic projections.
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// networkSetMeaning flattens named ordered network members.
func networkSetMeaning(values map[string][]string) []string {
	return namedSliceMeaning(values)
}

// stringSetMeaning flattens named ordered string members.
func stringSetMeaning(values map[string][]string) []string {
	return namedSliceMeaning(values)
}

// namedSliceMeaning renders deterministic names while preserving member order.
func namedSliceMeaning(values map[string][]string) []string {
	result := make([]string, 0, len(values))
	for _, name := range sortedKeys(values) {
		result = append(result, name+"="+strings.Join(values[name], ","))
	}

	return result
}

// legacyLocalizationMeaning flattens old catalog entries without map-order dependence.
func legacyLocalizationMeaning(configured config.PolicyLocalizationConfig) []string {
	result := make([]string, 0)

	for _, catalog := range configured.Catalogs {
		for _, key := range sortedKeys(catalog.Entries) {
			result = append(result, catalog.Namespace+"|"+catalog.Language+"|"+key+"="+catalog.Entries[key])
		}
	}

	return result
}

// unifiedLocalizationMeaning flattens standalone catalog entries identically.
func unifiedLocalizationMeaning(configured policyconfig.LocalizationConfig) []string {
	result := make([]string, 0)

	for _, catalog := range configured.Catalogs {
		for _, key := range sortedKeys(catalog.Entries) {
			result = append(result, catalog.Namespace+"|"+catalog.Language+"|"+key+"="+catalog.Entries[key])
		}
	}

	return result
}

// timeWindowMeaningSource is the closed pair of old and standalone window inputs.
type timeWindowMeaningSource interface {
	config.PolicyTimeWindowConfig | policyconfig.TimeWindowConfig
}

// timeIntervalMeaningSource is the closed pair of old and standalone interval inputs.
type timeIntervalMeaningSource interface {
	config.PolicyTimeIntervalConfig | policyconfig.TimeIntervalConfig
}

// normalizedTimeWindowMeaning is the decoder-neutral time-window comparison value.
type normalizedTimeWindowMeaning struct {
	days      []string
	intervals []string
	timezone  string
}

// legacyTimeWindowMeaning renders typed old windows through the shared semantic adapter.
func legacyTimeWindowMeaning(values map[string]config.PolicyTimeWindowConfig) []string {
	return timeWindowMeaning(values)
}

// unifiedTimeWindowMeaning renders standalone windows through the shared semantic adapter.
func unifiedTimeWindowMeaning(values map[string]policyconfig.TimeWindowConfig) []string {
	return timeWindowMeaning(values)
}

// timeWindowMeaning renders one normalized comparison form independently from concrete decoder types.
func timeWindowMeaning[W timeWindowMeaningSource](values map[string]W) []string {
	result := make([]string, 0, len(values))

	for _, name := range sortedKeys(values) {
		window := normalizeTimeWindowMeaning(values[name])

		result = append(
			result,
			name+"|"+window.timezone+"|"+strings.Join(window.days, ",")+"|"+strings.Join(window.intervals, ","),
		)
	}

	return result
}

// normalizeTimeWindowMeaning adapts either decoder type to one shared projection value.
func normalizeTimeWindowMeaning[W timeWindowMeaningSource](window W) normalizedTimeWindowMeaning {
	switch typed := any(window).(type) {
	case config.PolicyTimeWindowConfig:
		return normalizedTimeWindowMeaning{
			days: typed.Days, intervals: timeIntervalMeaning(typed.Intervals), timezone: typed.Timezone,
		}
	case policyconfig.TimeWindowConfig:
		return normalizedTimeWindowMeaning{
			days: typed.Days, intervals: timeIntervalMeaning(typed.Intervals), timezone: typed.Timezone,
		}
	default:
		return normalizedTimeWindowMeaning{}
	}
}

// timeIntervalMeaning renders old and standalone interval values identically.
func timeIntervalMeaning[I timeIntervalMeaningSource](values []I) []string {
	result := make([]string, 0, len(values))

	for _, interval := range values {
		start, end := timeIntervalBounds(interval)

		result = append(result, start+"-"+end)
	}

	return result
}

// timeIntervalBounds adapts the closed interval input pair without duplicating rendering logic.
func timeIntervalBounds[I timeIntervalMeaningSource](interval I) (string, string) {
	switch typed := any(interval).(type) {
	case config.PolicyTimeIntervalConfig:
		return typed.Start, typed.End
	case policyconfig.TimeIntervalConfig:
		return typed.Start, typed.End
	default:
		return "", ""
	}
}

// legacySchedulerGuardMeaning renders the focused typed guard fixture.
func legacySchedulerGuardMeaning(values map[string]config.PolicySchedulerGuardConfig) []string {
	result := make([]string, 0, len(values))
	for _, name := range sortedKeys(values) {
		guard := values[name]
		result = append(result, name+"|"+guard.If.Attribute+"|in="+fmt.Sprint(guard.If.In)+"|"+guard.OnMissingAttribute)
	}

	return result
}

// unifiedSchedulerGuardMeaning renders the same focused standalone guard fixture.
func unifiedSchedulerGuardMeaning(values map[string]policyconfig.SchedulerGuardConfig) []string {
	result := make([]string, 0, len(values))
	for _, name := range sortedKeys(values) {
		guard := values[name]
		result = append(result, name+"|"+guard.If.Attribute+"|in="+fmt.Sprint(guard.If.In)+"|"+guard.OnMissingAttribute)
	}

	return result
}

// legacyLuaProviderMeaning maps equal old names into distinct category-qualified identities.
func legacyLuaProviderMeaning(configured config.PolicyLuaAttributeSourcesConfig) []string {
	result := make([]string, 0, len(configured.Environment)+len(configured.Subject))
	for _, source := range configured.Environment {
		result = append(result, "authn/lua_environment_"+source.Name+"|lua_environment|"+source.ScriptPath)
	}

	for _, source := range configured.Subject {
		result = append(result, "authn/lua_subject_"+source.Name+"|lua_subject|"+source.ScriptPath)
	}

	sort.Strings(result)

	return result
}

// unifiedLuaProviderMeaning retains only providers mapped from old Lua source concepts.
func unifiedLuaProviderMeaning(configured map[string]policyconfig.ProviderConfig) []string {
	result := make([]string, 0)

	for _, name := range sortedKeys(configured) {
		provider := configured[name]
		if provider.Kind != "lua_environment" && provider.Kind != "lua_subject" {
			continue
		}

		result = append(result, "authn/"+name+"|"+provider.Kind+"|"+provider.ScriptPath)
	}

	return result
}

// legacyLuaEffectMeaning maps old action type and host ownership into one qualified effect.
func legacyLuaEffectMeaning(configured config.PolicyLuaObligationTargetsConfig) []string {
	result := make([]string, 0, len(configured.Actions))
	for _, action := range configured.Actions {
		result = append(result, "authn/lua_action_"+action.ScriptName+"|lua_action|"+action.ActionType+"|"+action.ScriptPath+"|"+luaActionExecution(action.ActionType))
	}

	return result
}

// unifiedLuaEffectMeaning retains only effects mapped from old Lua action concepts.
func unifiedLuaEffectMeaning(configured map[string]policyconfig.EffectConfig) []string {
	result := make([]string, 0)

	for _, name := range sortedKeys(configured) {
		effect := configured[name]
		if effect.Kind != "lua_action" {
			continue
		}

		result = append(result, "authn/"+name+"|"+effect.Kind+"|"+effect.ActionType+"|"+effect.ScriptPath+"|"+effect.Execution)
	}

	return result
}

// luaActionExecution returns the mandatory owner class for one old action type.
func luaActionExecution(actionType string) string {
	if actionType == "post" {
		return string(registry.ExecutionHostPostAction)
	}

	return string(registry.ExecutionHostSync)
}

// legacyHeaderMeaning renders old HTTP header sources.
func legacyHeaderMeaning(values []config.PolicyRequestHeaderAttributeConfig) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, requestSourceMeaning(value.Header, value.Attribute, value.Visibility, value.Normalize.Trim, value.Normalize.Case, value.Normalize.MaxLength))
	}

	return result
}

// unifiedHeaderMeaning renders standalone HTTP header sources.
func unifiedHeaderMeaning(values []policyconfig.HTTPHeaderFactSourceConfig) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, requestSourceMeaning(value.Header, value.Attribute, value.Visibility, value.Normalize.Trim, value.Normalize.Case, value.Normalize.MaxLength))
	}

	return result
}

// legacyMetadataMeaning renders old gRPC metadata sources.
func legacyMetadataMeaning(values []config.PolicyRequestMetadataAttributeConfig) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, requestSourceMeaning(value.Key, value.Attribute, value.Visibility, value.Normalize.Trim, value.Normalize.Case, value.Normalize.MaxLength))
	}

	return result
}

// unifiedMetadataMeaning renders standalone gRPC metadata sources.
func unifiedMetadataMeaning(values []policyconfig.GRPCMetadataFactSourceConfig) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, requestSourceMeaning(value.Key, value.Attribute, value.Visibility, value.Normalize.Trim, value.Normalize.Case, value.Normalize.MaxLength))
	}

	return result
}

// requestSourceMeaning retains source, destination, visibility, and normalization.
func requestSourceMeaning(source string, attribute string, visibility string, trim bool, valueCase string, maximum int) string {
	return fmt.Sprintf("%s|%s|%s|trim=%t|case=%s|max=%d", source, attribute, visibility, trim, valueCase, maximum)
}

// legacyBackendExportMeaning renders old backend attribute exports.
func legacyBackendExportMeaning(values []config.PolicyAttributeExportConfig) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Name+"|"+value.Attribute+"|"+value.Type+"|"+value.Sensitivity)
	}

	return result
}

// unifiedBackendExportMeaning renders standalone backend attribute sources.
func unifiedBackendExportMeaning(values []policyconfig.BackendAttributeFactSourceConfig) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Name+"|"+value.Attribute+"|"+value.Type+"|"+value.Sensitivity)
	}

	return result
}

// legacyReportMeaning maps decoded old report fields.
func legacyReportMeaning(report config.PolicyReportConfig) reportMeaning {
	return reportMeaning{report.Enabled, report.IncludeFSM, report.IncludeChecks, report.IncludeAttributes}
}

// snapshotReportMeaning maps actual old compiled report defaults.
func snapshotReportMeaning(report policyruntime.ReportSettings) reportMeaning {
	return reportMeaning{report.Enabled, report.IncludeFSM, report.IncludeChecks, report.IncludeAttributes}
}

// compiledTargetReportMeaning maps the immutable unified target report carrier.
func compiledTargetReportMeaning(report registry.TargetReportSettings) reportMeaning {
	return reportMeaning{report.Enabled(), report.IncludeFSM(), report.IncludeChecks(), report.IncludeAttributes()}
}

// unifiedReportMeaning maps normalized standalone target report fields.
func unifiedReportMeaning(report policyconfig.ReportConfig) reportMeaning {
	return reportMeaning{report.Enabled, report.IncludeFSM, report.IncludeChecks, report.IncludeAttributes}
}

func TestPolicyMigrationMappingTableIsFieldComplete(t *testing.T) {
	if len(legacyCheckMappings) != 12 {
		t.Fatalf("check identity rows = %d, want 12", len(legacyCheckMappings))
	}

	types := make([]string, 0, len(legacyCheckMappings))
	for _, mapping := range legacyCheckMappings {
		if !completeLegacyCheckMapping(mapping) {
			t.Fatalf("mapping row %q is incomplete: %#v", mapping.checkType, mapping)
		}

		types = append(types, mapping.checkType)
	}

	if slices.Contains(types, "") {
		t.Fatal("mapping table contains an empty check type")
	}

	sorted := append([]string(nil), types...)
	sort.Strings(sorted)

	for index := 1; index < len(sorted); index++ {
		if sorted[index] == sorted[index-1] {
			t.Fatalf("mapping table repeats check type %q", sorted[index])
		}
	}
}

// completeLegacyCheckMapping reports whether one identity row carries every shared authority field.
func completeLegacyCheckMapping(mapping legacyCheckMapping) bool {
	values := []string{
		mapping.checkType,
		mapping.checkName,
		mapping.canonicalRef,
		mapping.canonicalUse,
		mapping.invalidRef,
		mapping.acceptedOldForm,
		mapping.migrationRule,
		string(mapping.checkpoint),
		string(mapping.action),
	}

	return !slices.Contains(values, "")
}

func TestPolicyMigrationSharedAuthorityMutationIsRejected(t *testing.T) {
	mutatedEvidence := policyMigrationContractCases[0]
	mutatedEvidence.evidenceClass = migrationEvidenceNormalizedSource

	if err := validatePolicyMigrationEvidenceDescriptor(mutatedEvidence); err == nil {
		t.Fatal("mutated evidence class escaped the shared row descriptor")
	}

	mutatedIdentity := legacyCheckMappings[0]
	mutatedIdentity.canonicalUse = "authn/builtin/mutated"

	if missing := missingConfigRefDocumentationEvidence(readPolicyMigrationGuide(t), mutatedIdentity); missing == "" {
		t.Fatal("mutated identity escaped the manual-authority assertion")
	}

	_, err := configinput.Normalize(context.Background(), unifiedCheckIdentityDocument(mutatedIdentity))
	if err == nil || !strings.Contains(err.Error(), ".providers[0].use") {
		t.Fatalf("mutated identity normalization = %v, want provider-use rejection", err)
	}
}
