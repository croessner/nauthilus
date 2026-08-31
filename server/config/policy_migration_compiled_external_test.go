// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
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

// cutoverCheckMapping freezes one manual old-reference to production-use mapping.
type cutoverCheckMapping struct {
	checkType       string
	usePrefix       string
	instanceName    string
	canonicalUse    string
	acceptedOldForm string
	migrationRule   string
	kind            migrationReferenceKind
	checkpoint      policy.Stage
	action          policy.Operation
	observeSafe     bool
}

var cutoverCheckMappings = []cutoverCheckMapping{
	{
		checkType: policy.CheckTypeBruteForce, instanceName: "brute_force",
		canonicalUse: policy.AuthnProviderBruteForce, kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.controls.brute_force...`",
		migrationRule:   "Discard any suffix; the builtin binding owns typed brute-force configuration.",
	},
	{
		checkType: policy.CheckTypeTLSEncryption, instanceName: "tls_encryption",
		canonicalUse: policy.AuthnProviderTLSEncryption, kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate, observeSafe: true,
		acceptedOldForm: "empty or `auth.controls.tls_encryption...`", migrationRule: "Discard any suffix.",
	},
	{
		checkType: policy.CheckTypeRelayDomains, instanceName: "relay_domains",
		canonicalUse: policy.AuthnProviderRelayDomains, kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate, observeSafe: true,
		acceptedOldForm: "empty or `auth.controls.relay_domains...`", migrationRule: "Discard any suffix.",
	},
	{
		checkType: policy.CheckTypeRBL, instanceName: "rbl",
		canonicalUse: policy.AuthnProviderRBL, kind: migrationReferenceFixed,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.controls.rbl...`", migrationRule: "Discard any suffix.",
	},
	{
		checkType: policy.CheckTypeLuaEnvironment, usePrefix: "authn/lua_environment_", instanceName: "shared",
		canonicalUse: "authn/lua_environment_shared", kind: migrationReferenceLua,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.policy.attribute_sources.lua.environment.<source>`",
		migrationRule:   "An empty reference uses the old check name; the migrated provider must exist.",
	},
	{
		checkType: policy.CheckTypePluginEnvironment, usePrefix: "authn/plugin.", instanceName: "plugin_environment_acme",
		canonicalUse: "authn/plugin.acme.environment", kind: migrationReferencePluginEnvironment,
		checkpoint: policy.StagePreAuth, action: policy.OperationAuthenticate,
		acceptedOldForm: "exactly `plugins.modules.<module>.environment`",
		migrationRule:   "Empty, non-canonical, or unresolvable references are rejected.",
	},
	{
		checkType: policy.CheckTypeLDAPBackend, instanceName: "ldap_backend",
		canonicalUse: policy.AuthnProviderLDAPBackend, kind: migrationReferenceFixed,
		checkpoint: policy.StageAuthBackend, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.backends.ldap...`",
		migrationRule:   "Discard any suffix; the builtin binding owns typed LDAP configuration.",
	},
	{
		checkType: policy.CheckTypeLuaBackend, instanceName: "lua_backend",
		canonicalUse: policy.AuthnProviderLuaBackend, kind: migrationReferenceFixed,
		checkpoint: policy.StageAuthBackend, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.backends.lua.backend...`",
		migrationRule:   "Discard any suffix; the builtin binding owns the configured Lua backend.",
	},
	{
		checkType: policy.CheckTypePluginBackend, instanceName: "plugin_backend",
		canonicalUse: policy.AuthnProviderPluginBackendOrder, kind: migrationReferenceFixed,
		checkpoint: policy.StageAuthBackend, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.backends.order...`",
		migrationRule:   "Discard any suffix; the builtin binding owns backend order and plugin capabilities.",
	},
	{
		checkType: policy.CheckTypeLuaSubjectSource, usePrefix: "authn/lua_subject_", instanceName: "shared",
		canonicalUse: "authn/lua_subject_shared", kind: migrationReferenceLua,
		checkpoint: policy.StageSubjectAnalysis, action: policy.OperationAuthenticate,
		acceptedOldForm: "empty or `auth.policy.attribute_sources.lua.subject.<source>`",
		migrationRule:   "An empty reference uses the old check name; the migrated provider must exist.",
	},
	{
		checkType: policy.CheckTypePluginSubjectSource, usePrefix: "authn/plugin.", instanceName: "plugin_subject_acme_risk",
		canonicalUse: "authn/plugin.acme.subject.risk", kind: migrationReferencePluginSubject,
		checkpoint: policy.StageSubjectAnalysis, action: policy.OperationAuthenticate,
		acceptedOldForm: "`plugins.modules.<module>.subject` plus a derivable check-local suffix",
		migrationRule:   "Empty, non-canonical, non-derivable, or unresolvable references are rejected.",
	},
	{
		checkType: policy.CheckTypeAccountProvider, instanceName: "account_provider",
		canonicalUse: policy.AuthnProviderAccount, kind: migrationReferenceFixed,
		checkpoint: policy.StageAccountProvider, action: policy.OperationListAccounts,
		acceptedOldForm: "empty or `auth.backends...`",
		migrationRule:   "Discard any suffix; the builtin binding owns typed backend selection.",
	},
}

type reportMeaning struct {
	Enabled           bool
	IncludeFSM        bool
	IncludeChecks     bool
	IncludeAttributes bool
}

// migrationCatalogGolden is the frozen production meaning of the complete B001-C2 fixture.
type migrationCatalogGolden struct {
	Target            string
	Schema            string
	Mode              string
	DefaultPolicy     string
	Checkpoints       []migrationCheckpointGolden
	SchedulerGuards   []string
	ConfiguredRules   []string
	ConfiguredEffects []string
	Report            reportMeaning
}

// migrationCheckpointGolden freezes one compiled checkpoint and its provider topology.
type migrationCheckpointGolden struct {
	Name              string
	ProviderInstances []string
	ProviderUses      []string
	ProviderLevels    [][]string
}

func TestProductionPolicyMigrationFixtureMatchesFrozenSourceGolden(t *testing.T) {
	candidate := prepareResolvedProductionMigrationFixture(t)
	configured := candidate.GetPolicy()

	authn, exists := configured.Namespaces[policy.AuthnNamespace]
	if !exists {
		t.Fatal("production-loaded migration fixture has no authn namespace")
	}

	assertProductionMigrationNamespaceShape(t, authn)
	assertProductionMigrationScripts(t, authn)
	assertProductionMigrationFactSources(t, authn)

	if len(configured.Targets) != 1 || configured.Targets[0].DefaultPolicy != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("production target/default = %#v", configured.Targets)
	}

	delete(configured.Namespaces, policy.AuthnNamespace)

	if _, exists = candidate.GetPolicy().Namespaces[policy.AuthnNamespace]; !exists {
		t.Fatal("GetPolicy returned production-owned mutable namespace state")
	}
}

// assertProductionMigrationNamespaceShape verifies the frozen namespace owners and names.
func assertProductionMigrationNamespaceShape(t *testing.T, authn policyconfig.NamespaceConfig) {
	t.Helper()

	if got := sortedKeys(authn.Providers); !slices.Equal(got, []string{"lua_environment_shared", "lua_subject_shared"}) {
		t.Fatalf("production provider definitions = %v", got)
	}

	if got := sortedKeys(authn.Effects); !slices.Equal(got, []string{"audit_reason", "lua_action_notify"}) {
		t.Fatalf("production effect definitions = %v", got)
	}

	if got := sortedKeys(authn.DomainPlans); !slices.Equal(got, []string{"migrated_authenticate"}) {
		t.Fatalf("production domain plans = %v", got)
	}

	if got := sortedKeys(authn.PolicySets); !slices.Equal(got, []string{"configured"}) {
		t.Fatalf("production policy sets = %v", got)
	}
}

// assertProductionMigrationScripts verifies every migration script is an absolute production artifact.
func assertProductionMigrationScripts(t *testing.T, authn policyconfig.NamespaceConfig) {
	t.Helper()

	if got := authn.SchemaContributions.Lua.RegistryScripts; len(got) != 1 || !filepath.IsAbs(got[0]) || filepath.Base(got[0]) != "registry.lua" {
		t.Fatalf("production registry scripts = %v", got)
	}

	for name, expected := range map[string]string{
		"lua_environment_shared": "environment.lua",
		"lua_subject_shared":     "subject.lua",
	} {
		path := authn.Providers[name].ScriptPath
		if !filepath.IsAbs(path) || filepath.Base(path) != expected {
			t.Fatalf("production provider %s script = %q, want absolute %s", name, path, expected)
		}
	}

	actionPath := authn.Effects["lua_action_notify"].ScriptPath
	if !filepath.IsAbs(actionPath) || filepath.Base(actionPath) != "action.lua" {
		t.Fatalf("production action script = %q, want absolute action.lua", actionPath)
	}
}

// assertProductionMigrationFactSources verifies the frozen transport and backend fact mappings.
func assertProductionMigrationFactSources(t *testing.T, authn policyconfig.NamespaceConfig) {
	t.Helper()

	if len(authn.FactSources.HTTPHeaders) != 1 || authn.FactSources.HTTPHeaders[0].Attribute != "request.header.tenant" {
		t.Fatalf("production HTTP fact sources = %#v", authn.FactSources.HTTPHeaders)
	}

	if len(authn.FactSources.GRPCMetadata) != 1 || authn.FactSources.GRPCMetadata[0].Attribute != "request.metadata.tenant" {
		t.Fatalf("production gRPC fact sources = %#v", authn.FactSources.GRPCMetadata)
	}

	if len(authn.FactSources.BackendAttributes) != 1 || authn.FactSources.BackendAttributes[0].Name != "account_tier" {
		t.Fatalf("production backend fact sources = %#v", authn.FactSources.BackendAttributes)
	}
}

func TestProductionPolicyMigrationFixtureMatchesFrozenCatalogGolden(t *testing.T) {
	input := loadUnifiedMigrationInput(t)
	catalog := compileUnifiedMigrationFixture(t, input)
	got := compiledMigrationGolden(t, catalog)
	want := migrationCatalogGolden{
		Target:        "authn/authenticate",
		Schema:        "authn/authenticate/v1",
		Mode:          "observe",
		DefaultPolicy: registry.BuiltinStandardAuthPolicySet,
		Checkpoints: []migrationCheckpointGolden{
			{
				Name:              "pre_auth",
				ProviderInstances: []string{"brute_force", "environment_shared"},
				ProviderUses:      []string{policy.AuthnProviderBruteForce, "authn/lua_environment_shared"},
				ProviderLevels:    [][]string{{"brute_force"}, {"environment_shared"}},
			},
			{
				Name:              "auth_backend",
				ProviderInstances: []string{"ldap_backend"},
				ProviderUses:      []string{policy.AuthnProviderLDAPBackend},
				ProviderLevels:    [][]string{{"ldap_backend"}},
			},
			{
				Name:              "subject_analysis",
				ProviderInstances: []string{"subject_shared"},
				ProviderUses:      []string{"authn/lua_subject_shared"},
				ProviderLevels:    [][]string{{"subject_shared"}},
			},
			{Name: "auth_decision", ProviderInstances: []string{}, ProviderLevels: [][]string{}},
		},
		SchedulerGuards: []string{"service_allowed|run|attribute|environment.protocol|in|@string.privileged_services"},
		ConfiguredRules: []string{
			"deny_brute_force|pre_auth|brute_force|deny|migration_contract|authn/brute_force_update|authn/audit_reason",
			"final_contract_deny|auth_decision||deny|final_contract||",
		},
		ConfiguredEffects: []string{"authn/audit_reason", "authn/lua_action_notify"},
		Report:            reportMeaning{Enabled: true, IncludeFSM: true, IncludeChecks: true, IncludeAttributes: true},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled production migration golden:\n got: %#v\nwant: %#v", got, want)
	}
}

// compiledMigrationGolden projects only the frozen operator-authored B001-C2 meaning.
func compiledMigrationGolden(t *testing.T, catalog *policyruntime.TargetCatalog) migrationCatalogGolden {
	t.Helper()

	target := mustCatalogTarget(t, catalog, "authn/authenticate")
	result := migrationCatalogGolden{
		Target:          target.Target().String(),
		Schema:          target.Schema().Identity().String(),
		Mode:            string(target.AuthorityMode()),
		DefaultPolicy:   target.DefaultPolicySet().String(),
		Checkpoints:     compiledMigrationCheckpoints(target),
		SchedulerGuards: compiledMigrationGuards(target),
		ConfiguredRules: compiledMigrationRules(t, target),
		Report:          compiledReportMeaning(target.Report()),
	}

	for _, identity := range []string{"authn/audit_reason", "authn/lua_action_notify"} {
		if _, exists := target.LookupEffect(identity); exists {
			result.ConfiguredEffects = append(result.ConfiguredEffects, identity)
		}
	}

	return result
}

// compiledMigrationCheckpoints freezes target-local provider order and dependency levels.
func compiledMigrationCheckpoints(target policyruntime.CompiledTarget) []migrationCheckpointGolden {
	checkpoints := target.DomainPlan().Checkpoints()

	result := make([]migrationCheckpointGolden, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		instances := checkpoint.ProviderInstances()

		names := make([]string, 0, len(instances))
		for _, instance := range instances {
			names = append(names, instance.Name())
		}

		result = append(result, migrationCheckpointGolden{
			Name:              checkpoint.Name(),
			ProviderInstances: names,
			ProviderUses:      checkpoint.ProviderIDs(),
			ProviderLevels:    checkpoint.ProviderLevels(),
		})
	}

	return result
}

// compiledMigrationGuards renders deterministic scheduler-guard semantics.
func compiledMigrationGuards(target policyruntime.CompiledTarget) []string {
	guards := target.DomainPlan().SchedulerGuards()

	result := make([]string, 0, len(guards))
	for _, guard := range guards {
		expression := guard.Expression()

		result = append(result, strings.Join([]string{
			guard.Name(), guard.OnMissingAttribute(), string(expression.Kind()), expression.FactID(),
			string(expression.Operator()), expression.Reference(),
		}, "|"))
	}

	return result
}

// compiledMigrationRules renders the exact configured rule order and selections.
func compiledMigrationRules(t *testing.T, target policyruntime.CompiledTarget) []string {
	t.Helper()

	identity, err := registry.NewPolicySetID(policy.AuthnNamespace, "configured")
	if err != nil {
		t.Fatalf("construct configured policy set identity: %v", err)
	}

	set, exists := target.LookupPolicySet(identity)
	if !exists {
		t.Fatal("compiled target has no authn/configured set")
	}

	result := make([]string, 0, len(set.Rules()))
	for _, rule := range set.Rules() {
		result = append(result, strings.Join([]string{
			rule.Name(),
			rule.Checkpoint(),
			strings.Join(rule.RequiredProviders(), ","),
			string(rule.Decision()),
			rule.Reason(),
			joinEffectUseIDs(rule.Effects()),
			joinEffectUseIDs(rule.Advice()),
		}, "|"))
	}

	return result
}

// joinEffectUseIDs returns deterministic effect selection identities.
func joinEffectUseIDs(uses []registry.EffectUse) string {
	identities := make([]string, 0, len(uses))
	for _, use := range uses {
		identities = append(identities, use.ID())
	}

	return strings.Join(identities, ",")
}

func TestProductionPolicyCutoverCheckMappingsMatchFrozenCatalogGolden(t *testing.T) {
	if len(cutoverCheckMappings) != 12 {
		t.Fatalf("cutover check mappings = %d, want 12", len(cutoverCheckMappings))
	}

	seenTypes := make(map[string]struct{}, len(cutoverCheckMappings))

	seenUses := make(map[string]struct{}, len(cutoverCheckMappings))
	for _, mapping := range cutoverCheckMappings {
		t.Run(mapping.checkType, func(t *testing.T) {
			if _, exists := seenTypes[mapping.checkType]; exists {
				t.Fatalf("duplicate historical check type %q", mapping.checkType)
			}

			seenTypes[mapping.checkType] = struct{}{}

			if _, exists := seenUses[mapping.canonicalUse]; exists {
				t.Fatalf("duplicate production provider use %q", mapping.canonicalUse)
			}

			seenUses[mapping.canonicalUse] = struct{}{}

			input := normalizeCutoverCheckDocument(t, mapping)
			catalog := compileUnifiedMigrationFixture(t, input)
			target := mustCatalogTarget(t, catalog, policy.AuthnNamespace+"/"+string(mapping.action))

			checkpoint, exists := target.DomainPlan().Checkpoint(string(mapping.checkpoint))
			if !exists {
				t.Fatalf("compiled mapping has no %s checkpoint", mapping.checkpoint)
			}

			instances := checkpoint.ProviderInstances()
			if len(instances) != 1 {
				t.Fatalf("compiled mapping provider instances = %d, want 1", len(instances))
			}

			instance := instances[0]
			if instance.Name() != mapping.instanceName || instance.Use() != mapping.canonicalUse {
				t.Fatalf("compiled mapping identity = %q/%q, want %q/%q", instance.Name(), instance.Use(), mapping.instanceName, mapping.canonicalUse)
			}

			if !slices.Equal(instance.Actions(), []string{string(mapping.action)}) {
				t.Fatalf("compiled mapping actions = %v, want %s", instance.Actions(), mapping.action)
			}

			if instance.ObserveSafe() != mapping.observeSafe {
				t.Fatalf("compiled mapping observe_safe = %t, want %t", instance.ObserveSafe(), mapping.observeSafe)
			}

			assertCutoverMappingRuleGolden(t, target, checkpoint, mapping)
		})
	}
}

func TestProductionPolicyCutoverExtensibleMappingsRequireConfiguredCapabilities(t *testing.T) {
	for _, mapping := range cutoverCheckMappings {
		if mapping.kind == migrationReferenceFixed {
			continue
		}

		t.Run(mapping.checkType, func(t *testing.T) {
			document := cutoverCheckDocument(mapping)
			namespace := document.Policy.Namespaces[policy.AuthnNamespace]
			namespace.Providers = nil
			document.Policy.Namespaces[policy.AuthnNamespace] = namespace

			_, err := configinput.Normalize(context.Background(), document)
			if err == nil || !strings.Contains(err.Error(), ".use") {
				t.Fatalf("missing production capability error = %v, want provider-use path", err)
			}
		})
	}
}

func TestProductionPolicyCutoverRejectsUnqualifiedStandardAuth(t *testing.T) {
	document := cutoverCheckDocument(cutoverCheckMappings[0])
	document.Policy.Targets[0].DefaultPolicy = "standard_auth"

	_, err := configinput.Normalize(context.Background(), document)
	if err == nil || !strings.Contains(err.Error(), "policy.targets[0].default_policy") {
		t.Fatalf("unqualified standard_auth error = %v, want exact target path", err)
	}
}

// normalizeCutoverCheckDocument validates one manually authored production identity row.
func normalizeCutoverCheckDocument(t *testing.T, mapping cutoverCheckMapping) configinput.UnifiedPolicyInput {
	t.Helper()

	input, err := configinput.Normalize(context.Background(), cutoverCheckDocument(mapping))
	if err != nil {
		t.Fatalf("normalize production %s mapping: %v", mapping.checkType, err)
	}

	return input
}

// cutoverCheckDocument builds one isolated production-only identity contract.
func cutoverCheckDocument(mapping cutoverCheckMapping) policyconfig.Document {
	always := true

	provider := policyconfig.ProviderInstanceConfig{
		Name: mapping.instanceName, Use: mapping.canonicalUse,
		Actions: []string{string(mapping.action)},
	}
	if mapping.observeSafe {
		observeSafe := true
		provider.ObserveSafe = &observeSafe
	}

	namespace := policyconfig.NamespaceConfig{
		DomainPlans: map[string]policyconfig.DomainPlanConfig{
			"cutover_identity": {
				Checkpoints: map[string]policyconfig.CheckpointConfig{
					string(mapping.checkpoint): {Providers: []policyconfig.ProviderInstanceConfig{provider}},
				},
			},
		},
		PolicySets: map[string]policyconfig.PolicySetConfig{
			"configured": {
				Visibility: policyconfig.VisibilityPrivate,
				Rules: []policyconfig.PolicyRuleConfig{{
					Name: "requires_" + mapping.instanceName, Checkpoint: string(mapping.checkpoint),
					Actions: []string{string(mapping.action)}, RequireProviders: []string{mapping.instanceName},
					If: policyconfig.ConditionConfig{Always: &always},
					Then: policyconfig.ThenConfig{
						Decision: string(decision.EffectDeny), ResponseMarker: policy.ResponseMarkerFail,
					},
				}},
			},
		},
	}
	addCutoverProvider(mapping, &namespace)

	return policyconfig.Document{Policy: policyconfig.PolicyConfig{
		Namespaces: map[string]policyconfig.NamespaceConfig{policy.AuthnNamespace: namespace},
		Targets: []policyconfig.TargetConfig{{
			Namespace: policy.AuthnNamespace, Action: string(mapping.action), Schema: cutoverAuthnSchema(mapping.action),
			DomainPlan: "authn/cutover_identity", Mode: string(registry.AuthorityModeObserve),
			DefaultPolicy: registry.BuiltinStandardAuthPolicySet,
			Plans: map[string]policyconfig.TargetPlanConfig{
				string(mapping.checkpoint): {PolicySets: []string{"authn/configured"}},
			},
		}},
	}}
}

// addCutoverProvider declares only capabilities not owned by the builtin catalog.
func addCutoverProvider(mapping cutoverCheckMapping, namespace *policyconfig.NamespaceConfig) {
	if mapping.kind == migrationReferenceFixed {
		return
	}

	kind := "plugin"
	scriptPath := ""
	module := "acme"

	if mapping.kind == migrationReferenceLua {
		kind = "lua_environment"
		if mapping.checkType == policy.CheckTypeLuaSubjectSource {
			kind = "lua_subject"
		}

		scriptPath = "/test/" + strings.TrimPrefix(mapping.canonicalUse, policy.AuthnNamespace+"/") + ".lua"
		module = ""
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

// assertCutoverMappingRuleGolden binds the provider instance to one exact configured rule.
func assertCutoverMappingRuleGolden(
	t *testing.T,
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
	mapping cutoverCheckMapping,
) {
	t.Helper()

	identity, err := registry.NewPolicySetID(policy.AuthnNamespace, "configured")
	if err != nil {
		t.Fatalf("construct production configured set: %v", err)
	}

	set, exists := target.LookupPolicySet(identity)
	if !exists || len(set.Rules()) != 1 {
		t.Fatalf("compiled production configured rules = %d, want 1", len(set.Rules()))
	}

	rule := set.Rules()[0]
	if rule.Checkpoint() != checkpoint.Name() || !slices.Equal(rule.RequiredProviders(), []string{mapping.instanceName}) {
		t.Fatalf("compiled production rule = %q/%v, want %q/%q", rule.Checkpoint(), rule.RequiredProviders(), checkpoint.Name(), mapping.instanceName)
	}
}

// cutoverAuthnSchema resolves the immutable schema paired with one authn action.
func cutoverAuthnSchema(action policy.Operation) string {
	switch action {
	case policy.OperationAuthenticate:
		return "authn/authenticate/v1"
	case policy.OperationListAccounts:
		return "authn/list_accounts/v1"
	default:
		return ""
	}
}

// assertPolicyMigrationFrozenEvidence binds one mapping row to production source or catalog meaning.
func assertPolicyMigrationFrozenEvidence(
	t *testing.T,
	document policyconfig.Document,
	test policyMigrationContractCase,
) {
	t.Helper()

	if test.evidenceField.class() != test.evidenceClass {
		t.Fatalf("evidence class = %d, want %d", test.evidenceField.class(), test.evidenceClass)
	}

	got := productionMigrationEvidence(t, document, test.evidenceField)
	if !reflect.DeepEqual(got, test.expectedEvidenceValue) {
		t.Fatalf("frozen production evidence = %#v, want %#v", got, test.expectedEvidenceValue)
	}
}

// productionMigrationEvidence selects one value from the sole production representation.
func productionMigrationEvidence(
	t *testing.T,
	document policyconfig.Document,
	field migrationEvidenceField,
) any {
	t.Helper()

	if field.class() == migrationEvidenceActualCatalog {
		return productionCatalogMigrationEvidence(t, document, field)
	}

	namespace := document.Policy.Namespaces[policy.AuthnNamespace]
	if evidence, found := productionNamespaceMigrationEvidence(namespace, field); found {
		return evidence
	}

	return productionExternalMigrationEvidence(t, namespace, field)
}

// productionNamespaceMigrationEvidence selects scalar evidence owned directly by the namespace model.
func productionNamespaceMigrationEvidence(
	namespace policyconfig.NamespaceConfig,
	field migrationEvidenceField,
) (any, bool) {

	switch field {
	case migrationFieldLocalization:
		return namespace.Localization.Catalogs[0].Entries["denied"], true
	case migrationFieldNetworks:
		return namespace.ConditionSets.Networks["trusted"][0], true
	case migrationFieldStrings:
		return namespace.ConditionSets.Strings["privileged"][0], true
	case migrationFieldTimeWindows:
		return namespace.ConditionSets.TimeWindows["office"].Timezone, true
	case migrationFieldLuaEnvironment, migrationFieldLuaSubject:
		return policy.AuthnNamespace + "/" + sortedKeys(namespace.Providers)[0], true
	case migrationFieldLuaEffect:
		return policy.AuthnNamespace + "/" + sortedKeys(namespace.Effects)[0], true
	default:
		return nil, false
	}
}

// productionExternalMigrationEvidence selects file-backed and request-source evidence.
func productionExternalMigrationEvidence(
	t *testing.T,
	namespace policyconfig.NamespaceConfig,
	field migrationEvidenceField,
) any {
	t.Helper()

	switch field {
	case migrationFieldRegistryScripts:
		return productionRegistryScriptEvidence(t, namespace)
	case migrationFieldHTTPHeaders:
		return namespace.FactSources.HTTPHeaders[0].Attribute
	case migrationFieldGRPCMetadata:
		return namespace.FactSources.GRPCMetadata[0].Attribute
	case migrationFieldBackendAttributes:
		return namespace.FactSources.BackendAttributes[0].Sensitivity
	default:
		t.Fatalf("migration field %d has no frozen production evidence", field)

		return nil
	}
}

// productionRegistryScriptEvidence proves that the frozen registry declaration is present on disk.
func productionRegistryScriptEvidence(t *testing.T, namespace policyconfig.NamespaceConfig) string {
	t.Helper()

	source, err := os.ReadFile(namespace.SchemaContributions.Lua.RegistryScripts[0])
	if err != nil {
		t.Fatalf("read production registry script: %v", err)
	}

	if !strings.Contains(string(source), `id = "lua.contract.registry_flag"`) {
		t.Fatal("production registry script lacks frozen lua.contract.registry_flag declaration")
	}

	return "lua.contract.registry_flag"
}

// productionCatalogMigrationEvidence compiles one focused row through the actual target catalog.
func productionCatalogMigrationEvidence(
	t *testing.T,
	document policyconfig.Document,
	field migrationEvidenceField,
) any {
	t.Helper()

	prepared := prepareProductionMigrationEvidence(document, field)

	input, err := configinput.Normalize(context.Background(), prepared)
	if err != nil {
		t.Fatalf("normalize focused production migration evidence: %v", err)
	}

	target := mustCatalogTarget(t, compileUnifiedMigrationFixture(t, input), "authn/authenticate")
	if evidence, found := productionSimpleCatalogEvidence(target, field); found {
		return evidence
	}

	switch field {
	case migrationFieldSchedulerGuards:
		return productionSchedulerGuardEvidence(t, target)
	case migrationFieldChecks:
		return productionCheckEvidence(t, target)
	case migrationFieldRules:
		return productionRuleEvidence(t, target)
	default:
		t.Fatalf("migration field %d is not catalog evidence", field)

		return nil
	}
}

// productionSimpleCatalogEvidence returns catalog values that need no lookup validation.
func productionSimpleCatalogEvidence(
	target policyruntime.CompiledTarget,
	field migrationEvidenceField,
) (any, bool) {
	switch field {
	case migrationFieldMode:
		return string(target.AuthorityMode()), true
	case migrationFieldDefaultPolicy:
		return target.DefaultPolicySet().String(), true
	case migrationFieldReport:
		return target.Report().IncludeAttributes(), true
	default:
		return nil, false
	}
}

// productionSchedulerGuardEvidence returns the frozen missing-attribute behavior.
func productionSchedulerGuardEvidence(t *testing.T, target policyruntime.CompiledTarget) string {
	t.Helper()

	guard, exists := target.DomainPlan().SchedulerGuard("known_client")
	if !exists {
		t.Fatal("focused production scheduler guard is missing")
	}

	return guard.OnMissingAttribute()
}

// productionCheckEvidence returns the sole provider identity at the focused checkpoint.
func productionCheckEvidence(t *testing.T, target policyruntime.CompiledTarget) string {
	t.Helper()

	checkpoint, exists := target.DomainPlan().Checkpoint(string(policy.StagePreAuth))
	if !exists || len(checkpoint.ProviderInstances()) != 1 {
		t.Fatal("focused production check/provider is missing")
	}

	return checkpoint.ProviderInstances()[0].Use()
}

// productionRuleEvidence returns the checkpoint bound to the focused configured rule.
func productionRuleEvidence(t *testing.T, target policyruntime.CompiledTarget) string {
	t.Helper()

	identity, err := registry.NewPolicySetID(policy.AuthnNamespace, "configured")
	if err != nil {
		t.Fatalf("construct focused policy-set identity: %v", err)
	}

	set, exists := target.LookupPolicySet(identity)
	if !exists || len(set.Rules()) != 1 {
		t.Fatal("focused production rule is missing")
	}

	return set.Rules()[0].Checkpoint()
}

// prepareProductionMigrationEvidence adds only the activation context omitted by focused rows.
func prepareProductionMigrationEvidence(
	document policyconfig.Document,
	field migrationEvidenceField,
) policyconfig.Document {
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
		plan.Checkpoints = map[string]policyconfig.CheckpointConfig{string(policy.StagePreAuth): {}}
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

// assertPolicyMigrationDefaultOrIdentity proves the frozen default or qualified identity.
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

// policyMigrationDefaultOrIdentity returns one production default or exact qualified identity.
func policyMigrationDefaultOrIdentity(document policyconfig.Document, field migrationEvidenceField) any {
	if value, ok := productionMigrationTargetDefault(field); ok {
		return value
	}

	if value, ok := productionMigrationEmptyDefault(field); ok {
		return value
	}

	namespace := document.Policy.Namespaces[policy.AuthnNamespace]

	switch field {
	case migrationFieldLuaEnvironment, migrationFieldLuaSubject:
		return policy.AuthnNamespace + "/" + sortedKeys(namespace.Providers)[0]
	case migrationFieldLuaEffect:
		return policy.AuthnNamespace + "/" + sortedKeys(namespace.Effects)[0]
	case migrationFieldChecks:
		return namespace.DomainPlans["password"].Checkpoints[string(policy.StagePreAuth)].Providers[0].Use
	default:
		return nil
	}
}

// productionMigrationTargetDefault returns normalized target defaults.
func productionMigrationTargetDefault(field migrationEvidenceField) (any, bool) {
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
		return reportMeaning{
			Enabled: target.Report.Enabled, IncludeFSM: target.Report.IncludeFSM,
			IncludeChecks: target.Report.IncludeChecks, IncludeAttributes: target.Report.IncludeAttributes,
		}, true
	default:
		return nil, false
	}
}

// productionMigrationEmptyDefault proves source-owned collections normalize empty.
func productionMigrationEmptyDefault(field migrationEvidenceField) (any, bool) {
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

// loadUnifiedMigrationInput loads the frozen fixture through the production FileSettings path.
func loadUnifiedMigrationInput(t *testing.T) configinput.UnifiedPolicyInput {
	t.Helper()

	candidate := prepareResolvedProductionMigrationFixture(t)

	input, err := configinput.Normalize(context.Background(), policyconfig.Document{Policy: candidate.GetPolicy()})
	if err != nil {
		t.Fatalf("normalize production-loaded migration fixture: %v", err)
	}

	return input
}

// compileUnifiedMigrationFixture builds a real candidate catalog with the production effect supervisor.
func compileUnifiedMigrationFixture(t *testing.T, input configinput.UnifiedPolicyInput) *policyruntime.TargetCatalog {
	t.Helper()

	lifetime, cancel := context.WithCancel(context.Background())

	supervisor, err := effectsupervisor.New(effectsupervisor.Config{
		Lifetime: lifetime,
		Capacity: 4,
		Workers:  1,
	})
	if err != nil {
		cancel()
		t.Fatalf("construct production effect supervisor: %v", err)
	}

	t.Cleanup(func() {
		cancel()

		if shutdownErr := supervisor.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("shutdown production effect supervisor: %v", shutdownErr)
		}
	})

	catalog, err := input.Compile(context.Background(), supervisor)
	if err != nil {
		t.Fatalf("compile production migration fixture: %v", err)
	}

	return catalog
}

// mustCatalogTarget resolves one exact compiled target.
func mustCatalogTarget(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	identity string,
) policyruntime.CompiledTarget {
	t.Helper()

	namespace, action, ok := strings.Cut(identity, "/")
	if !ok {
		t.Fatalf("invalid test target identity %q", identity)
	}

	targetID, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("construct target %s: %v", identity, err)
	}

	target, exists := catalog.Lookup(targetID)
	if !exists {
		t.Fatalf("compiled catalog has no target %s", identity)
	}

	return target
}

// compiledReportMeaning detaches one immutable report selection for golden comparison.
func compiledReportMeaning(report registry.TargetReportSettings) reportMeaning {
	return reportMeaning{
		Enabled: report.Enabled(), IncludeFSM: report.IncludeFSM(),
		IncludeChecks: report.IncludeChecks(), IncludeAttributes: report.IncludeAttributes(),
	}
}

// sortedKeys returns deterministic keys for test-owned contract projections.
func sortedKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}

	sort.Strings(result)

	return result
}
