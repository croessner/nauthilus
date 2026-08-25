// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyprovider_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const configuredLuaCallbacks = `
_G["policy.facts.collect"] = function(request)
    if request.target.namespace ~= "mail" or request.target.action ~= "filter" then
        error("unexpected target")
    end

    return {
        facts = {
            { name = "score", value = { kind = "integer", value = "7" } },
        },
    }
end

_G["policy.effects.execute"] = function(request)
    if request.effect ~= "mail/record-sync" and request.effect ~= "mail/record-post" then
        error("unselected effect")
    end

    return { state = "succeeded" }
end
`

const configuredLuaPolicyTemplate = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          filter:
            versions:
              v1:
                facts:
                  - attribute: lua.risk.score
                    category: environment
                    type: integer
                    allowed_sources: [lua]
      providers:
        reputation:
          kind: lua
          module: risk
          script_path: %q
          targets: [{action: filter}]
          executions: [host_sync, host_post_action]
          produced_facts: [lua.risk.score]
          failure: continue
          timeout: 100ms
          diagnostics: {public_id: risk-provider}
      effects:
        record-sync:
          kind: obligation
          provider: mail/reputation
          targets: [{action: filter}]
          execution: host_sync
          diagnostics: {public_id: sync-effect}
          parameters:
            message:
              type: string
              max_length: 32
              allowed_strings: [accepted]
              non_empty: true
              required: true
        record-post:
          kind: obligation
          provider: mail/reputation
          targets: [{action: filter}]
          execution: host_post_action
          diagnostics: {public_id: post-effect}
          parameters:
            message:
              type: string
              max_length: 32
              allowed_strings: [accepted]
              non_empty: true
              required: true
      policy_sets:
        default: {rules: []}
  targets:
    - namespace: mail
      action: filter
      schema: mail/filter/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

func TestConfiguredLuaGenerationPreparesExactDefinitionsAndBindings(t *testing.T) {
	scriptPath := writeConfiguredLuaScript(t, "provider.lua", configuredLuaCallbacks)
	configured := decodeConfiguredLuaPolicy(t, configuredLuaPolicyYAML(scriptPath))
	before := configured.Namespaces["mail"].Providers["reputation"]
	acceptor := &generationTestAcceptor{}

	preparation, err := configinput.PrepareConfiguredLuaGeneration(t.Context(), configinput.ConfiguredLuaGenerationInput{
		Policy: configured, PostActionAcceptance: acceptor,
		NativeModules: []policyruntime.NativeModuleBindingInput{{
			ModuleName: "native-fixture", ArtifactPath: "/loaded/native-fixture.so", ArtifactDigest: "sha256:fixture",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v", err)
	}

	if !reflect.DeepEqual(before, configured.Namespaces["mail"].Providers["reputation"]) {
		t.Fatal("PrepareConfiguredLuaGeneration() mutated caller-owned configuration")
	}

	assertConfiguredLuaContribution(t, preparation)
	assertConfiguredLuaBindings(t, preparation)
}

func TestConfiguredLuaGenerationRejectsMissingCallbackWithoutLeakingPathOrScriptError(t *testing.T) {
	secretPath := writeConfiguredLuaScript(t, "secret-path-token.lua", `error("provider-secret-token")`)
	configured := decodeConfiguredLuaPolicy(t, configuredLuaPolicyYAML(secretPath))

	_, err := configinput.PrepareConfiguredLuaGeneration(t.Context(), configinput.ConfiguredLuaGenerationInput{
		Policy: configured, PostActionAcceptance: &generationTestAcceptor{},
	})
	if !errors.Is(err, policyprovider.ErrInvalidGenerationRegistration) {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v, want invalid registration", err)
	}

	for _, secret := range []string{secretPath, "secret-path-token", "provider-secret-token"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("preparation error exposed %q: %v", secret, err)
		}
	}
}

func TestConfiguredLuaGenerationAggregatesAuthoritiesAndRejectsCapabilityMismatch(t *testing.T) {
	configured := decodeConfiguredLuaPolicy(t, configuredLuaPolicyYAML(
		writeConfiguredLuaScript(t, "risk.lua", configuredLuaCallbacks),
	))
	addConfiguredGeoProvider(t, &configured, writeConfiguredLuaScript(t, "geo.lua", `
_G["policy.facts.collect"] = function(request)
    return { facts = { { name = "country", value = { kind = "string", value = "DE" } } } }
end
`))

	preparation, err := configinput.PrepareConfiguredLuaGeneration(t.Context(), configinput.ConfiguredLuaGenerationInput{
		Policy: configured, PostActionAcceptance: &generationTestAcceptor{},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v", err)
	}

	owners := make([]string, 0, len(preparation.Definitions))
	for _, contribution := range preparation.Definitions {
		owners = append(owners, contribution.Ownership().Owner())
	}

	if !reflect.DeepEqual(owners, []string{"lua.geo", "lua.risk"}) ||
		!reflect.DeepEqual(preparation.Bindings.FactProviderIDs(), []string{
			"mail/lua.geo.location", "mail/lua.risk.reputation",
		}) {
		t.Fatalf("owners/facts = %v/%v", owners, preparation.Bindings.FactProviderIDs())
	}

	namespace := configured.Namespaces["mail"]
	delete(namespace.Effects, "record-post")
	configured.Namespaces["mail"] = namespace

	_, err = configinput.PrepareConfiguredLuaGeneration(t.Context(), configinput.ConfiguredLuaGenerationInput{
		Policy: configured, PostActionAcceptance: &generationTestAcceptor{},
	})
	if !errors.Is(err, policyprovider.ErrInvalidGenerationRegistration) {
		t.Fatalf("PrepareConfiguredLuaGeneration(mismatch) error = %v, want invalid registration", err)
	}
}

func TestConfiguredLuaGenerationHonorsPreparationCancellation(t *testing.T) {
	configured := decodeConfiguredLuaPolicy(t, configuredLuaPolicyYAML(
		writeConfiguredLuaScript(t, "canceled.lua", configuredLuaCallbacks),
	))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := configinput.PrepareConfiguredLuaGeneration(ctx, configinput.ConfiguredLuaGenerationInput{
		Policy: configured, PostActionAcceptance: &generationTestAcceptor{},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v, want cancellation", err)
	}
}

func TestConfiguredLuaGenerationBoundsCallbackRegistration(t *testing.T) {
	configured := decodeConfiguredLuaPolicy(t, configuredLuaPolicyYAML(
		writeConfiguredLuaScript(t, "loop.lua", `while true do end`),
	))
	started := time.Now()

	_, err := configinput.PrepareConfiguredLuaGeneration(t.Context(), configinput.ConfiguredLuaGenerationInput{
		Policy: configured, PostActionAcceptance: &generationTestAcceptor{},
	})
	if !errors.Is(err, policyprovider.ErrInvalidGenerationRegistration) {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v, want bounded registration failure", err)
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("callback registration took %s, want provider-local bound", elapsed)
	}
}

// assertConfiguredLuaContribution verifies only authority-owned provider/effect definitions are returned.
func assertConfiguredLuaContribution(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	if len(preparation.Definitions) != 1 {
		t.Fatalf("definitions = %d, want one Lua authority contribution", len(preparation.Definitions))
	}

	contribution := preparation.Definitions[0]
	assertConfiguredLuaDefinitionKinds(t, contribution)
	assertConfiguredLuaProvider(t, contribution)
	assertConfiguredLuaEffects(t, contribution)
}

// assertConfiguredLuaDefinitionKinds rejects non-extension definition kinds.
func assertConfiguredLuaDefinitionKinds(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	if contribution.Ownership().Owner() != "lua.risk" {
		t.Fatalf("contribution owner = %q, want lua.risk", contribution.Ownership().Owner())
	}

	if len(contribution.Targets())+len(contribution.Schemas())+len(contribution.Plans())+
		len(contribution.PolicySets()) != 0 {
		t.Fatalf("contribution contains non-Lua definitions: %#v", contribution)
	}
}

// assertConfiguredLuaProvider verifies the normalized schedule and schema projection.
func assertConfiguredLuaProvider(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	providers := contribution.Providers()
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want one merged provider", len(providers))
	}

	provider := providers[0]
	if provider.ID() != "mail/lua.risk.reputation" || provider.DiagnosticID() != "risk-provider" {
		t.Fatalf("provider = %#v", provider)
	}

	if len(provider.Targets()) != 1 || provider.Targets()[0].String() != "mail/filter" {
		t.Fatalf("provider targets = %#v", provider.Targets())
	}

	if len(provider.Outputs()) != 1 || provider.Outputs()[0].ID() != "lua.risk.score" {
		t.Fatalf("provider outputs = %#v", provider.Outputs())
	}
}

// assertConfiguredLuaEffects verifies exact normalized diagnostic metadata.
func assertConfiguredLuaEffects(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	effects := contribution.Effects()
	if len(effects) != 2 {
		t.Fatalf("effects = %#v, want two normalized definitions", effects)
	}

	got := []string{
		effects[0].ID(), effects[0].DiagnosticID(),
		effects[1].ID(), effects[1].DiagnosticID(),
	}
	want := []string{"mail/record-post", "post-effect", "mail/record-sync", "sync-effect"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("effects = %#v, want normalized sync/post definitions", effects)
	}
}

// assertConfiguredLuaBindings verifies target-aware facts, selected effects, and native ownership once.
func assertConfiguredLuaBindings(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	assertConfiguredNativeBindings(t, preparation)
	assertConfiguredFactBinding(t, preparation)
	assertConfiguredEffectBindings(t, preparation)
}

// assertConfiguredNativeBindings verifies aggregate assembly inserts native modules once.
func assertConfiguredNativeBindings(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	if got := preparation.Bindings.NativeModuleIDs(); !reflect.DeepEqual(got, []string{"native-fixture"}) {
		t.Fatalf("native modules = %v, want one exact binding", got)
	}
}

// assertConfiguredFactBinding invokes one exact target-aware generic fact owner.
func assertConfiguredFactBinding(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	providerID := "mail/lua.risk.reputation"

	factBinding, exists := preparation.Bindings.FactProviders()[providerID]
	if !exists {
		t.Fatal("configured fact binding is missing")
	}

	if factBinding.Source != decision.FactSourceLua || factBinding.Authority != "risk" {
		t.Fatalf("fact binding = %#v", factBinding)
	}

	facts, err := factBinding.Provider.Collect(t.Context(), mustGenerationFactInput(t))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if len(facts) != 1 || facts[0].ID() != "lua.risk.score" || facts[0].Value().Kind() != decision.ValueKindInteger {
		t.Fatalf("facts = %#v", facts)
	}
}

// assertConfiguredEffectBindings invokes synchronous and prepared post-action owners.
func assertConfiguredEffectBindings(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	providerID := "mail/lua.risk.reputation"

	syncProvider, syncExists := preparation.Bindings.SyncEffects()[providerID]

	postProvider, postExists := preparation.Bindings.PostActions()[providerID]
	if !syncExists || !postExists {
		t.Fatalf("sync/post bindings = %t/%t", syncExists, postExists)
	}

	syncResult := syncProvider.Execute(t.Context(), configuredEffectExecution(t, "mail/record-sync", providerID, 1))
	if syncResult.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("sync result = %q", syncResult.State())
	}

	work, err := postProvider.Prepare(t.Context(), configuredEffectExecution(t, "mail/record-post", providerID, 2))
	if err != nil {
		t.Fatalf("Prepare(post) error = %v", err)
	}

	executable := work.(effectsupervisor.ExecutableWork)
	if result := executable.Execute(t.Context()); result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("post result = %q", result.State())
	}

	executable.Cleanup()
}

// configuredEffectExecution constructs one selected generic Lua effect invocation.
func configuredEffectExecution(
	t *testing.T,
	effectID string,
	providerID string,
	ordinal uint32,
) policyruntime.EffectExecution {
	t.Helper()

	parameters := configuredEffectParameters(t, map[string]decision.Value{
		"message": mustStringValue(t, "accepted"),
	})

	return configuredRuntimeEffect(t, policyruntime.EffectExecutionInput{
		Facts: mustGenerationFacts(t), Caller: mustGenerationCaller(t), Parameters: parameters,
		Target: mustPolicyTarget(t, "mail", "filter"), EffectID: effectID,
		DecisionID: "configured-lua", Provider: providerID, Generation: 1, Ordinal: ordinal,
	})
}

// configuredEffectParameters constructs one strict test parameter map.
func configuredEffectParameters(
	t *testing.T,
	values map[string]decision.Value,
) decision.ValueMap {
	t.Helper()

	parameters, err := decision.NewValueMap(values)
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	return parameters
}

// configuredRuntimeEffect owns one complete selected-effect test input.
func configuredRuntimeEffect(
	t *testing.T,
	input policyruntime.EffectExecutionInput,
) policyruntime.EffectExecution {
	t.Helper()

	execution, err := policyruntime.NewEffectExecution(input)
	if err != nil {
		t.Fatalf("NewEffectExecution() error = %v", err)
	}

	return execution
}

// writeConfiguredLuaScript creates one hermetic configured script below the test directory.
func writeConfiguredLuaScript(t *testing.T, name string, source string) string {
	t.Helper()

	path := t.TempDir() + "/" + name
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

// decodeConfiguredLuaPolicy decodes one standalone generic Lua configuration fixture.
func decodeConfiguredLuaPolicy(t *testing.T, source string) policyconfig.PolicyConfig {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	return document.Policy
}

// configuredLuaPolicyYAML binds one script to an exact target and two typed host effects.
func configuredLuaPolicyYAML(scriptPath string) string {
	return fmt.Sprintf(configuredLuaPolicyTemplate, scriptPath)
}

// addConfiguredGeoProvider extends the exact schema with a second independent Lua authority.
func addConfiguredGeoProvider(t *testing.T, configured *policyconfig.PolicyConfig, scriptPath string) {
	t.Helper()

	namespace := configured.Namespaces["mail"]
	schema := namespace.SchemaContributions.Static["filter"]
	version := schema.Versions["v1"]
	version.Facts = append(version.Facts, policyconfig.StaticFactSchemaConfig{
		Attribute: "lua.geo.country", Category: "environment", Type: "string",
		AllowedSources: []string{"lua"}, MaxLength: 2,
	})
	schema.Versions["v1"] = version
	namespace.SchemaContributions.Static["filter"] = schema
	namespace.Providers["location"] = policyconfig.ProviderConfig{
		Kind: policyconfig.ProviderKindLua, Module: "geo", ScriptPath: scriptPath,
		Targets:       []policyconfig.TargetReferenceConfig{{Action: "filter"}},
		ProducedFacts: []string{"lua.geo.country"}, Failure: "continue", Timeout: 100 * time.Millisecond,
	}
	configured.Namespaces["mail"] = namespace
}
