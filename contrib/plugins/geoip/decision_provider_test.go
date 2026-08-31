// Copyright (C) 2026 Christian Roessner
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
)

func TestTopLevelPolicyExampleReferencesRegisteredDecisionFactProvider(t *testing.T) {
	registry, _ := registerTestPlugin(t, testModule(testDatabasePath(t, "geoip.json")))
	providers := registry.DecisionFactProviders()

	if len(providers) != 1 {
		t.Fatalf("generic fact providers = %d, want 1", len(providers))
	}

	descriptor := providers[0].DecisionFactProviderDescriptor
	if descriptor.Namespace != "authn" || descriptor.Name != componentSource {
		t.Fatalf("generic fact descriptor = %#v, want authn/%s", descriptor, componentSource)
	}

	if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		t.Fatalf("ValidateDecisionFactProviderDescriptor() error = %v", err)
	}

	if len(descriptor.Outputs) != 26 {
		t.Fatalf("generic fact outputs = %d, want exact 26-fact contract", len(descriptor.Outputs))
	}

	example := readPolicyExample(t, "go_plugin_geoip.yml")
	for _, fragment := range []string{
		"policy:\n",
		"        " + componentSource + ":\n",
		"          kind: native\n",
		"          module: " + pluginName + "\n",
		"                  use: authn/plugin." + pluginName + "." + componentSource + "\n",
	} {
		if !strings.Contains(example, fragment) {
			t.Errorf("policy example does not reference registered generic descriptor fragment %q", fragment)
		}
	}

	for _, output := range descriptor.Outputs {
		qualified := "plugin." + pluginName + "." + output.Name
		if !strings.Contains(example, qualified) {
			t.Errorf("policy example omits registered generic output %q", qualified)
		}
	}
}

func TestTopLevelPolicyExampleSatisfiesStandaloneContract(t *testing.T) {
	registry, _ := registerTestPlugin(t, testModule(testDatabasePath(t, "geoip.json")))
	descriptor := registry.DecisionFactProviders()[0].DecisionFactProviderDescriptor
	example := readPolicyExample(t, "go_plugin_geoip.yml")

	settings, err := policyconfig.DecodeSettings("yaml", strings.NewReader(example))
	if err != nil {
		t.Fatalf("DecodeSettings() error = %v", err)
	}

	policyJSON, err := json.Marshal(map[string]any{"policy": settings["policy"]})
	if err != nil {
		t.Fatalf("marshal isolated policy: %v", err)
	}

	document, err := policyconfig.Decode("json", bytes.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	assertPolicyExampleDescriptor(t, document, descriptor)

	if err := policyconfig.Validate(document); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	assertBoundGeoIPSchemaContribution(t, registry, descriptor)
}

func TestDecisionFactProviderReusesRedactedGeoIPLookup(t *testing.T) {
	runner, plugin, _, _ := startedTestRunnerWithPlugin(t, testModule(testDatabasePath(t, "geoip.json")))
	defer stopRunner(t, runner)

	provider := geoIPDecisionFactProvider{plugin: plugin}

	for _, action := range []string{"authenticate", "lookup_identity"} {
		t.Run(action, func(t *testing.T) {
			request := newGeoIPDecisionFactRequest(t, action, testClientIP)

			result, err := provider.Collect(context.Background(), request)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}

			if err := pluginapi.ValidateDecisionFactResult(provider.Descriptor(), result); err != nil {
				t.Fatalf("ValidateDecisionFactResult() error = %v", err)
			}

			assertDecisionOutput(t, result, "matched", true)
			assertDecisionOutput(t, result, "country_iso", testCountryDE)
			assertDecisionOutput(t, result, "asn", int64(64500))
		})
	}
}

func TestDecisionFactProviderRejectsMalformedAdmittedInput(t *testing.T) {
	provider := geoIPDecisionFactProvider{plugin: NewPlugin()}

	for _, test := range malformedDecisionInputCases(t) {
		t.Run(test.name, func(t *testing.T) {
			assertDecisionProviderRejectsMalformedInput(t, provider, test)
		})
	}
}

type malformedDecisionInputCase struct {
	fact   *pluginapi.DecisionFactView
	name   string
	target pluginapi.DecisionTargetSelector
}

// malformedDecisionInputCases builds each invalid admitted input shape from constructor-valid values.
func malformedDecisionInputCases(t *testing.T) []malformedDecisionInputCase {
	t.Helper()

	validString := decisionStringValue(t, testClientIP)
	invalidAddress := decisionStringValue(t, "not-an-address")
	integer := int64(1)

	integerValue, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Integer: &integer})
	if err != nil {
		t.Fatalf("NewDecisionValue(integer) error = %v", err)
	}

	validTarget := pluginapi.DecisionTargetSelector{Namespace: decisionPolicyNamespace, Action: "authenticate"}

	return []malformedDecisionInputCase{
		{name: "missing fact", target: validTarget},
		{
			name: "wrong category", target: validTarget,
			fact: decisionFactView(t, decisionInputClientIP, pluginapi.DecisionFactCategorySubject, validString),
		},
		{
			name: "wrong kind", target: validTarget,
			fact: decisionFactView(t, decisionInputClientIP, pluginapi.DecisionFactCategoryEnvironment, integerValue),
		},
		{
			name: "invalid address", target: validTarget,
			fact: decisionFactView(t, decisionInputClientIP, pluginapi.DecisionFactCategoryEnvironment, invalidAddress),
		},
		{
			name:   "wrong target",
			target: pluginapi.DecisionTargetSelector{Namespace: decisionPolicyNamespace, Action: "authorize"},
			fact:   decisionFactView(t, decisionInputClientIP, pluginapi.DecisionFactCategoryEnvironment, validString),
		},
	}
}

// assertDecisionProviderRejectsMalformedInput verifies one invalid input maps to the exclusive public error class.
func assertDecisionProviderRejectsMalformedInput(
	t *testing.T,
	provider geoIPDecisionFactProvider,
	test malformedDecisionInputCase,
) {
	t.Helper()

	facts := []pluginapi.DecisionFactView(nil)
	if test.fact != nil {
		facts = append(facts, *test.fact)
	}

	result, err := provider.Collect(context.Background(), newDecisionFactRequest(t, test.target, facts))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if result.ErrorClass != pluginapi.DecisionErrorClassInvalidInput || len(result.Facts) != 0 {
		t.Fatalf("Collect() result = %#v, want exclusive invalid-input failure", result)
	}

	if err := pluginapi.ValidateDecisionFactResult(provider.Descriptor(), result); err != nil {
		t.Fatalf("ValidateDecisionFactResult() error = %v", err)
	}
}

func TestDecisionFactProviderRejectsOutputsOutsideDescriptorBounds(t *testing.T) {
	oversizedText := strings.Repeat("x", decisionOutputMaximumStringBytes+1)
	plugin := NewPlugin()
	plugin.swapDatabases(
		context.Background(),
		moduleConfig{LookupTimeout: time.Second},
		geoDatabases{primary: &fileDatabase{records: []geoRecord{{
			Prefix:      mustPrefix(t, "203.0.113.0/24"),
			CountryName: oversizedText,
		}}}},
		false,
	)
	t.Cleanup(func() {
		if err := plugin.Stop(context.Background()); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})

	provider := geoIPDecisionFactProvider{plugin: plugin}

	_, err := provider.Collect(
		context.Background(),
		newGeoIPDecisionFactRequest(t, "authenticate", testClientIP),
	)
	if err == nil || !strings.Contains(err.Error(), "string exceeds generic output bound") {
		t.Fatalf("Collect() error = %v, want bounded string rejection", err)
	}

	tests := []struct {
		value any
		name  string
	}{
		{name: "too many strings", value: make([]string, decisionOutputMaximumStrings+1)},
		{name: "oversized member", value: []string{oversizedText}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, valueErr := geoIPDecisionValue(test.value); valueErr == nil {
				t.Fatal("geoIPDecisionValue() error = nil, want declared bound rejection")
			}
		})
	}
}

func TestDecisionFactProviderCollectAcrossReconfigure(t *testing.T) {
	fixture := newDecisionReconfigureFixture(t)
	defer stopRunner(t, fixture.runner)

	collectedResult := collectDecisionFactAsync(fixture.provider, fixture.request)
	<-fixture.initial.started

	fixture.reconfigure(t)
	assertActiveDecisionDatabaseRemainsOpen(t, fixture.initial)
	fixture.initial.unblock()

	active := <-collectedResult
	assertCollectedDecisionCountry(t, fixture.provider, active, testCountryDE)
	<-fixture.initial.closed

	current, err := fixture.provider.Collect(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Collect() after reconfigure error = %v", err)
	}

	assertDecisionOutput(t, current, "country_iso", testReloadedCountry)
}

type decisionReconfigureFixture struct {
	runner          *pluginruntime.Runner
	initial         *lifecycleTestDatabase
	provider        geoIPDecisionFactProvider
	request         pluginapi.DecisionFactRequest
	replacementPath string
}

type collectedDecisionFact struct {
	result pluginapi.DecisionFactResult
	err    error
}

// newDecisionReconfigureFixture starts one plugin whose two paths resolve to controlled database lifecycles.
func newDecisionReconfigureFixture(t *testing.T) decisionReconfigureFixture {
	t.Helper()

	initialPath := testDatabasePath(t, "geoip.json")
	replacementPath := testDatabasePath(t, "geoip-reload.json")
	initial := newLifecycleTestDatabase(testCountryDE, true)
	replacement := newLifecycleTestDatabase(testReloadedCountry, false)
	plugin := NewPlugin()
	plugin.databaseLoad = func(_ context.Context, config moduleConfig) (geoDatabase, error) {
		switch config.DatabasePath {
		case initialPath:
			return initial, nil
		case replacementPath:
			return replacement, nil
		default:
			return nil, fmt.Errorf("unexpected database path %q", config.DatabasePath)
		}
	}

	module := testModule(initialPath)
	module.Config["lookup_timeout"] = "5s"
	registry, _ := registerTestPluginInstance(t, plugin, module)

	runner := newRunnerForPlugin(registry, plugin, module, newRecordingMetrics(), &recordingTracer{})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	provider := geoIPDecisionFactProvider{plugin: plugin}
	request := newGeoIPDecisionFactRequest(t, "authenticate", testClientIP)

	return decisionReconfigureFixture{
		runner: runner, initial: initial, provider: provider, request: request, replacementPath: replacementPath,
	}
}

// collectDecisionFactAsync starts one collection so reconfiguration can race only at the controlled database barrier.
func collectDecisionFactAsync(
	provider geoIPDecisionFactProvider,
	request pluginapi.DecisionFactRequest,
) <-chan collectedDecisionFact {
	collectedResult := make(chan collectedDecisionFact, 1)

	go func() {
		result, err := provider.Collect(context.Background(), request)
		collectedResult <- collectedDecisionFact{result: result, err: err}
	}()

	return collectedResult
}

// reconfigure publishes the replacement database through the real runner lifecycle.
func (f decisionReconfigureFixture) reconfigure(t *testing.T) {
	t.Helper()

	if err := f.runner.Reconfigure(
		context.Background(),
		testConfigFile(testModule(f.replacementPath)),
	); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
}

// assertActiveDecisionDatabaseRemainsOpen verifies replacement does not retire an in-flight owner.
func assertActiveDecisionDatabaseRemainsOpen(t *testing.T, initial *lifecycleTestDatabase) {
	t.Helper()

	select {
	case <-initial.closed:
		t.Fatal("Reconfigure() closed the database used by an active generic collection")
	default:
	}
}

// assertCollectedDecisionCountry validates one completed generic collection and its expected country fact.
func assertCollectedDecisionCountry(
	t *testing.T,
	provider geoIPDecisionFactProvider,
	active collectedDecisionFact,
	want string,
) {
	t.Helper()

	if active.err != nil {
		t.Fatalf("Collect() across reconfigure error = %v", active.err)
	}

	if err := pluginapi.ValidateDecisionFactResult(provider.Descriptor(), active.result); err != nil {
		t.Fatalf("ValidateDecisionFactResult(active) error = %v", err)
	}

	assertDecisionOutput(t, active.result, "country_iso", want)
}

func TestDecisionFactProviderUsesImmutableBoundedTimeoutCapability(t *testing.T) {
	plugin := NewPlugin()
	plugin.mu.Lock()
	plugin.config.LookupTimeout = time.Second
	plugin.mu.Unlock()

	descriptor := (geoIPDecisionFactProvider{plugin: plugin}).Descriptor()
	if descriptor.Timeout != pluginapi.MaximumDecisionFactProviderTimeout {
		t.Fatalf("descriptor timeout = %s, want immutable capability %s", descriptor.Timeout, pluginapi.MaximumDecisionFactProviderTimeout)
	}

	_, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		"database_path":  testDatabasePath(t, "geoip.json"),
		"lookup_timeout": (pluginapi.MaximumDecisionFactProviderTimeout + time.Nanosecond).String(),
	}))
	if err == nil {
		t.Fatal("decodeModuleConfig() error = nil, want generic capability timeout bound")
	}
}

// newGeoIPDecisionFactRequest builds one exact authn request with an admitted client-IP fact.
func newGeoIPDecisionFactRequest(t *testing.T, action string, clientIP string) pluginapi.DecisionFactRequest {
	t.Helper()

	value := decisionStringValue(t, clientIP)
	fact := decisionFactView(
		t,
		decisionInputClientIP,
		pluginapi.DecisionFactCategoryEnvironment,
		value,
	)

	return newDecisionFactRequest(
		t,
		pluginapi.DecisionTargetSelector{Namespace: "authn", Action: action},
		[]pluginapi.DecisionFactView{*fact},
	)
}

// newDecisionFactRequest constructs one generic request from already strict facts.
func newDecisionFactRequest(
	t *testing.T,
	target pluginapi.DecisionTargetSelector,
	facts []pluginapi.DecisionFactView,
) pluginapi.DecisionFactRequest {
	t.Helper()

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{
		Principal:          "authn-runtime",
		AuthenticationKind: "internal",
	})
	if err != nil {
		t.Fatalf("NewDecisionCallerView() error = %v", err)
	}

	request, err := pluginapi.NewDecisionFactRequest(target, caller, facts)
	if err != nil {
		t.Fatalf("NewDecisionFactRequest() error = %v", err)
	}

	return request
}

// decisionStringValue creates one constructor-validated generic string value.
func decisionStringValue(t *testing.T, value string) pluginapi.DecisionValue {
	t.Helper()

	strict, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &value})
	if err != nil {
		t.Fatalf("NewDecisionValue() error = %v", err)
	}

	return strict
}

// decisionFactView creates one constructor-validated generic fact view.
func decisionFactView(
	t *testing.T,
	id string,
	category pluginapi.DecisionFactCategory,
	value pluginapi.DecisionValue,
) *pluginapi.DecisionFactView {
	t.Helper()

	fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{
		ID: id, Category: category, Value: value,
	})
	if err != nil {
		t.Fatalf("NewDecisionFactView() error = %v", err)
	}

	return &fact
}

// assertPolicyExampleDescriptor compares the parsed provider and schema to the registered capability.
func assertPolicyExampleDescriptor(
	t *testing.T,
	document policyconfig.Document,
	descriptor pluginapi.DecisionFactProviderDescriptor,
) {
	t.Helper()

	namespace, exists := document.Policy.Namespaces[descriptor.Namespace]
	if !exists {
		t.Fatalf("policy namespace %q is missing", descriptor.Namespace)
	}

	provider, exists := namespace.Providers[descriptor.Name]
	if !exists {
		t.Fatalf("policy provider %q is missing", descriptor.Name)
	}

	if provider.Kind != policyconfig.ProviderKindNative || provider.Module != pluginName {
		t.Fatalf("policy provider = %#v, want native module %q", provider, pluginName)
	}

	wantActions := make([]string, 0, len(descriptor.Targets))
	for _, target := range descriptor.Targets {
		wantActions = append(wantActions, target.Action)
	}

	gotActions := make([]string, 0, len(provider.Targets))
	for _, target := range provider.Targets {
		gotActions = append(gotActions, target.Action)
	}

	if !reflect.DeepEqual(gotActions, wantActions) {
		t.Fatalf("provider targets = %#v, want %#v", gotActions, wantActions)
	}

	wantFacts := make([]string, 0, len(descriptor.Outputs))
	for _, output := range descriptor.Outputs {
		wantFacts = append(wantFacts, "plugin."+pluginName+"."+output.Name)
	}

	if !reflect.DeepEqual(provider.ProducedFacts, wantFacts) {
		t.Fatalf("provider produced_facts = %#v, want %#v", provider.ProducedFacts, wantFacts)
	}

	bindings := namespace.DomainPlans["geoip"].Checkpoints["pre_auth"].Providers
	if !containsProviderBinding(bindings, "authn/plugin."+pluginName+"."+descriptor.Name) {
		t.Fatalf("pre_auth bindings = %#v, want registered generic provider", bindings)
	}
}

// assertBoundGeoIPSchemaContribution verifies the real native binding extends both builtin authn schemas.
func assertBoundGeoIPSchemaContribution(
	t *testing.T,
	registry *pluginregistry.Registry,
	descriptor pluginapi.DecisionFactProviderDescriptor,
) {
	t.Helper()

	ownership, err := policyregistry.NewNamespaceOwnership("plugin."+pluginName, []string{descriptor.Namespace})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	native, err := pluginregistry.NewNativeDecisionContribution(registry, pluginName, ownership)
	if err != nil {
		t.Fatalf("NewNativeDecisionContribution() error = %v", err)
	}

	builtin, err := policyregistry.NewBuiltinTargetContributor().Contribute(context.Background())
	if err != nil {
		t.Fatalf("builtin Contribute() error = %v", err)
	}

	extended, err := policyregistry.ExtendBuiltinAuthnSchemas(builtin, native)
	if err != nil {
		t.Fatalf("ExtendBuiltinAuthnSchemas() error = %v", err)
	}

	for _, target := range descriptor.Targets {
		facts := boundSchemaFacts(t, extended.Schemas(), descriptor.Namespace, target.Action)
		assertBoundGeoIPTargetFacts(t, target.Action, facts, descriptor.Outputs)
	}
}

// assertBoundGeoIPTargetFacts verifies every declared output against one extended target schema.
func assertBoundGeoIPTargetFacts(
	t *testing.T,
	action string,
	facts map[string]policyregistry.FactSchema,
	outputs []pluginapi.DecisionFactOutputDescriptor,
) {
	t.Helper()

	for _, output := range outputs {
		qualified := "plugin." + pluginName + "." + output.Name

		fact, exists := facts[qualified]
		if !exists {
			t.Errorf("%s schema omits %q", action, qualified)

			continue
		}

		assertBoundGeoIPFact(t, action, qualified, fact, output)
	}
}

// assertBoundGeoIPFact compares one immutable schema fact to its public descriptor.
func assertBoundGeoIPFact(
	t *testing.T,
	action string,
	qualified string,
	fact policyregistry.FactSchema,
	output pluginapi.DecisionFactOutputDescriptor,
) {
	t.Helper()

	if string(fact.Category()) != string(output.Category) || string(fact.Kind()) != string(output.Kind) ||
		fact.MaxLength() != output.MaxLength || fact.MaxItems() != output.MaxItems ||
		fact.MaxBytes() != output.MaxBytes ||
		!reflect.DeepEqual(fact.AllowedSources(), []decision.FactSource{decision.FactSourcePlugin}) {
		t.Errorf("%s schema fact %q = %#v, want descriptor %#v from plugin", action, qualified, fact, output)
	}
}

// boundSchemaFacts indexes the selected immutable builtin authn schema.
func boundSchemaFacts(
	t *testing.T,
	schemas []policyregistry.SchemaDefinition,
	namespace string,
	action string,
) map[string]policyregistry.FactSchema {
	t.Helper()

	for _, schema := range schemas {
		identity := schema.Identity()
		if identity.Namespace() != namespace || identity.Name() != action || identity.Version().String() != "v1" {
			continue
		}

		facts := schema.Facts()

		indexed := make(map[string]policyregistry.FactSchema, len(facts))
		for _, fact := range facts {
			indexed[fact.ID()] = fact
		}

		return indexed
	}

	t.Fatalf("bound schema %s/%s/v1 missing", namespace, action)

	return nil
}

// containsProviderBinding reports whether one checkpoint selects the exact canonical provider ID.
func containsProviderBinding(bindings []policyconfig.ProviderInstanceConfig, canonicalID string) bool {
	for _, binding := range bindings {
		if binding.Use == canonicalID {
			return true
		}
	}

	return false
}

// assertDecisionOutput verifies one generic result member without exposing other output values.
func assertDecisionOutput(t *testing.T, result pluginapi.DecisionFactResult, name string, want any) {
	t.Helper()

	for _, output := range result.Facts {
		if output.Name != name {
			continue
		}

		got, ok := output.Value.Any()
		if !ok || got != want {
			t.Fatalf("generic output %q = %#v/%t, want %#v", name, got, ok, want)
		}

		return
	}

	t.Fatalf("generic output %q is missing", name)
}

// readPolicyExample returns one repository-owned top-level plugin example.
func readPolicyExample(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "server", "docs", "examples", name)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy example %q: %v", path, err)
	}

	return string(content)
}
