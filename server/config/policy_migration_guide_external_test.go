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
	"runtime"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	policyMigrationGuideHeading       = "### New standalone `policy` input"
	policyMigrationGuideNativeHeading = "## Generic native provider configuration"
)

type policyMigrationGuideAcceptance struct{}

// Accept supplies the capability needed to compile builtin post-action effects.
func (policyMigrationGuideAcceptance) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestPolicyMigrationGuideStandaloneExampleCompiles(t *testing.T) {
	source := policyMigrationGuideStandaloneYAML(t)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode documented standalone policy: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize documented standalone policy: %v", err)
	}

	if _, err = input.Compile(context.Background(), policyMigrationGuideAcceptance{}); err != nil {
		t.Fatalf("compile documented standalone policy: %v", err)
	}
}

func TestPolicyMigrationGuideGenericNativeExampleValidates(t *testing.T) {
	source := policyMigrationGuideFencedYAML(t, policyMigrationGuideNativeHeading)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode documented generic native policy: %v", err)
	}

	if err = policyconfig.Validate(document); err != nil {
		t.Fatalf("validate documented generic native policy: %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize documented generic native policy: %v", err)
	}

	catalog, err := input.Compile(context.Background(), policyMigrationGuideAcceptance{})
	if err != nil {
		t.Fatalf("compile documented generic native policy: %v", err)
	}

	assertPolicyMigrationGuideNativeCatalog(t, catalog)
	assertPolicyMigrationGuideNativeDocument(t, document)
}

// assertPolicyMigrationGuideNativeDocument checks the documented source-owned native contract.
func assertPolicyMigrationGuideNativeDocument(t *testing.T, document policyconfig.Document) {
	t.Helper()

	namespace := document.Policy.Namespaces["dkim2"]

	assertPolicyMigrationGuideNativeFactProvider(t, namespace)
	assertPolicyMigrationGuideNativeFactSchema(t, namespace)
	assertPolicyMigrationGuideNativeEffectProvider(t, namespace)
	assertPolicyMigrationGuideNativeEffectSelection(t, namespace)
}

// assertPolicyMigrationGuideNativeFactProvider checks the documented fact-provider identity and scope.
func assertPolicyMigrationGuideNativeFactProvider(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	provider := namespace.Providers["risk"]

	if got := provider.CanonicalID("dkim2", "risk"); got != "dkim2/plugin.reputation.risk" {
		t.Fatalf("documented native provider identity = %q, want dkim2/plugin.reputation.risk", got)
	}

	if provider.Module != "reputation" || len(provider.Targets) != 1 || provider.Targets[0].Action != "sign-message" {
		t.Fatalf("documented native module/targets = %q/%v", provider.Module, provider.Targets)
	}

	if got := provider.ProducedFacts; len(got) != 1 || got[0] != "plugin.reputation.risk_score" {
		t.Fatalf("documented native provider outputs = %v, want plugin.reputation.risk_score", got)
	}
}

// assertPolicyMigrationGuideNativeFactSchema checks the documented source authority.
func assertPolicyMigrationGuideNativeFactSchema(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	facts := namespace.SchemaContributions.Static["sign-message"].Versions["v1"].Facts

	if len(facts) != 1 || len(facts[0].AllowedSources) != 1 || facts[0].AllowedSources[0] != "plugin" {
		t.Fatalf("documented native fact schema = %v, want one plugin-sourced fact", facts)
	}
}

// assertPolicyMigrationGuideNativeEffectProvider checks the documented effect-provider binding and execution modes.
func assertPolicyMigrationGuideNativeEffectProvider(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	provider := namespace.Providers["risk"]
	notifier := namespace.Providers["notifier"]
	effect := namespace.Effects["record-audit"]

	if effect.Provider != "dkim2/plugin.reputation.notifier" ||
		effect.Provider != notifier.CanonicalID("dkim2", "notifier") ||
		effect.Execution != "host_sync" {
		t.Fatalf("documented native effect binding = %q/%q", effect.Provider, effect.Execution)
	}

	if len(provider.Executions) != 0 || len(notifier.Executions) != 1 || notifier.Executions[0] != "host_sync" {
		t.Fatalf("documented native fact/effect executions = %v/%v", provider.Executions, notifier.Executions)
	}
}

// assertPolicyMigrationGuideNativeEffectSelection checks the documented obligation selection and parameters.
func assertPolicyMigrationGuideNativeEffectSelection(t *testing.T, namespace policyconfig.NamespaceConfig) {
	t.Helper()

	rules := namespace.PolicySets["default"].Rules

	if len(rules) != 1 || len(rules[0].Then.Obligations) != 1 {
		t.Fatalf("documented native effect rules = %v, want one selected obligation", rules)
	}

	selection := rules[0].Then.Obligations[0]

	if selection.ID != "dkim2/record-audit" || selection.Parameters["channel"] != "security" {
		t.Fatalf("documented native effect selection = %q/%v", selection.ID, selection.Parameters)
	}
}

// assertPolicyMigrationGuideNativeCatalog checks exact native identities at the compiled target boundary.
func assertPolicyMigrationGuideNativeCatalog(t *testing.T, catalog *policyruntime.TargetCatalog) {
	t.Helper()

	target, err := decision.NewTarget("dkim2", "sign-message")
	if err != nil {
		t.Fatalf("construct documented generic native target: %v", err)
	}

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatal("documented generic native target is absent from compiled catalog")
	}

	if got := compiled.Schema().Identity().String(); got != "dkim2/sign-message/v1" {
		t.Fatalf("documented generic native schema = %q, want dkim2/sign-message/v1", got)
	}

	factProvider, exists := compiled.LookupProvider("dkim2/plugin.reputation.risk")
	if !exists || factProvider.ID() != "dkim2/plugin.reputation.risk" {
		t.Fatalf("documented native fact provider = %q, exists %t", factProvider.ID(), exists)
	}

	effectProvider, exists := compiled.LookupProvider("dkim2/plugin.reputation.notifier")
	if !exists || effectProvider.ID() != "dkim2/plugin.reputation.notifier" {
		t.Fatalf("documented native effect provider = %q, exists %t", effectProvider.ID(), exists)
	}

	effect, exists := compiled.LookupEffect("dkim2/record-audit")
	if !exists || effect.Provider() != effectProvider.ID() {
		t.Fatalf("documented selected effect provider = %q, exists %t", effect.Provider(), exists)
	}
}

// policyMigrationGuideStandaloneYAML extracts the fenced example owned by the migration guide.
func policyMigrationGuideStandaloneYAML(t *testing.T) string {
	t.Helper()

	return policyMigrationGuideFencedYAML(t, policyMigrationGuideHeading)
}

// policyMigrationGuideFencedYAML extracts the first fenced YAML example after one exact heading.
func policyMigrationGuideFencedYAML(t *testing.T, heading string) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve migration guide test path")
	}

	guidePath := filepath.Join(filepath.Dir(currentFile), "..", "docs", "policy_configuration_migration.md")

	guide, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("read migration guide: %v", err)
	}

	_, afterHeading, found := strings.Cut(string(guide), heading)
	if !found || strings.Contains(afterHeading, heading) {
		t.Fatalf("migration guide must contain exactly one %q heading", heading)
	}

	const fenceStart = "\n\n```yaml\n"
	if !strings.HasPrefix(afterHeading, fenceStart) {
		t.Fatalf("migration guide heading %q has no YAML fence", heading)
	}

	afterFence := strings.TrimPrefix(afterHeading, fenceStart)

	source, _, found := strings.Cut(afterFence, "\n```\n")
	if !found {
		t.Fatalf("migration guide heading %q has no closing fence", heading)
	}

	return source
}
