// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
)

const (
	recordReferenceNamespace  = "inventory"
	recordReferenceAction     = "inspect-shipment"
	recordReferenceAssessment = "inventory/plugin.inspector.assessment"
	recordReferenceLocator    = "inventory/plugin.locator.origin"
	recordReferencePrincipal  = "inventory-scanner"
	recordReferenceLegs       = "plugin.inspector.assessed_legs"
)

// TestRecordReferenceCompilesExplicitTargetAndNativeProviders verifies provider, schema and schedule compilation.
func TestRecordReferenceCompilesExplicitTargetAndNativeProviders(t *testing.T) {
	t.Parallel()

	input := normalizeRecordReference(t)
	assertRecordReferenceProvider(t, input)

	compiled := compileRecordReferenceTarget(t, input)
	assertRecordReferenceSchema(t, compiled.Schema())
	assertRecordReferenceSchedule(t, compiled)

	if compiled.AuthorityMode() != registry.AuthorityModeEnforce || len(compiled.EffectIDs()) != 0 {
		t.Fatalf("authority/effects = %s/%v, want enforce without effects", compiled.AuthorityMode(), compiled.EffectIDs())
	}
}

// TestRecordReferenceUsesRelativeWireAllowlistsAndIsNotBuiltin keeps operator targets out of the generic catalog.
func TestRecordReferenceUsesRelativeWireAllowlistsAndIsNotBuiltin(t *testing.T) {
	t.Parallel()

	client := decodeRecordReference(t).Policy.API.Clients[0]

	if !slices.Contains(client.AllowedResourceAttributes, "inventory.legs") ||
		slices.Contains(client.AllowedResourceAttributes, "resource.inventory.legs") {
		t.Fatalf("resource allowlist = %v, want wire-local keys", client.AllowedResourceAttributes)
	}

	if !slices.Contains(client.AllowedEnvironmentAttributes, "warehouse.dock_ip") ||
		slices.Contains(client.AllowedEnvironmentAttributes, "environment.warehouse.dock_ip") {
		t.Fatalf("environment allowlist = %v, want wire-local keys", client.AllowedEnvironmentAttributes)
	}

	empty, err := Normalize(context.Background(), policyconfig.Document{})
	if err != nil {
		t.Fatalf("Normalize(empty) error = %v", err)
	}

	catalog, err := empty.Compile(context.Background(), nil)
	if err != nil {
		t.Fatalf("Compile(empty) error = %v", err)
	}

	if _, exists := catalog.Lookup(recordReferenceTarget(t)); exists {
		t.Fatal("operator-declared target was hardcoded into the generic catalog")
	}
}

// TestRecordReferenceIsIsolatedFromAuthenticationFactsAndProviders keeps non-authentication targets independent.
func TestRecordReferenceIsIsolatedFromAuthenticationFactsAndProviders(t *testing.T) {
	t.Parallel()

	compiled := compileRecordReferenceTarget(t, normalizeRecordReference(t))

	for _, fact := range compiled.Schema().Facts() {
		if strings.HasPrefix(fact.ID(), "subject.authn.") {
			t.Fatalf("operator schema contains authentication fact %q", fact.ID())
		}
	}

	if got := compiled.DomainPlan().Checkpoints(); len(got) != 1 || got[0].Name() != decision.CheckpointFinalDecision {
		t.Fatalf("checkpoints = %#v, want generic final_decision only", got)
	}

	if got := compiled.ProviderIDs(); !sameRecordReferenceProviders(got) {
		t.Fatalf("providers = %v, want the declared native providers only", got)
	}
}

// TestRecordReferenceSchemaRejectsEmptyProviderCollection prevents vacuous all-record predicates.
func TestRecordReferenceSchemaRejectsEmptyProviderCollection(t *testing.T) {
	t.Parallel()

	compiled := compileRecordReferenceTarget(t, normalizeRecordReference(t))

	records, err := decision.NewRecordList(nil)
	if err != nil {
		t.Fatal(err)
	}

	value, err := decision.NewValue(decision.ValueInput{Records: &records})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = compiled.Schema().NormalizeValue(recordReferenceLegs, value); err == nil {
		t.Fatal("empty record collection satisfied min_records")
	}
}

// TestRecordReferenceAdmissionPrefixesLocalWireFactsOnce verifies exact single category qualification.
func TestRecordReferenceAdmissionPrefixesLocalWireFactsOnce(t *testing.T) {
	t.Parallel()

	prepared := prepareRecordReferenceAdmission(t)
	caller, request := recordReferenceAdmissionRequest(t)

	permit, err := prepared.Authority.Admit(t.Context(), caller, request)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	defer permit.Release()

	facts := permit.Facts()
	if _, ok := facts.Get("resource.inventory.manifest_schema"); !ok {
		t.Fatal("admission did not add the resource category prefix")
	}

	address, ok := facts.Get("environment.warehouse.dock_ip")
	if !ok {
		t.Fatal("admission did not add the environment category prefix")
	}

	if got, _ := address.Value().StringValue(); got != "192.0.2.25" {
		t.Fatalf("admitted dock address = %q, want 192.0.2.25", got)
	}

	if _, duplicate := facts.Get("environment.environment.warehouse.dock_ip"); duplicate {
		t.Fatal("admission double-prefixed the local environment key")
	}
}

// assertRecordReferenceProvider verifies the configured native provider contract.
func assertRecordReferenceProvider(t *testing.T, input UnifiedPolicyInput) {
	t.Helper()

	provider, _ := findProviderAndEffectOptional(input, recordReferenceAssessment, "")
	if got := provider.ProducedFacts(); !slices.Equal(got, []string{recordReferenceLegs, "plugin.inspector.assessment_complete"}) {
		t.Fatalf("assessment produced facts = %v", got)
	}

	if string(provider.Failure()) != "indeterminate" || provider.Timeout().String() != "400ms" {
		t.Fatalf("assessment failure/timeout = %s/%s", provider.Failure(), provider.Timeout())
	}
}

// assertRecordReferenceSchema verifies the exact caller and provider fact shapes and bounds.
func assertRecordReferenceSchema(t *testing.T, schema policyruntime.CompiledSchema) {
	t.Helper()

	assertRecordReferenceFact(t, schema.Facts(), "resource.inventory.legs", decision.ValueKindRecords, decision.FactSourceCaller, true)
	assertRecordReferenceFact(t, schema.Facts(), "environment.warehouse.dock_ip", decision.ValueKindString, decision.FactSourceCaller, true)
	assertRecordReferenceFact(t, schema.Facts(), recordReferenceLegs, decision.ValueKindRecords, decision.FactSourcePlugin, false)

	if signals, _ := findCompiledFactSchema(schema.Facts(), "environment.warehouse.signals"); signals.MaxItems() != 4 {
		t.Fatalf("signals max_items = %d, want 4", signals.MaxItems())
	}

	for _, tc := range []struct {
		id     string
		fields int
	}{{"resource.inventory.legs", 5}, {recordReferenceLegs, 7}} {
		fact, _ := findCompiledFactSchema(schema.Facts(), tc.id)

		records, ok := fact.RecordSchema()
		if !ok || records.MinRecords() != 1 || records.MaxRecords() != 8 || len(records.Fields()) != tc.fields ||
			records.MaxAggregateBytes() != 16384 {
			t.Fatalf("%s record schema = %#v", tc.id, records)
		}
	}
}

// assertRecordReferenceSchedule verifies all guarded providers of the final checkpoint.
func assertRecordReferenceSchedule(t *testing.T, compiled policyruntime.CompiledTarget) {
	t.Helper()

	checkpoint, ok := compiled.DomainPlan().Checkpoint(decision.CheckpointFinalDecision)
	if !ok || !sameRecordReferenceProviders(checkpoint.ProviderIDs()) {
		t.Fatalf("final provider schedule = %v", checkpoint.ProviderIDs())
	}

	for _, instance := range checkpoint.ProviderInstances() {
		if !slices.Equal(instance.SkipIf(), []string{"unverified_shipment"}) {
			t.Fatal("provider missing scheduler guard")
		}
	}
}

// assertRecordReferenceFact verifies one exact schema declaration.
func assertRecordReferenceFact(
	t *testing.T,
	facts []registry.FactSchema,
	id string,
	kind decision.ValueKind,
	source decision.FactSource,
	required bool,
) {
	t.Helper()

	fact, ok := findCompiledFactSchema(facts, id)
	if !ok || fact.Kind() != kind || !slices.Equal(fact.AllowedSources(), []decision.FactSource{source}) ||
		fact.Required() != required {
		t.Fatalf("fact %s = %#v, %t", id, fact, ok)
	}
}

// sameRecordReferenceProviders compares the exact provider owners without assuming map traversal order.
func sameRecordReferenceProviders(ids []string) bool {
	got := slices.Clone(ids)
	slices.Sort(got)

	return slices.Equal(got, []string{recordReferenceAssessment, recordReferenceLocator})
}

// prepareRecordReferenceAdmission compiles the tracked authority and caller profile.
func prepareRecordReferenceAdmission(t *testing.T) policyruntime.AdmissionPreparation {
	t.Helper()

	input := normalizeRecordReference(t)

	catalog, err := input.Compile(t.Context(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{recordReferencePrincipal})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	prepared, err := admission.Prepare(input.CallerAdmission(), catalog, credentials)
	if err != nil {
		t.Fatalf("admission.Prepare() error = %v", err)
	}

	return prepared
}

// recordReferenceAdmissionRequest constructs one local-key request at the public boundary.
func recordReferenceAdmissionRequest(t *testing.T) (decision.CallerContext, decision.DecisionRequest) {
	t.Helper()

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: recordReferencePrincipal, AuthenticationKind: "basic", TransportKind: "http",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	resource, err := decision.NewEntity(decision.EntityInput{
		Type:       "inventory-shipment",
		Attributes: map[string]decision.Value{"inventory.manifest_schema": recordReferenceString(t, "inventory.manifest.v1")},
	})
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	environment, err := decision.NewEnvironment(decision.EnvironmentInput{
		Service: "warehouse", Instance: "wh01.example.net", Protocol: "http",
		Attributes: map[string]decision.Value{"warehouse.dock_ip": recordReferenceString(t, "192.0.2.25")},
	})
	if err != nil {
		t.Fatalf("NewEnvironment() error = %v", err)
	}

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: "1", Target: recordReferenceTarget(t), Resource: resource, Environment: environment,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	return caller, request
}

// recordReferenceString constructs one immutable string value.
func recordReferenceString(t *testing.T, text string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue(%q) error = %v", text, err)
	}

	return value
}

// recordReferenceTarget returns the operator-declared target of the tracked fixture.
func recordReferenceTarget(t *testing.T) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(recordReferenceNamespace, recordReferenceAction)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}

// normalizeRecordReference normalizes the tracked executable Policy document.
func normalizeRecordReference(t *testing.T) UnifiedPolicyInput {
	t.Helper()

	input, err := Normalize(t.Context(), decodeRecordReference(t))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	return input
}

// compileRecordReferenceTarget compiles and resolves the exact configured target.
func compileRecordReferenceTarget(t *testing.T, input UnifiedPolicyInput) policyruntime.CompiledTarget {
	t.Helper()

	catalog, err := input.Compile(t.Context(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	compiled, ok := catalog.Lookup(recordReferenceTarget(t))
	if !ok {
		t.Fatal("compiled operator-declared target is missing")
	}

	return compiled
}

// decodeRecordReference reads the tracked executable configuration through the production decoder.
func decodeRecordReference(t *testing.T) policyconfig.Document {
	t.Helper()

	document, err := policyconfig.Decode("yaml", bytes.NewReader(testsupport.TrackedRecordPolicyBytes(t)))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	return document
}
