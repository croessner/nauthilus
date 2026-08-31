// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const dkim2ReferencePath = "../../docs/examples/policy_dkim2_rspamd_verifier.yml"

func TestDKIM2RspamdReferenceCompilesExactGenericTargetAndNativeAssessment(t *testing.T) {
	t.Parallel()

	input := normalizeDKIM2Reference(t)
	assertDKIM2ReferenceProvider(t, input)
	compiled := compileDKIM2ReferenceTarget(t, input)
	assertDKIM2ReferenceSchema(t, compiled.Schema())
	assertDKIM2ReferenceSchedule(t, compiled)
}

// assertDKIM2ReferenceProvider verifies the configured native provider contract.
func assertDKIM2ReferenceProvider(t *testing.T, input UnifiedPolicyInput) {
	t.Helper()

	provider, _ := findProviderAndEffectOptional(input, "dkim2/plugin.dkim2_reputation.assessment", "")
	if got := provider.ProducedFacts(); !slices.Equal(got, []string{"plugin.dkim2_reputation.assessed_chain"}) {
		t.Fatalf("assessor produced facts = %v", got)
	}

	if string(provider.Failure()) != "indeterminate" || provider.Timeout().String() != "400ms" {
		t.Fatalf("assessor failure/timeout = %s/%s", provider.Failure(), provider.Timeout())
	}
}

// assertDKIM2ReferenceSchema verifies the exact caller and provider fact shapes.
func assertDKIM2ReferenceSchema(t *testing.T, schema policyruntime.CompiledSchema) {
	t.Helper()

	assertDKIM2ReferenceFact(t, schema.Facts(), "resource.dkim2.chain", decision.ValueKindRecords, decision.FactSourceCaller, true)
	assertDKIM2ReferenceFact(t, schema.Facts(), "environment.rspamd.smtp_client_ip", decision.ValueKindString, decision.FactSourceCaller, true)
	assertDKIM2ReferenceFact(t, schema.Facts(), "plugin.dkim2_reputation.assessed_chain", decision.ValueKindRecords, decision.FactSourcePlugin, false)
	assertDKIM2ReferenceMaxItems(t, schema.Facts(), "environment.rspamd.normalized_signals", 20)
	assertDKIM2ReferenceMaxItems(t, schema.Facts(), "environment.rspamd.recipient_classes", 3)
	assertDKIM2VerifierChainSchema(t, schema.Facts())
	assertDKIM2AssessmentSchema(t, schema.Facts())
}

// assertDKIM2VerifierChainSchema verifies the bounded verifier record contract.
func assertDKIM2VerifierChainSchema(t *testing.T, facts []registry.FactSchema) {
	t.Helper()

	chain, _ := schemaFactByID(facts, "resource.dkim2.chain")

	chainSchema, ok := chain.RecordSchema()
	if !ok || chainSchema.MinRecords() != 1 || chainSchema.MaxRecords() != 128 || len(chainSchema.Fields()) != 23 {
		t.Fatalf("verifier chain schema = %#v", chainSchema)
	}

	changeClasses, ok := recordFieldByName(chainSchema.Fields(), "change_classes")
	if !ok || changeClasses.MaxItems() != 2 {
		t.Fatalf("change_classes schema = %#v, want max_items 2", changeClasses)
	}
}

// assertDKIM2AssessmentSchema verifies the exact native assessment record contract.
func assertDKIM2AssessmentSchema(t *testing.T, facts []registry.FactSchema) {
	t.Helper()

	assessment, _ := schemaFactByID(facts, "plugin.dkim2_reputation.assessed_chain")

	assessmentSchema, ok := assessment.RecordSchema()
	if !ok || assessmentSchema.MinRecords() != 1 || assessmentSchema.MaxRecords() != 128 || len(assessmentSchema.Fields()) != 10 {
		t.Fatalf("assessed chain schema = %#v", assessmentSchema)
	}

	fieldNames := make([]string, 0, len(assessmentSchema.Fields()))
	for _, field := range assessmentSchema.Fields() {
		fieldNames = append(fieldNames, field.Name())
	}

	wantFields := []string{
		"sequence", "message_instance", "hop_binding", "signer_reputation", "smtp_peer_reputation",
		"contract_state", "recipe_authorization", "assessment_complete", "acceptable", "violation_classes",
	}
	if !slices.Equal(fieldNames, wantFields) {
		t.Fatalf("assessed chain fields = %v, want %v", fieldNames, wantFields)
	}

	violationClasses, ok := recordFieldByName(assessmentSchema.Fields(), "violation_classes")
	if !ok || violationClasses.MaxItems() != 14 {
		t.Fatalf("violation_classes schema = %#v, want max_items 14", violationClasses)
	}
}

// assertDKIM2ReferenceSchedule verifies the guarded final-decision provider instance.
func assertDKIM2ReferenceSchedule(t *testing.T, compiled policyruntime.CompiledTarget) {
	t.Helper()

	checkpoint, ok := compiled.DomainPlan().Checkpoint(decision.CheckpointFinalDecision)
	if !ok || !slices.Equal(checkpoint.ProviderIDs(), []string{"dkim2/plugin.dkim2_reputation.assessment"}) {
		t.Fatalf("final provider schedule = %v", checkpoint.ProviderIDs())
	}

	instances := checkpoint.ProviderInstances()
	if len(instances) != 1 || !slices.Equal(instances[0].SkipIf(), []string{"nonpass_verifier_state"}) {
		t.Fatalf("assessment scheduler guard = %#v", instances)
	}
}

func TestDKIM2RspamdReferenceUsesRelativeWireAllowlistsAndIsNotBuiltin(t *testing.T) {
	t.Parallel()

	document := decodeDKIM2Reference(t)
	client := document.Policy.API.Clients[0]

	if !slices.Contains(client.AllowedResourceAttributes, "dkim2.chain") ||
		slices.Contains(client.AllowedResourceAttributes, "resource.dkim2.chain") {
		t.Fatalf("resource allowlist = %v, want wire-local dkim2 keys", client.AllowedResourceAttributes)
	}

	if !slices.Contains(client.AllowedEnvironmentAttributes, "rspamd.smtp_client_ip") ||
		slices.Contains(client.AllowedEnvironmentAttributes, "environment.rspamd.smtp_client_ip") {
		t.Fatalf("environment allowlist = %v, want wire-local rspamd keys", client.AllowedEnvironmentAttributes)
	}

	empty, err := Normalize(context.Background(), policyconfig.Document{})
	if err != nil {
		t.Fatalf("Normalize(empty) error = %v", err)
	}

	catalog, err := empty.Compile(context.Background(), nil)
	if err != nil {
		t.Fatalf("Compile(empty) error = %v", err)
	}

	target, _ := decision.NewTarget("dkim2", "accept-message-instance")
	if _, exists := catalog.Lookup(target); exists {
		t.Fatal("DKIM2 verifier target was hardcoded into the generic catalog")
	}
}

func TestDKIM2RspamdReferenceIsIsolatedFromAuthenticationFactsAndProviders(t *testing.T) {
	t.Parallel()

	input, err := Normalize(context.Background(), decodeDKIM2Reference(t))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	catalog, err := input.Compile(context.Background(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	target, _ := decision.NewTarget("dkim2", "accept-message-instance")

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("compiled DKIM2 verifier target is missing")
	}

	for _, fact := range compiled.Schema().Facts() {
		if strings.HasPrefix(fact.ID(), "subject.authn.") {
			t.Fatalf("DKIM2 schema contains authentication fact %q", fact.ID())
		}
	}

	if got := compiled.DomainPlan().Checkpoints(); len(got) != 1 || got[0].Name() != decision.CheckpointFinalDecision {
		t.Fatalf("DKIM2 checkpoints = %#v, want generic final_decision only", got)
	}

	if got := compiled.ProviderIDs(); !slices.Equal(got, []string{"dkim2/plugin.dkim2_reputation.assessment"}) {
		t.Fatalf("DKIM2 providers = %v, want isolated assessment provider", got)
	}
}

func TestDKIM2RspamdReferenceAdmissionPrefixesLocalWireFactsOnce(t *testing.T) {
	t.Parallel()

	prepared := prepareDKIM2ReferenceAdmission(t)
	caller, request := dkim2ReferenceAdmissionRequest(t)

	permit, err := prepared.Authority.Admit(t.Context(), caller, request)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	defer permit.Release()

	assertDKIM2AdmittedFacts(t, permit.Facts(), "192.0.2.25")
}

// assertDKIM2AdmittedFacts verifies exact single category qualification.
func assertDKIM2AdmittedFacts(t *testing.T, facts decision.FactSet, address string) {
	t.Helper()

	if _, ok := facts.Get("resource.dkim2.projection_schema"); !ok {
		t.Fatal("admission did not add the resource category prefix")
	}

	ip, ok := facts.Get("environment.rspamd.smtp_client_ip")
	if !ok {
		t.Fatal("admission did not add the environment category prefix")
	}

	gotIP, _ := ip.Value().StringValue()
	if gotIP != address {
		t.Fatalf("admitted SMTP peer = %q, want %q", gotIP, address)
	}

	if _, duplicate := facts.Get("environment.environment.rspamd.smtp_client_ip"); duplicate {
		t.Fatal("admission double-prefixed the local environment key")
	}
}

// prepareDKIM2ReferenceAdmission compiles the tracked authority and caller profile.
func prepareDKIM2ReferenceAdmission(t *testing.T) policyruntime.AdmissionPreparation {
	t.Helper()

	input := normalizeDKIM2Reference(t)

	catalog, err := input.Compile(t.Context(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{"rspamd-verifier"})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	prepared, err := admission.Prepare(input.CallerAdmission(), catalog, credentials)
	if err != nil {
		t.Fatalf("admission.Prepare() error = %v", err)
	}

	return prepared
}

// dkim2ReferenceAdmissionRequest constructs one local-key request at the public boundary.
func dkim2ReferenceAdmissionRequest(t *testing.T) (decision.CallerContext, decision.DecisionRequest) {
	t.Helper()

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "rspamd-verifier", AuthenticationKind: "basic", TransportKind: "http",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	target, _ := decision.NewTarget("dkim2", "accept-message-instance")
	resource := dkim2ReferenceEntity(t, "dkim2-message-instance", "dkim2.projection_schema", "dkim2.verifier-projection.v1")
	environment := dkim2ReferenceEnvironment(t, "rspamd.smtp_client_ip", "192.0.2.25")

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: "1", Target: target, Resource: resource, Environment: environment,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	return caller, request
}

// dkim2ReferenceEntity constructs one resource with a single local string fact.
func dkim2ReferenceEntity(t *testing.T, resourceType string, attribute string, text string) decision.Entity {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue(%s) error = %v", attribute, err)
	}

	entity, err := decision.NewEntity(decision.EntityInput{
		Type: resourceType, Attributes: map[string]decision.Value{attribute: value},
	})
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	return entity
}

// dkim2ReferenceEnvironment constructs one Rspamd environment with a local string fact.
func dkim2ReferenceEnvironment(t *testing.T, attribute string, text string) decision.Environment {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue(%s) error = %v", attribute, err)
	}

	environment, err := decision.NewEnvironment(decision.EnvironmentInput{
		Service: "rspamd", Instance: "mx01.example.net", Protocol: "milter",
		Attributes: map[string]decision.Value{attribute: value},
	})
	if err != nil {
		t.Fatalf("NewEnvironment() error = %v", err)
	}

	return environment
}

// normalizeDKIM2Reference normalizes the tracked executable Policy document.
func normalizeDKIM2Reference(t *testing.T) UnifiedPolicyInput {
	t.Helper()

	input, err := Normalize(t.Context(), decodeDKIM2Reference(t))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	return input
}

// compileDKIM2ReferenceTarget compiles and resolves the exact configured target.
func compileDKIM2ReferenceTarget(t *testing.T, input UnifiedPolicyInput) policyruntime.CompiledTarget {
	t.Helper()

	catalog, err := input.Compile(t.Context(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	target, _ := decision.NewTarget("dkim2", "accept-message-instance")

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("compiled DKIM2 verifier target is missing")
	}

	return compiled
}

// decodeDKIM2Reference reads the tracked executable configuration fixture.
func decodeDKIM2Reference(t *testing.T) policyconfig.Document {
	t.Helper()

	file, err := os.Open(dkim2ReferencePath)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", dkim2ReferencePath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Close(%s) error = %v", dkim2ReferencePath, closeErr)
		}
	}()

	document, err := policyconfig.Decode("yaml", file)
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	return document
}

// assertDKIM2ReferenceFact verifies one exact schema declaration.
func assertDKIM2ReferenceFact(
	t *testing.T,
	facts []registry.FactSchema,
	id string,
	kind decision.ValueKind,
	source decision.FactSource,
	required bool,
) {
	t.Helper()

	fact, ok := schemaFactByID(facts, id)
	if !ok || fact.Kind() != kind || !slices.Equal(fact.AllowedSources(), []decision.FactSource{source}) ||
		fact.Required() != required {
		t.Fatalf("fact %s = %#v, %t", id, fact, ok)
	}
}

// assertDKIM2ReferenceMaxItems verifies one fact collection bound.
func assertDKIM2ReferenceMaxItems(t *testing.T, facts []registry.FactSchema, id string, maxItems int) {
	t.Helper()

	fact, ok := schemaFactByID(facts, id)
	if !ok || fact.MaxItems() != maxItems {
		t.Fatalf("fact %s max_items = %d, want %d", id, fact.MaxItems(), maxItems)
	}
}

// schemaFactByID resolves one exact reference schema fact.
func schemaFactByID(facts []registry.FactSchema, id string) (registry.FactSchema, bool) {
	for _, fact := range facts {
		if fact.ID() == id {
			return fact, true
		}
	}

	return registry.FactSchema{}, false
}

// recordFieldByName resolves one exact field from a record schema.
func recordFieldByName(fields []registry.RecordFieldSchema, name string) (registry.RecordFieldSchema, bool) {
	for _, field := range fields {
		if field.Name() == name {
			return field, true
		}
	}

	return registry.RecordFieldSchema{}, false
}
