package main

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestAssessmentRecordPreservesCorrelationAndConditionalDetails prevents missing evidence from becoming numeric zero facts.
func TestAssessmentRecordPreservesCorrelationAndConditionalDetails(t *testing.T) {
	subject := extractedSubject{subjectInput: subjectInput{role: "peer", kind: kindIP}}
	tuple := emptyAssessment(assessmentMissing, profileOperational)
	record, err := assessmentRecord(subject, tuple)
	requireNoError(t, err)

	fields := make(map[string]bool)
	for _, field := range record.Fields() {
		fields[field.Name()] = true
	}

	for _, name := range []string{"role", "kind", "state", "profile", "band", "override"} {
		if !fields[name] {
			t.Fatal("required identity or assessment field missing")
		}
	}

	for _, name := range []string{"risk_score", "trust_score", "confidence", "samples", "age_seconds", "source_diversity", "value", "subject_tag"} {
		if fields[name] {
			t.Fatal("missing assessment invented details or exposed a raw subject")
		}
	}
}

// TestAssessmentUnavailableIgnoresReadyActiveHistoryWhenPreviousReadFails checks the complete rotation dependency contract.
func TestAssessmentUnavailableIgnoresReadyActiveHistoryWhenPreviousReadFails(t *testing.T) {
	active := assessmentTuple{State: assessmentFresh, Profile: profileOperational, Band: bandTrusted, Override: overrideNone,
		Details: &assessmentDetails{Trust: 0.9, Confidence: 0.9, Samples: 100, Diversity: 2}}

	merged := mergeAssessments(active, emptyAssessment(assessmentUnavailable, profileOperational))
	if merged.State != assessmentUnavailable || merged.Details != nil {
		t.Fatal("partial rotation history granted trust")
	}
}

// TestAssessmentCorrelationCannotOverwriteClosedTuple reserves all provider-owned tuple fields.
func TestAssessmentCorrelationCannotOverwriteClosedTuple(t *testing.T) {
	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: stringPointer(bandTrusted)})
	requireNoError(t, err)
	field, err := pluginapi.NewDecisionRecordFieldValue(value)
	requireNoError(t, err)

	subject := extractedSubject{subjectInput: subjectInput{role: "peer", kind: kindIP}, correlation: map[string]pluginapi.DecisionRecordFieldValue{"band": field}}
	_, err = assessmentRecord(subject, emptyAssessment(assessmentMissing, profileOperational))
	requireError(t, err)
}

// stringPointer creates an owned scalar for strict public value constructors.
func stringPointer(value string) *string { return &value }

// TestAssessmentProviderRegistersConfiguredNamespacesAndEmitsAllProfiles proves actual generic registry and callback integration.
func TestAssessmentProviderRegistersConfiguredNamespacesAndEmitsAllProfiles(t *testing.T) {
	raw := testConfigMap(t)
	raw["target_bindings"] = []any{
		testAssessmentBinding("authn/authenticate", "assessment", "auth_subjects"),
		testAssessmentBinding("workflow/submit", "workflow_assessment", "workflow_subjects"),
	}

	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: "reputation", Type: config.PluginModuleTypeGo, Path: "/plugins/reputation.so", Config: raw})
	plugin := NewPlugin()
	requireNoError(t, plugin.Register(registrar))
	requireNoError(t, registrar.Commit())
	assertAssessmentAuthnSchema(t, registry)

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{Principal: "worker", AuthenticationKind: "internal"})
	requireNoError(t, err)
	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: stringPointer("worker")})
	requireNoError(t, err)
	fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: "subject.worker", Category: pluginapi.DecisionFactCategorySubject, Value: value})
	requireNoError(t, err)

	expected := map[string]pluginapi.DecisionTargetSelector{
		"assessment":          {Namespace: "authn", Action: "authenticate"},
		"workflow_assessment": {Namespace: "workflow", Action: "submit"},
	}
	found := 0

	for _, component := range registry.DecisionFactProviders() {
		target, exists := expected[component.LocalName]
		if !exists {
			continue
		}

		found++
		request, err := pluginapi.NewDecisionFactRequest(target, caller, []pluginapi.DecisionFactView{fact})
		requireNoError(t, err)

		provider := component.Value.(pluginapi.DecisionFactProvider)
		result, err := provider.Collect(t.Context(), request)
		requireNoError(t, err)
		requireNoError(t, pluginapi.ValidateDecisionFactResult(provider.Descriptor(), result))

		if len(result.Facts) != 4 {
			t.Fatal("configured provider omitted profile views")
		}
	}

	if found != len(expected) {
		t.Fatal("configured namespace component not registered")
	}
}

// assertAssessmentAuthnSchema proves the actual registered reputation output extends builtin authentication safely.
func assertAssessmentAuthnSchema(t *testing.T, registered *pluginregistry.Registry) {
	t.Helper()

	owner, err := policyregistry.NewNamespaceOwnership("plugin.reputation", []string{"authn", "workflow", "reputation"})
	requireNoError(t, err)
	extension, err := pluginregistry.NewNativeDecisionContribution(registered, "reputation", owner)
	requireNoError(t, err)
	builtin, err := policyregistry.NewBuiltinTargetContributor().Contribute(t.Context())
	requireNoError(t, err)
	extended, err := policyregistry.ExtendBuiltinAuthnSchemas(builtin, extension)
	requireNoError(t, err)

	found := 0

	for _, schema := range extended.Schemas() {
		for _, fact := range schema.Facts() {
			if fact.ID() != "plugin.reputation.auth_subjects" {
				continue
			}

			records, present := fact.RecordSchema()
			if !present || len(records.Fields()) != 12 || records.MaxRecords() != maximumAssessmentSubjects {
				t.Fatal("authentication lost the complete bounded assessment tuple")
			}

			found++
		}
	}

	if found != 1 {
		t.Fatal("assessment output was absent or leaked into another authentication target")
	}
}
