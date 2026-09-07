package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"testing"
)

// TestNeutralTargetExtractorsCompileExactScalarAndCorrelatedRecords proves a non-mail capability.
func TestNeutralTargetExtractorsCompileExactScalarAndCorrelatedRecords(t *testing.T) {
	raw := testConfigMap(t)
	raw["target_bindings"] = []any{map[string]any{"target": "workflow/submit", "output_fact": "workflow_subjects", "subjects": []any{
		map[string]any{"attribute": "subject.worker", "role": "origin_service", "kind": "service"},
		map[string]any{"attribute": "resource.jobs", "field": "owner", "role": "account", "kind": "account", "correlation_fields": []any{"sequence"}, "correlation_types": map[string]any{"sequence": "integer"}},
	}}}
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)

	worker, owner := "WORKER", "CaseSensitive"
	sequence := int64(7)
	record, err := recordInputs([]outputInput{{name: "owner", input: pluginapi.DecisionValueInput{String: &owner}}, {name: "sequence", input: pluginapi.DecisionValueInput{Integer: &sequence}}})
	requireNoError(t, err)
	list, err := pluginapi.NewDecisionRecordList([]pluginapi.DecisionRecord{record})
	requireNoError(t, err)

	facts := []pluginapi.DecisionFactView{}

	for _, input := range []outputInput{{name: "subject.worker", input: pluginapi.DecisionValueInput{String: &worker}}, {name: "resource.jobs", input: pluginapi.DecisionValueInput{Records: &list}}} {
		value, err := pluginapi.NewDecisionValue(input.input)
		requireNoError(t, err)
		fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: input.name, Category: pluginapi.DecisionFactCategoryResource, Value: value})
		requireNoError(t, err)

		facts = append(facts, fact)
	}

	target := pluginapi.DecisionTargetSelector{Namespace: "workflow", Action: "submit"}
	subjects, err := cfg.extractSubjects(target, facts)
	requireNoError(t, err)

	if len(subjects) != 2 || subjects[0].value != "worker" || subjects[1].value != owner {
		t.Fatal("neutral extraction lost canonical subjects")
	}

	got, ok := subjects[1].correlation["sequence"].Value().Integer()
	if !ok || got != sequence {
		t.Fatal("correlated record identity lost")
	}

	_, err = cfg.extractSubjects(pluginapi.DecisionTargetSelector{Namespace: "workflow", Action: "other"}, facts)
	requireError(t, err)
}

// TestAssessmentBindingsRejectAmbiguousOutputsAndComponents keeps generated facts and module identities unambiguous.
func TestAssessmentBindingsRejectAmbiguousOutputsAndComponents(t *testing.T) {
	cases := []struct{ name, firstTarget, secondTarget, firstOutput, secondOutput string }{
		{"generated output collision", "workflow/submit", "workflow/read", "subjects", "subjects_fast"},
		{"component namespace collision", "authn/authenticate", "workflow/submit", "auth_subjects", "workflow_subjects"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			raw := testConfigMap(t)
			raw["target_bindings"] = []any{testAssessmentBinding(tt.firstTarget, "", tt.firstOutput), testAssessmentBinding(tt.secondTarget, "", tt.secondOutput)}
			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}
}

// testAssessmentBinding builds one neutral scalar fixture shared by extraction and actual registry tests.
func testAssessmentBinding(target, component, output string) map[string]any {
	return map[string]any{"target": target, "component": component, "output_fact": output,
		"subjects": []any{map[string]any{"attribute": "subject.worker", "role": "service", "kind": "service"}}}
}
