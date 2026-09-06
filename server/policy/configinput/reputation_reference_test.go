package configinput

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"go.yaml.in/yaml/v3"
)

// TestReputationReferenceSchemaProtectsRawAndAdmittedSubjects checks the actual example through Policy compilation.
func TestReputationReferenceSchemaProtectsRawAndAdmittedSubjects(t *testing.T) {
	input := reputationReferenceInput(t)

	catalog, err := input.Compile(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	target, _ := decision.NewTarget("reputation", "observe")

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("observation target missing")
	}

	for _, fact := range compiled.Schema().Facts() {
		if fact.ID() != "resource.reputation.subjects" && fact.ID() != "plugin.reputation.admitted_subjects" {
			continue
		}

		records, ok := fact.RecordSchema()
		if !ok {
			t.Fatal("protected collection has no closed record schema")
		}

		for _, field := range records.Fields() {
			if field.ExpressionVisible() || field.VisibleToProvider("reputation/plugin.other.audit") {
				t.Fatal("protected field crosses authority boundary")
			}

			if fact.ID() == "plugin.reputation.admitted_subjects" && !field.VisibleToProvider("reputation/plugin.reputation.storage") {
				t.Fatal("selected storage owner cannot read admitted plan")
			}
		}
	}
}

// reputationReferenceInput normalizes only the Policy section of the shared operator example.
func reputationReferenceInput(t *testing.T) UnifiedPolicyInput {
	t.Helper()

	content, err := os.ReadFile("../../docs/examples/go_plugin_reputation.yml")
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(content, &raw); err != nil {
		t.Fatal(err)
	}

	policy, err := yaml.Marshal(map[string]any{"policy": raw["policy"]})
	if err != nil {
		t.Fatal(err)
	}

	document, err := policyconfig.Decode("yaml", bytes.NewReader(policy))
	if err != nil {
		t.Fatal(err)
	}

	input, err := Normalize(context.Background(), document)
	if err != nil {
		t.Fatal(err)
	}

	return input
}
