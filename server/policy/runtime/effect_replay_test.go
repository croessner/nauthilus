package runtime

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestEffectReplayKeyRequiresAdmittedBoundedCallerFact rejects missing and unsafe replay-key schemas.
func TestEffectReplayKeyRequiresAdmittedBoundedCallerFact(t *testing.T) {
	for _, test := range []struct {
		name     string
		kind     decision.ValueKind
		source   decision.FactSource
		maximum  int
		required bool
		valid    bool
	}{
		{"bounded caller key", decision.ValueKindString, decision.FactSourceCaller, 128, true, true},
		{"unbounded", decision.ValueKindString, decision.FactSourceCaller, 0, true, false},
		{"optional", decision.ValueKindString, decision.FactSourceCaller, 128, false, false},
		{"provider owned", decision.ValueKindString, decision.FactSourcePlugin, 128, true, false},
		{"wrong kind", decision.ValueKindInteger, decision.FactSourceCaller, 0, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fact, err := registry.NewFactSchema(registry.FactSchemaInput{
				ID: "resource.workflow.event_id", Category: decision.FactCategoryResource,
				Kind: test.kind, AllowedSources: []decision.FactSource{test.source}, MaxLength: test.maximum, Required: test.required,
			})
			if err != nil {
				if test.valid {
					t.Fatal(err)
				}

				return
			}

			err = validateEffectReplayKey("resource.workflow.event_id", []registry.FactSchema{fact})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t, want %t: %v", err == nil, test.valid, err)
			}
		})
	}

	if err := validateEffectReplayKey("resource.workflow.event_id", nil); err == nil {
		t.Fatal("missing key schema was accepted")
	}
}
