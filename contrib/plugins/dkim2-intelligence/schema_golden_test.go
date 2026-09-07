package main

import (
	"encoding/json"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"strings"
	"testing"
)

type goldenSchema struct {
	MinRecords int           `json:"min_records"`
	MaxRecords int           `json:"max_records"`
	MaxFields  int           `json:"max_fields"`
	MaxBytes   int           `json:"max_aggregate_bytes"`
	Fields     []goldenField `json:"fields"`
}

type goldenField struct {
	Name      string   `json:"name"`
	Kind      string   `json:"type"`
	MaxLength int      `json:"max_length"`
	MaxItems  int      `json:"max_items"`
	MaxBytes  int      `json:"max_bytes"`
	Required  bool     `json:"required"`
	Visible   bool     `json:"expression_visible"`
	Providers []string `json:"provider_visibility"`
}

// TestNormativeRecordSchemasMatchGoldenFieldTables compares code and executable example with independently transcribed spec tables.
func TestNormativeRecordSchemasMatchGoldenFieldTables(t *testing.T) {
	golden := loadGoldenSchemas(t)
	for _, tc := range []struct {
		name                 string
		fields               []fieldSpec
		maxRecords, maxBytes int
	}{{"assessed_chain", chainFields(), 128, 262144}, {"smtp_peer", peerFields(), 1, 8192}} {
		expected := golden[tc.name]
		if expected.MinRecords != 1 || expected.MaxRecords != tc.maxRecords || expected.MaxBytes != tc.maxBytes || expected.MaxFields != len(tc.fields) {
			t.Fatal("record bound drift")
		}

		compareGoldenFields(t, tc.fields, expected.Fields)
	}

	compareExecutableSchemas(t, golden)
}

// loadGoldenSchemas reads the independent normative field table transcription.
func loadGoldenSchemas(t *testing.T) map[string]goldenSchema {
	t.Helper()

	data, err := os.ReadFile("testdata/record-contract.json")
	if err != nil {
		t.Fatal(err)
	}

	var golden map[string]goldenSchema
	if err = json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}

	return golden
}

// compareGoldenFields compares every bound and visibility field independently of declaration order.
func compareGoldenFields(t *testing.T, fields []fieldSpec, expected []goldenField) {
	t.Helper()

	got, want := make(map[string]goldenField), make(map[string]goldenField)

	for _, field := range fields {
		item := goldenField{Name: field.Name, Kind: string(field.Kind), MaxLength: field.MaxLength, MaxItems: field.MaxItems, MaxBytes: field.MaxBytes, Required: field.Required, Visible: !field.ProviderOnly}
		if field.ProviderOnly {
			item.Providers = []string{"dkim2/plugin.dkim2_intelligence.assessment"}
		}

		got[field.Name] = item
	}

	for _, field := range expected {
		want[field.Name] = field
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normative field metadata drift: got %#v want %#v", got, want)
	}
}

// compareExecutableSchemas checks the operator example's actual record schemas against the same normative fixture.
func compareExecutableSchemas(t *testing.T, golden map[string]goldenSchema) {
	t.Helper()

	raw, err := os.ReadFile("../../../server/docs/examples/policy_dkim2_rspamd_verifier.yml")
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err = yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	facts := document["policy"].(map[string]any)["namespaces"].(map[string]any)["dkim2"].(map[string]any)["schema_contributions"].(map[string]any)["static"].(map[string]any)["accept-message-instance"].(map[string]any)["versions"].(map[string]any)["v1"].(map[string]any)["facts"].([]any)
	matched := 0

	for _, item := range facts {
		fact := item.(map[string]any)
		if !strings.HasPrefix(fact["attribute"].(string), "plugin.dkim2_intelligence.") {
			continue
		}

		schema, present := fact["record_schema"]
		if !present {
			continue
		}

		encoded, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}

		var actual goldenSchema
		if err = json.Unmarshal(encoded, &actual); err != nil {
			t.Fatal(err)
		}

		name := strings.TrimPrefix(fact["attribute"].(string), "plugin.dkim2_intelligence.")
		if !reflect.DeepEqual(golden[name], actual) {
			t.Fatalf("executable schema differs for %s", name)
		}

		matched++
	}

	if matched != len(golden) {
		t.Fatal("missing executable composition schema")
	}
}

// TestClosedEnumBranchesAndFieldBounds rejects unknown values instead of silently widening the schema.
func TestClosedEnumBranchesAndFieldBounds(t *testing.T) {
	for _, field := range append(chainFields(), peerFields()...) {
		if field.Kind == pluginapi.DecisionValueKindString {
			for _, text := range field.Values {
				if _, err := validateField(testValue(t, pluginapi.DecisionValueInput{String: &text}), field); err != nil {
					t.Fatalf("declared %s enum %s rejected", field.Name, text)
				}
			}

			oversized := strings.Repeat("x", field.MaxLength+1)
			if _, err := validateField(testValue(t, pluginapi.DecisionValueInput{String: &oversized}), field); err == nil {
				t.Fatalf("unbounded %s", field.Name)
			}

			if len(field.Values) > 0 {
				unknown := "unknown_value"
				if _, err := validateField(testValue(t, pluginapi.DecisionValueInput{String: &unknown}), field); err == nil {
					t.Fatalf("unknown %s enum accepted", field.Name)
				}
			}
		}
	}
}
