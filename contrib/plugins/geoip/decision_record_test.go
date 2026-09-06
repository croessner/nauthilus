// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"strings"
	"testing"
)

func TestDecisionBindingCorrelatesOnlyAdmittedIPRecords(t *testing.T) {
	module, _ := testGeoIPObservationExample(t)
	registry, plugin := registerTestPlugin(t, module)

	runner := newRunnerForPlugin(registry, plugin, module, newRecordingMetrics(), &recordingTracer{})
	if err := runner.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer stopRunner(t, runner)

	provider := registry.DecisionFactProviders()[0].Value.(pluginapi.DecisionFactProvider)
	value := testGeoIPRecordValue(t, []map[string]string{
		{"kind": "ip", "role": "smtp_peer", "value": testClientIP},
		{"kind": "asn", "role": "smtp_peer", "value": "12345"},
		{"kind": "network", "role": "smtp_peer", "value": "0.0.0.0/0"},
	})
	fact := decisionFactView(t, "resource.reputation.subjects", pluginapi.DecisionFactCategoryResource, value)

	result, err := provider.Collect(t.Context(), newDecisionFactRequest(t, pluginapi.DecisionTargetSelector{Namespace: "reputation", Action: "observe"}, []pluginapi.DecisionFactView{*fact}))
	if err != nil {
		t.Fatal(err)
	}

	if result.ErrorClass != "" || len(result.Facts) != 1 {
		t.Fatalf("record lookup failed: %v", result.ErrorClass)
	}

	records, ok := result.Facts[0].Value.Records()
	if !ok || len(records.Records()) != 1 {
		t.Fatal("non-IP caller subjects contributed geographic records")
	}

	for _, expected := range []struct{ name, value string }{{"ip", testClientIP}, {"role", "smtp_peer"}} {
		found := false

		for _, field := range records.Records()[0].Fields() {
			if field.Name() != expected.name {
				continue
			}

			actual, _ := field.Value().Value().StringValue()
			found = actual == expected.value
		}

		if !found {
			t.Fatalf("wrong or missing correlation %s", expected.name)
		}
	}
}

// testGeoIPRecordValue creates typed caller records through the public constructors.
func testGeoIPRecordValue(t *testing.T, input []map[string]string) pluginapi.DecisionValue {
	t.Helper()

	records := make([]pluginapi.DecisionRecord, 0, len(input))
	for _, row := range input {
		fields := make([]pluginapi.DecisionRecordField, 0, len(row))
		for name, text := range row {
			value, err := pluginapi.NewDecisionRecordFieldValue(decisionStringValue(t, text))
			if err != nil {
				t.Fatal(err)
			}

			field, err := pluginapi.NewDecisionRecordField(name, value)
			if err != nil {
				t.Fatal(err)
			}

			fields = append(fields, field)
		}

		record, err := pluginapi.NewDecisionRecord(fields)
		if err != nil {
			t.Fatal(err)
		}

		records = append(records, record)
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatal(err)
	}

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
	if err != nil {
		t.Fatal(err)
	}

	return value
}

// testGeoIPObservationExample loads the actual operator fragment and substitutes only local fixture database paths.
func testGeoIPObservationExample(t *testing.T) (config.PluginModule, map[string]any) {
	t.Helper()

	raw, err := policyconfig.DecodeSettings("yaml", strings.NewReader(readPolicyExample(t, "reputation_geoip_observation.yml")))
	if err != nil {
		t.Fatal(err)
	}

	module := testModule(testDatabasePath(t, "geoip.json"))
	module.Config = raw["plugins"].(map[string]any)["modules"].([]any)[0].(map[string]any)["config"].(map[string]any)
	module.Config["database_path"] = testDatabasePath(t, "geoip.json")
	module.Config["asn_database_path"] = testDatabasePath(t, "geoip.json")

	return module, raw
}

func TestDecisionBindingRecordExampleOwnsClosedOutputVocabulary(t *testing.T) {
	_, raw := testGeoIPObservationExample(t)
	namespace := raw["policy"].(map[string]any)["namespaces"].(map[string]any)["reputation"].(map[string]any)
	facts := namespace["schema_contributions"].(map[string]any)["static"].(map[string]any)["observe"].(map[string]any)["versions"].(map[string]any)["v1"].(map[string]any)["facts"].([]any)
	declared := make(map[string]string)

	for _, value := range facts {
		fact := value.(map[string]any)
		if fact["attribute"] != "plugin.geoip.observations" {
			continue
		}

		for _, value := range fact["record_schema"].(map[string]any)["fields"].([]any) {
			field := value.(map[string]any)
			declared[field["name"].(string)] = field["type"].(string)
		}
	}

	if len(declared) != len(geoIPDecisionOutputSpecifications())+1 {
		t.Fatal("record example has an incompatible closed field set")
	}

	for _, output := range geoIPDecisionOutputSpecifications() {
		if declared[output.name] != string(output.kind) {
			t.Errorf("record field %s kind mismatches actual provider", output.name)
		}
	}

	if declared["role"] != "string" {
		t.Fatal("record example loses role correlation")
	}
}
