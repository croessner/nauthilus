package main

import (
	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
	"testing"
)

// testGeoIPExample merges documented keyed fragment additions without duplicating the base operator contract.
func testGeoIPExample(t *testing.T) map[string]any {
	t.Helper()
	base := testYAMLMap(t, "../../../server/docs/examples/go_plugin_reputation.yml")
	addition := testYAMLMap(t, "../../../server/docs/examples/reputation_geoip_observation.yml")

	return testsupport.MergeExample(base, addition).(map[string]any)
}

// testGeoIPReputationConfig selects the exact merged reputation module configuration.
func testGeoIPReputationConfig(t *testing.T) map[string]any {
	t.Helper()

	raw := testGeoIPExample(t)
	for _, value := range raw["plugins"].(map[string]any)["modules"].([]any) {
		module := value.(map[string]any)
		if module["name"] == "reputation" {
			return module["config"].(map[string]any)
		}
	}

	t.Fatal("merged reputation module missing")

	return nil
}
