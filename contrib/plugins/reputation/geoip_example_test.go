package main

import "testing"

// testGeoIPExample merges documented keyed fragment additions without duplicating the base operator contract.
func testGeoIPExample(t *testing.T) map[string]any {
	t.Helper()
	base := testYAMLMap(t, "../../../server/docs/examples/go_plugin_reputation.yml")
	addition := testYAMLMap(t, "../../../server/docs/examples/reputation_geoip_observation.yml")

	return mergeGeoIPExample(base, addition).(map[string]any)
}

// mergeGeoIPExample implements the documented test-fixture merge by map key and exact module/fact/field identity.
func mergeGeoIPExample(base, addition any) any {
	if incoming, ok := addition.(map[string]any); ok {
		target, compatible := base.(map[string]any)
		if !compatible {
			target = make(map[string]any)
		}

		for key, value := range incoming {
			target[key] = mergeGeoIPExample(target[key], value)
		}

		return target
	}

	incoming, list := addition.([]any)

	target, compatible := base.([]any)
	if !list || !compatible {
		return addition
	}

	for _, item := range incoming {
		identity := geoIPExampleIdentity(item)
		if identity == "" {
			return addition
		}

		found := false

		for index, old := range target {
			if geoIPExampleIdentity(old) == identity {
				target[index] = mergeGeoIPExample(old, item)
				found = true

				break
			}
		}

		if !found {
			target = append(target, item)
		}
	}

	return target
}

// geoIPExampleIdentity recognizes only documented keyed collections and leaves scalar arrays as replacements.
func geoIPExampleIdentity(value any) string {
	record, ok := value.(map[string]any)
	if !ok {
		return ""
	}

	for _, field := range []string{"name", "attribute"} {
		if text, ok := record[field].(string); ok {
			return field + ":" + text
		}
	}

	return ""
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
