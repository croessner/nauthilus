package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"net/netip"
	"testing"
)

// TestPeerGeographicEvidenceRequiresExactAddressAndExplicitAvailability rejects forged or partial enrichment.
func TestPeerGeographicEvidenceRequiresExactAddressAndExplicitAvailability(t *testing.T) {
	for _, tc := range []struct {
		state, ip string
		age, asn  int64
		valid     bool
	}{
		{"fresh", "192.0.2.1", 1, 64500, true}, {"stale", "192.0.2.1", 86400, 64500, true},
		{"not_found", "192.0.2.1", 0, 0, true}, {"unavailable", "192.0.2.1", 0, 0, true},
		{"fresh", "192.0.2.2", 1, 64500, false}, {"fresh", "192.0.2.1", -1, 64500, false},
		{"unknown", "192.0.2.1", 1, 64500, false}, {"not_found", "192.0.2.1", 0, 64500, false},
	} {
		values := map[string]pluginapi.DecisionValue{}
		values["lookup_state"] = testValue(t, pluginapi.DecisionValueInput{String: &tc.state})
		values["ip"] = testValue(t, pluginapi.DecisionValueInput{String: &tc.ip})

		values["data_age_seconds"] = testValue(t, pluginapi.DecisionValueInput{Integer: &tc.age})
		if tc.asn != 0 {
			values["asn"] = testValue(t, pluginapi.DecisionValueInput{Integer: &tc.asn})
		}

		_, err := decodeGeographic(values, netip.MustParseAddr("192.0.2.1"))
		if (err == nil) != tc.valid {
			t.Fatalf("%+v error=%v", tc, err)
		}
	}
}

// testValue constructs a strict immutable scalar for composition tests.
func testValue(t *testing.T, input pluginapi.DecisionValueInput) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(input)
	if err != nil {
		t.Fatal(err)
	}

	return value
}
