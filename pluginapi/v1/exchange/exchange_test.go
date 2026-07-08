// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package exchange

import (
	"reflect"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestRuntimeDeltaBuildersUseOnlyStandardKeys(t *testing.T) {
	leaked := true
	count := uint64(42)

	deltas := []pluginapi.RuntimeDelta{
		FeatureRuntimeDelta(FeatureGeoIPReputation, FeatureMarker{
			Triggered: true,
			Decision:  "suspicious",
			Source:    "redis",
		}),
		HIBPRuntimeDelta(HIBPResult{
			HashInfo: "ABCDE42",
			Leaked:   &leaked,
			Count:    &count,
		}),
		GeoIPRuntimeDelta(map[string]any{
			"matched":     true,
			"country_iso": "DE",
		}),
		GeoIPReputationRuntimeDelta(map[string]any{
			FieldDecision: "suspicious",
			FieldSource:   "redis",
		}),
	}

	for _, delta := range deltas {
		if len(delta.Set) != 1 {
			t.Fatalf("delta set = %#v, want one standard key", delta.Set)
		}

		for key := range delta.Set {
			if !strings.HasPrefix(key, Prefix) {
				t.Fatalf("delta key = %q, want prefix %q", key, Prefix)
			}

			if key == "rt" {
				t.Fatal("delta emitted forbidden legacy runtime key")
			}
		}
	}
}

func TestDecisionSourcesAreDeterministicAndDeduplicated(t *testing.T) {
	values := map[string]any{
		KeyDecisionSources: []any{"custom", FeatureBlocklist, FeatureBlocklist},
		FeatureKey(FeatureAccountProtection): map[string]any{
			FieldTriggered: true,
		},
		KeyFailedLoginHotspot: map[string]any{
			FieldTriggered: true,
		},
		KeyGeoIPReputation: map[string]any{
			FieldDecision: "suspicious",
			FieldSource:   "redis",
		},
	}
	facts := []pluginapi.PolicyFact{
		{Attribute: "lua.plugin.blocklist.matched", Value: true},
		{Attribute: "plugin.subject.account_protection.active", Value: true},
		{Attribute: "lua.plugin.geoip_reputation.decision", Value: "suspicious"},
	}

	got := NewSnapshotFromValues(values, facts).DecisionSources()
	want := []string{
		"custom",
		FeatureBlocklist,
		FeatureAccountProtection,
		FeatureFailedLoginHotspot,
		FeatureGeoIPReputation,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecisionSources() = %#v, want %#v", got, want)
	}
}

func TestDecisionSourcesIncludeGeoIPReputationFromStandardAndFacts(t *testing.T) {
	cases := []struct {
		values map[string]any
		facts  []pluginapi.PolicyFact
		name   string
	}{
		{
			name: "standard exchange value",
			values: map[string]any{
				KeyGeoIPReputation: map[string]any{
					FieldDecision: "suspicious",
				},
			},
		},
		{
			name: "lua policy fact",
			facts: []pluginapi.PolicyFact{
				{Attribute: "lua.plugin.geoip_reputation.decision", Value: "suspicious"},
			},
		},
		{
			name: "native policy fact",
			facts: []pluginapi.PolicyFact{
				{Attribute: "plugin.subject.geoip_reputation.decision", Value: "suspicious"},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := NewSnapshotFromValues(testCase.values, testCase.facts).DecisionSources()
			want := []string{FeatureGeoIPReputation}

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("DecisionSources() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestHIBPHashInfoReadsStandardMap(t *testing.T) {
	snapshot := NewSnapshotFromValues(map[string]any{
		KeyHaveIBeenPwned: HIBPValue(HIBPResult{HashInfo: "ABCDE42"}),
	}, nil)

	if got := snapshot.HIBPHashInfo(); got != "ABCDE42" {
		t.Fatalf("HIBPHashInfo() = %q, want ABCDE42", got)
	}
}
