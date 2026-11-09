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

package main

import (
	"maps"
	"testing"

	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
)

// builtinFeatureMarkers returns the runtime values the host publishes for triggered built-in controls.
func builtinFeatureMarkers(features ...string) map[string]any {
	values := make(map[string]any, len(features))
	for _, feature := range features {
		maps.Copy(values, exchange.FeatureRuntimeDelta(feature, exchange.FeatureMarker{Triggered: true, Source: "builtin"}).Set)
	}

	return values
}

// TestDecisionSourcesIncludeBuiltinRBLAndBruteForce pins that host-published RBL and brute-force markers reach the
// decision_sources column in the standard exchange order.
func TestDecisionSourcesIncludeBuiltinRBLAndBruteForce(t *testing.T) {
	tests := []struct {
		runtimeValues map[string]any
		name          string
		want          string
	}{
		{name: "rbl", runtimeValues: builtinFeatureMarkers(exchange.FeatureRBL), want: "rbl"},
		{name: "brute force", runtimeValues: builtinFeatureMarkers(exchange.FeatureBruteForce), want: "brute_force"},
		{name: "both after blocklist", runtimeValues: func() map[string]any {
			values := builtinFeatureMarkers(exchange.FeatureBruteForce, exchange.FeatureRBL)
			values[exchange.KeyDecisionSources] = []any{exchange.FeatureBlocklist}

			return values
		}(), want: "blocklist,rbl,brute_force"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := singleRowForRequest(t, requestOptions{runtimeValues: test.runtimeValues})
			assertStringField(t, row, "decision_sources", test.want)
		})
	}
}
