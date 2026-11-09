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

package core

import (
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
)

// TestTriggeredBuiltinControlsPublishDecisionSources pins that a triggered RBL threshold or brute-force bucket
// publishes the standard exchange feature marker, so native analytics plugins report it in decision_sources.
func TestTriggeredBuiltinControlsPublishDecisionSources(t *testing.T) {
	tests := []struct {
		name     string
		controls []string
		want     []string
	}{
		{name: "rbl", controls: []string{definitions.ControlRBL}, want: []string{exchange.FeatureRBL}},
		{name: "brute force", controls: []string{definitions.ControlBruteForce}, want: []string{exchange.FeatureBruteForce}},
		{name: "both in exchange order", controls: []string{definitions.ControlBruteForce, definitions.ControlRBL},
			want: []string{exchange.FeatureRBL, exchange.FeatureBruteForce}},
		{name: "other controls publish no source", controls: []string{definitions.ControlTLSEncryption, definitions.ControlRelayDomains}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &AuthState{}
			auth.Runtime.Context = lualib.NewContext()

			for _, control := range test.controls {
				auth.updateLuaContext(control)
			}

			got := exchange.NewSnapshotFromValues(auth.Runtime.Context.Snapshot(), nil).DecisionSources()
			if !slices.Equal(got, test.want) {
				t.Fatalf("decision sources = %#v, want %#v", got, test.want)
			}
		})
	}
}
