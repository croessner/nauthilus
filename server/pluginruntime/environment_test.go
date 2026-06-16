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

package pluginruntime

import (
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/pluginregistry"
)

const testRuntimeEnvironmentFact = "plugin.environment.geoip.matched"

func TestRunner_EnvironmentSourceReturnsFactsRuntimeDeltaAndObservations(t *testing.T) {
	observer := &recordingObserver{}
	result := pluginapi.EnvironmentResult{
		Facts: []pluginapi.PolicyFact{
			{Attribute: testRuntimeEnvironmentFact, Value: true},
		},
		RuntimeDelta: pluginapi.RuntimeDelta{
			Set: map[string]any{
				"plugin.environment.geoip": map[string]any{"matched": true},
			},
		},
	}
	runner := newTestRunner(
		t,
		&runtimePlugin{},
		func(registrar pluginapi.Registrar) error {
			return registrar.RegisterEnvironmentSource(runtimeAdapterEnvironmentSource{result: result})
		},
		WithObserver(observer),
	)

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	got, err := runner.EvaluateEnvironment(context.Background(), testRuntimeModuleName+".environment", pluginapi.EnvironmentRequest{})
	if err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	if err := ValidateRuntimeDelta(got.RuntimeDelta); err != nil {
		t.Fatalf("ValidateRuntimeDelta() error = %v", err)
	}

	if got.Facts[0].Attribute != testRuntimeEnvironmentFact || got.Facts[0].Value != true {
		t.Fatalf("facts = %#v, want matched fact", got.Facts)
	}

	if !observer.sawCall(testRuntimeEnvironment, string(pluginregistry.ComponentKindEnvironmentSource), "Evaluate") {
		t.Fatalf("observer records = %#v, want environment Evaluate call", observer.records)
	}
}

type runtimeAdapterEnvironmentSource struct {
	result pluginapi.EnvironmentResult
}

// Descriptor returns a stable test environment source descriptor.
func (s runtimeAdapterEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Name:        testRuntimeEnvironment,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

// Evaluate returns the configured environment result.
func (s runtimeAdapterEnvironmentSource) Evaluate(context.Context, pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error) {
	return s.result, nil
}
