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

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

const (
	environmentCheckConfigRef  = pluginEnvironmentConfigRefPrefix + testRuntimeModuleName + ".environment"
	environmentCheckName       = "plugin_environment_geoip"
	environmentLogKey          = "geoip_marker"
	environmentLogValue        = "native"
	environmentRuntimeKey      = "plugin.environment.geoip"
	environmentRuntimeMatched  = "matched"
	environmentStatusText      = "native environment ok"
	testRuntimeEnvironmentFact = "plugin.environment.geoip.matched"
)

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

func TestEnvironmentSourceBridgeAppliesRuntimeFactsAndObservations(t *testing.T) {
	result := pluginapi.EnvironmentResult{
		Status: &pluginapi.StatusMessage{
			DefaultText: environmentStatusText,
		},
		Logs: []pluginapi.LogField{{Key: environmentLogKey, Value: environmentLogValue}},
		Facts: []pluginapi.PolicyFact{
			{Attribute: testRuntimeEnvironmentFact, Value: true},
		},
		RuntimeDelta: pluginapi.RuntimeDelta{
			Set: map[string]any{
				environmentRuntimeKey: map[string]any{environmentRuntimeMatched: true},
			},
		},
		Triggered: true,
	}
	bridge := newEnvironmentTestBridge(t, runtimeAdapterEnvironmentSource{result: result})
	auth := newSubjectTestAuth(t)
	activateEnvironmentPolicySnapshot(t, testRuntimeEnvironmentFact)

	triggered, abort, handled, err := bridge.Evaluate(auth.Request.HTTPClientContext, auth.View())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !handled || !triggered || abort {
		t.Fatalf("Evaluate() handled=%t triggered=%t abort=%t, want handled triggered without abort", handled, triggered, abort)
	}

	assertEnvironmentRuntime(t, auth)
	assertEnvironmentPolicyReport(t, auth)
}

func TestEnvironmentSourceBridgeAppliesGeoIPPrivacyPolicyFactsWithoutTriggering(t *testing.T) {
	facts := []pluginapi.PolicyFact{
		{Attribute: "plugin.environment.geoip.is_tor_exit_node", Value: true},
		{Attribute: "plugin.environment.geoip.is_known_vpn_exit", Value: false},
		{Attribute: "plugin.environment.geoip.is_public_proxy", Value: true},
		{Attribute: "plugin.environment.geoip.privacy_data_stale", Value: false},
		{Attribute: "plugin.environment.geoip.is_hosting_network", Value: true},
		{Attribute: "plugin.environment.geoip.is_shared_egress", Value: true},
	}
	attributes := make([]string, 0, len(facts))

	for _, fact := range facts {
		attributes = append(attributes, fact.Attribute)
	}

	bridge := newEnvironmentTestBridge(t, runtimeAdapterEnvironmentSource{result: pluginapi.EnvironmentResult{Facts: facts}})
	auth := newSubjectTestAuth(t)
	activateEnvironmentPolicySnapshot(t, attributes...)

	triggered, abort, handled, err := bridge.Evaluate(auth.Request.HTTPClientContext, auth.View())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !handled || triggered || abort {
		t.Fatalf("Evaluate() handled=%t triggered=%t abort=%t, want handled evidence only", handled, triggered, abort)
	}

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	for _, fact := range facts {
		if got := report.Attributes[fact.Attribute].Value; got != fact.Value {
			t.Fatalf("policy fact %s = %#v, want %#v", fact.Attribute, got, fact.Value)
		}
	}
}

func newEnvironmentTestBridge(t *testing.T, sources ...pluginapi.EnvironmentSource) *EnvironmentSourceBridge {
	t.Helper()

	runner := newStartedTestRunnerWithModule(t, &runtimePlugin{}, initialRuntimeModule(nil), func(registrar pluginapi.Registrar) error {
		for _, source := range sources {
			if err := registrar.RegisterEnvironmentSource(source); err != nil {
				return err
			}
		}

		return nil
	})

	return NewEnvironmentSourceBridge(runner)
}

func assertEnvironmentRuntime(t *testing.T, auth *core.AuthState) {
	t.Helper()

	value := auth.Runtime.Context.Get(environmentRuntimeKey)
	runtimeValues, ok := value.(map[string]any)

	if !ok || runtimeValues[environmentRuntimeMatched] != true {
		t.Fatalf("runtime value = %#v, want matched GeoIP runtime map", value)
	}

	if auth.Runtime.StatusMessage != environmentStatusText {
		t.Fatalf("status = %q, want plugin environment status", auth.Runtime.StatusMessage)
	}

	for index := 0; index+1 < len(auth.Runtime.AdditionalLogs); index += 2 {
		if auth.Runtime.AdditionalLogs[index] == environmentLogKey && auth.Runtime.AdditionalLogs[index+1] == environmentLogValue {
			return
		}
	}

	t.Fatalf("additional logs = %#v, want plugin environment log field", auth.Runtime.AdditionalLogs)
}

func assertEnvironmentPolicyReport(t *testing.T, auth *core.AuthState) {
	t.Helper()

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	if value := report.Attributes[testRuntimeEnvironmentFact].Value; value != true {
		t.Fatalf("policy fact = %#v, want true", value)
	}

	check := report.Checks[environmentCheckName]
	if check.Type != policy.CheckTypePluginEnvironment || !check.Matched {
		t.Fatalf("environment check = %#v, want matched plugin environment check", check)
	}
}

func activateEnvironmentPolicySnapshot(t *testing.T, attributes ...string) {
	t.Helper()

	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StagePreAuth,
		category:      policyregistry.AttributeCategoryEnvironment,
		attributeType: policyregistry.AttributeTypeBool,
		checkName:     environmentCheckName,
		checkType:     policy.CheckTypePluginEnvironment,
		configRef:     environmentCheckConfigRef,
	}, attributes...)
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
