package main

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	serverconfig "github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// TestAuthLearningUnavailableDoesNotVetoAuthentication keeps learning availability out of the decision path.
func TestAuthLearningUnavailableDoesNotVetoAuthentication(t *testing.T) {
	learner := authenticationLearner{plugin: NewPlugin()}

	result, err := learner.Execute(t.Context(), pluginapi.ObligationRequest{})
	if err != nil || result.Temporary || result.Applied {
		t.Fatalf("unavailable learning changed authentication: result=%+v error=%v", result, err)
	}
}

// TestAuthLearningHasNoSynchronousAdmissionGate prevents worker pressure from rejecting a login before capture.
func TestAuthLearningHasNoSynchronousAdmissionGate(t *testing.T) {
	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)

	registrar := pluginregistry.NewRegistry().NewRegistrar(serverconfig.PluginModule{Name: pluginName})
	p := NewPlugin()
	requireNoError(t, p.registerAuthentication(registrar, cfg))

	components := registrar.Components()
	if len(components) != 1 || components[0].CallbackAdmissionLimits != (pluginapi.CallbackAdmissionLimits{}) {
		t.Fatal("background learning still rejects authentication at the host admission gate")
	}
}
