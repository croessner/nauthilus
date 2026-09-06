//go:build reputation_integration

package main

import (
	"context"
	"slices"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

type learningTestCounter struct{ results []string }

// Add retains only bounded outcomes for deterministic callback assertions.
func (c *learningTestCounter) Add(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	for _, label := range labels {
		if label.Name == "result" {
			c.results = append(c.results, label.Value)
		}
	}
}

// TestReputationRedisAuthLearningUsesRegisteredBackendTruth proves pre-event reads, skipped denials and harmless retries.
func TestReputationRedisAuthLearningUsesRegisteredBackendTruth(t *testing.T) {
	_, facade := localReputationRedis(t)
	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: pluginName, Type: config.PluginModuleTypeGo, Path: "/plugins/reputation.so", Config: learningConfigMap(t)})
	plugin := NewPlugin()
	requireNoError(t, plugin.Register(registrar))
	requireNoError(t, registrar.Commit())
	host := pluginruntime.NewHost(pluginruntime.WithConfig(pluginregistry.NewConfigView(testAdmissionMap())), pluginruntime.WithOpaqueIdentifierTagger(manifestTestTagger(t, false)), pluginruntime.WithRedis(facade))
	requireNoError(t, plugin.Start(t.Context(), host))

	counter := &learningTestCounter{}
	plugin.learningCounter = counter
	learner := registry.PostActionTargets()[0].Value.(pluginapi.PostActionTarget)

	subject := subjectInput{role: "auth_client", kind: kindIP, value: "192.0.2.7"}
	if before := plugin.state.assess(t.Context(), subject, profileOperational); before.State != assessmentMissing {
		t.Fatal("current event present before selected post-action")
	}

	identity, err := pluginapi.NewExecutionIdentityView(pluginName, componentLearnOutcome, "post_action", "enqueue", authenticationTarget)
	requireNoError(t, err)
	request, err := pluginapi.NewPostActionRequest(pluginapi.PostActionRequest{Snapshot: pluginapi.RequestSnapshot{ClientIP: subject.value}}, identity)
	requireNoError(t, err)
	assertUnobservedAuthLearning(t, plugin, learner, request, subject)

	request.BackendOutcome, err = pluginapi.NewBackendOutcomeView("backend-success", "verified-account", pluginapi.BackendOutcomeAuthenticated, time.Now())
	requireNoError(t, err)

	for range 2 {
		result, err := learner.Enqueue(t.Context(), request)
		requireNoError(t, err)

		if !result.Enqueued || result.Temporary {
			t.Fatal("selected backend evidence not acknowledged")
		}
	}

	assessment := plugin.state.assess(t.Context(), subject, profileOperational)
	if assessment.State != assessmentFresh || assessment.Details.Trust <= 0 || assessment.Details.Risk != 0 {
		t.Fatal("final denied flag replaced successful backend evidence")
	}

	assertLearningResults(t, counter, learningSkipped, "applied", "duplicate")

	plugin.state.redis = interruptRedis(facade, scriptManifest, false, 1)

	failed, err := learner.Enqueue(t.Context(), request)
	if err == nil || !failed.Temporary {
		t.Fatal("learning outage was hidden")
	}
}

// assertUnobservedAuthLearning proves that a pre-backend denial cannot modify independent evidence.
func assertUnobservedAuthLearning(t *testing.T, plugin *Plugin, learner pluginapi.PostActionTarget, request pluginapi.PostActionRequest, subject subjectInput) {
	t.Helper()
	skipped, err := learner.Enqueue(t.Context(), request)
	requireNoError(t, err)

	if skipped.Enqueued {
		t.Fatal("pre-backend denial learned bad credentials")
	}

	if after := plugin.state.assess(t.Context(), subject, profileOperational); after.State != assessmentMissing {
		t.Fatal("skipped callback wrote evidence")
	}
}

// assertLearningResults shares bounded observability assertions across native authentication and both external transports.
func assertLearningResults(t *testing.T, counter *learningTestCounter, expected ...string) {
	t.Helper()

	if !slices.Equal(counter.results, expected) {
		t.Fatalf("learning outcomes: %v, expected %v", counter.results, expected)
	}
}
