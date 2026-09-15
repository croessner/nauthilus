//go:build reputation_integration

package main

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

type learningTestCounter struct {
	results []string
	mu      sync.Mutex
}

// bindLearningTestCounter preserves the production allowlist around a deterministic integration sink.
func bindLearningTestCounter(t *testing.T, plugin *Plugin, counter *learningTestCounter) {
	t.Helper()

	wrapped, err := telemetry.BindCounter(counter, learningMetricDimensions())
	requireNoError(t, err)
	plugin.mu.Lock()
	plugin.learningCounter = wrapped
	plugin.mu.Unlock()
}

// Add retains only bounded outcomes for deterministic callback assertions.
func (c *learningTestCounter) Add(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	registrar := registry.NewRegistrar(config.PluginModule{Name: pluginName, Type: config.PluginModuleTypeGo, Path: "/plugins/reputation.so", Config: asyncLearningIntegrationConfig(t)})
	plugin := NewPlugin()
	requireNoError(t, plugin.Register(registrar))
	requireNoError(t, registrar.Commit())
	host := pluginruntime.NewHost(pluginruntime.WithConfig(pluginregistry.NewConfigView(testAdmissionMap())), pluginruntime.WithOpaqueIdentifierTagger(manifestTestTagger(t, false)), pluginruntime.WithRedis(facade))
	requireNoError(t, plugin.Start(t.Context(), host))

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		requireNoError(t, plugin.Stop(ctx))
	})

	terminal := make(chan string, 16)
	plugin.learningQueue.process = func(ctx context.Context, job learningJob) string {
		result := plugin.state.learnAuthentication(ctx, job)
		if result != learningUnavailable && result != learningPartial {
			terminal <- result
		}

		return result
	}
	learner := registry.ObligationTargets()[0].Value.(pluginapi.ObligationTarget)

	subject := subjectInput{role: "auth_client", kind: kindIP, value: "192.0.2.7"}
	if before := plugin.state.assess(t.Context(), subject, profileOperational); before.State != assessmentMissing {
		t.Fatal("current event present before selected obligation")
	}

	identity, err := pluginapi.NewExecutionIdentityView(pluginName, componentLearnOutcome, "obligation", "execute", authenticationTarget)
	requireNoError(t, err)
	request, err := pluginapi.NewObligationRequest(pluginapi.ObligationRequest{Snapshot: pluginapi.RequestSnapshot{ClientIP: subject.value}}, identity)
	requireNoError(t, err)
	assertUnobservedAuthLearning(t, plugin, learner, request, subject)

	request.BackendOutcome, err = pluginapi.NewBackendOutcomeView("backend-success", "verified-account", pluginapi.BackendOutcomeAuthenticated, time.Now())
	requireNoError(t, err)

	for _, expected := range []string{storageApplied, storageDuplicate} {
		result, err := learner.Execute(t.Context(), request)
		requireNoError(t, err)

		if result.Applied || result.Temporary {
			t.Fatal("local capture claimed durable delivery or vetoed authentication")
		}

		awaitLearningResult(t, terminal, expected)
	}

	assessment := plugin.state.assess(t.Context(), subject, profileOperational)
	if assessment.State != assessmentFresh || assessment.Details.Trust <= 0 || assessment.Details.Risk != 0 {
		t.Fatal("final denied flag replaced successful backend evidence")
	}

	plugin.state.journal = unavailableJournalRuntime(t)

	result, deliveryErr := learner.Execute(t.Context(), request)
	if deliveryErr != nil || result.Temporary || result.Applied {
		t.Fatal("Kafka outage vetoed authentication or claimed delivery")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	requireNoError(t, plugin.learningQueue.stop(ctx))

	plugin.state.journal = nil

	plugin.state.redis = interruptRedis(facade, scriptManifest, false, 1)
	if metric := plugin.state.learnAuthentication(t.Context(), learningJobFromRequest(t, plugin.state.config, request)); metric != learningUnavailable {
		t.Fatal("background Redis failure was not observable")
	}
}

// assertUnobservedAuthLearning proves that a pre-backend denial cannot modify independent evidence.
func assertUnobservedAuthLearning(t *testing.T, plugin *Plugin, learner pluginapi.ObligationTarget, request pluginapi.ObligationRequest, subject subjectInput) {
	t.Helper()
	skipped, err := learner.Execute(t.Context(), request)
	requireNoError(t, err)

	if skipped.Applied {
		t.Fatal("pre-backend denial learned bad credentials")
	}

	if after := plugin.state.assess(t.Context(), subject, profileOperational); after.State != assessmentMissing {
		t.Fatal("skipped callback wrote evidence")
	}
}

// assertLearningResults shares bounded observability assertions across native authentication and both external transports.
func assertLearningResults(t *testing.T, counter *learningTestCounter, expected ...string) {
	t.Helper()

	counter.mu.Lock()
	defer counter.mu.Unlock()

	if !slices.Equal(counter.results, expected) {
		t.Fatalf("learning outcomes: %v, expected %v", counter.results, expected)
	}
}

// asyncLearningIntegrationConfig bounds outage retries in the real Redis test without changing source semantics.
func asyncLearningIntegrationConfig(t *testing.T) map[string]any {
	raw := learningConfigMap(t)
	raw["auth_learning_queue"] = map[string]any{"capacity": 16, "max_age": "800ms", "timeout": "500ms"}

	return raw
}

// learningJobFromRequest reuses the production projection for direct storage failure verification.
func learningJobFromRequest(t *testing.T, cfg *configuration, request pluginapi.ObligationRequest) learningJob {
	t.Helper()

	source, input, err := cfg.authenticationObservation(request)
	requireNoError(t, err)

	return learningJob{source: source, input: input}
}
