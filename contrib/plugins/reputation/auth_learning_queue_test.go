package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// testLearningQueue supplies isolated capacity with bounded test shutdown and observable terminal results.
func testLearningQueue(t *testing.T, workers, capacity int, process func(context.Context, learningJob) string) (*authenticationLearningQueue, <-chan string) {
	t.Helper()

	results := make(chan string, capacity+workers+8)

	q := newAuthenticationLearningQueue(learningQueueSettings{capacity: capacity, maxAge: time.Minute, timeout: time.Second},
		pluginapi.CallbackAdmissionLimits{RequestsPerSecond: 1000, MaxConcurrency: workers}, process,
		func(_ context.Context, result string) { results <- result })
	go q.run(t.Context())

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		q.cancel()

		if err := q.stop(ctx); err != nil {
			t.Error(err)
		}
	})

	return q, results
}

// awaitLearningResult fails deterministically when a bounded worker no longer makes progress.
func awaitLearningResult(t *testing.T, results <-chan string, expected string) {
	t.Helper()

	select {
	case result := <-results:
		if result != expected {
			t.Fatalf("result=%s, want=%s", result, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("learning worker did not report completion")
	}
}

// TestLearningQueueBoundsWorkAndDrains keeps saturation nonblocking and processes accepted work once.
func TestLearningQueueBoundsWorkAndDrains(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})

	q, results := testLearningQueue(t, 1, 1, func(ctx context.Context, _ learningJob) string {
		entered <- struct{}{}

		select {
		case <-release:
			return storageApplied
		case <-ctx.Done():
			return learningUnavailable
		}
	})
	if q.submit(t.Context(), learningJob{}) != learningBuffered {
		t.Fatal("first job rejected")
	}

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	if q.submit(t.Context(), learningJob{}) != learningBuffered || q.submit(t.Context(), learningJob{}) != learningQueueFull {
		t.Fatal("queue capacity not enforced")
	}

	close(release)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	requireNoError(t, q.stop(ctx))
	awaitLearningResult(t, results, storageApplied)
	awaitLearningResult(t, results, storageApplied)

	if q.submit(t.Context(), learningJob{}) != learningShutdown {
		t.Fatal("shutdown admitted more work")
	}
}

// TestLearningQueueOwnsContextAndContainsPanic keeps request cancellation and plugin panics out of later jobs.
func TestLearningQueueOwnsContextAndContainsPanic(t *testing.T) {
	var calls atomic.Int32

	q, results := testLearningQueue(t, 1, 2, func(ctx context.Context, _ learningJob) string {
		if ctx.Err() != nil {
			t.Error("request cancellation leaked into worker")
		}

		if calls.Add(1) == 1 {
			panic("test worker failure")
		}

		return storageApplied
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	q.submit(ctx, learningJob{})
	awaitLearningResult(t, results, learningPanic)
	q.submit(ctx, learningJob{})
	awaitLearningResult(t, results, storageApplied)
}

// TestLearningQueueExpiresBeforeStorage prevents stale queued evidence from reaching Redis or Kafka.
func TestLearningQueueExpiresBeforeStorage(t *testing.T) {
	q, _ := testLearningQueue(t, 1, 1, func(context.Context, learningJob) string {
		t.Error("expired job reached storage")
		return storageApplied
	})
	if result := q.execute(learningJob{deadline: time.Now().Add(-time.Second)}); result != learningExpired {
		t.Fatalf("expired job result: %s", result)
	}
}

// TestAuthenticationCaptureNeverWaitsForStorage covers full queues and unavailable background delivery.
func TestAuthenticationCaptureNeverWaitsForStorage(t *testing.T) {
	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)

	entered := make(chan struct{}, 1)
	q, results := testLearningQueue(t, 1, 1, func(ctx context.Context, _ learningJob) string {
		entered <- struct{}{}

		<-ctx.Done()

		return learningUnavailable
	})
	state := &stateOwner{config: cfg}
	state.ready.Store(true)
	p := &Plugin{state: state, learningQueue: q}
	learner := authenticationLearner{plugin: p}
	request := learningQueueTestRequest(t)

	for range 4 {
		result, err := learner.Execute(t.Context(), request)
		if err != nil || result.Temporary || result.Applied {
			t.Fatalf("capture claimed delivery or vetoed authentication: %+v %v", result, err)
		}
	}

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("background delivery never started")
	}

	q.cancel()
	awaitLearningResult(t, results, learningUnavailable)
}

// learningQueueTestRequest provides immutable authenticated backend evidence with no credentials.
func learningQueueTestRequest(t *testing.T) pluginapi.ObligationRequest {
	t.Helper()

	identity, err := pluginapi.NewExecutionIdentityView(pluginName, componentLearnOutcome, extensionObligation, operationExecute, authenticationTarget)
	requireNoError(t, err)
	outcome, err := pluginapi.NewBackendOutcomeView("queue-test", "verified-account", pluginapi.BackendOutcomeAuthenticated, time.Now())
	requireNoError(t, err)
	request, err := pluginapi.NewObligationRequest(pluginapi.ObligationRequest{BackendOutcome: outcome, Snapshot: pluginapi.RequestSnapshot{ClientIP: "192.0.2.7"}}, identity)
	requireNoError(t, err)

	return request
}

// TestLearningQueueCapacityDoesNotChangeModel keeps operational sizing out of score and replay identity.
func TestLearningQueueCapacityDoesNotChangeModel(t *testing.T) {
	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)
	before, err := compileModel(cfg)
	requireNoError(t, err)

	cfg.raw.AuthLearningQueue = authLearningQueueConfig{Capacity: 4096, MaxAge: "1m", Timeout: "1s"}
	after, err := compileModel(cfg)
	requireNoError(t, err)

	if before.fingerprint != after.fingerprint {
		t.Fatal("queue sizing changed existing reputation")
	}
}

// TestLearningQueueSettingsRejectInvalidBounds validates durations independently even when their text is identical.
func TestLearningQueueSettingsRejectInvalidBounds(t *testing.T) {
	for _, test := range []struct {
		config authLearningQueueConfig
		valid  bool
	}{
		{authLearningQueueConfig{}, true},
		{authLearningQueueConfig{MaxAge: "2s", Timeout: "2s"}, true},
		{authLearningQueueConfig{Capacity: -1}, false},
		{authLearningQueueConfig{Capacity: 65537}, false},
		{authLearningQueueConfig{MaxAge: "bad"}, false},
		{authLearningQueueConfig{MaxAge: "0s"}, false},
		{authLearningQueueConfig{MaxAge: "6m"}, false},
		{authLearningQueueConfig{Timeout: "31s"}, false},
	} {
		settings, err := test.config.settings()
		if (err == nil) != test.valid {
			t.Fatalf("settings=%+v error=%v valid=%v", settings, err, test.valid)
		}

		if test.config.MaxAge == "2s" && settings.maxAge != 2*time.Second {
			t.Fatal("equal duration text lost one setting")
		}
	}
}

// TestLearningQueueRetriesTheSameEvidence preserves deduplication identity through a transient delivery failure.
func TestLearningQueueRetriesTheSameEvidence(t *testing.T) {
	var attempts atomic.Int32

	q, results := testLearningQueue(t, 1, 1, func(_ context.Context, job learningJob) string {
		if job.input.eventID != "unchanged-event" {
			t.Error("retry changed event identity")
		}

		if attempts.Add(1) == 1 {
			return learningUnavailable
		}

		return storageApplied
	})
	q.submit(t.Context(), learningJob{input: observationInput{eventID: "unchanged-event"}})
	awaitLearningResult(t, results, learningRetried)
	awaitLearningResult(t, results, storageApplied)
}

// TestLearningQueueShutdownDeadlineCancelsBlockedStorage releases workers and counts abandoned queued evidence.
func TestLearningQueueShutdownDeadlineCancelsBlockedStorage(t *testing.T) {
	entered := make(chan struct{})
	q, results := testLearningQueue(t, 1, 1, func(ctx context.Context, _ learningJob) string {
		close(entered)
		<-ctx.Done()

		return learningUnavailable
	})
	q.submit(t.Context(), learningJob{})

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter storage")
	}

	q.submit(t.Context(), learningJob{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if q.stop(ctx) != context.Canceled {
		t.Fatal("shutdown ignored the caller deadline")
	}

	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("canceled workers retained queued evidence")
	}

	awaitLearningResult(t, results, learningUnavailable)
	awaitLearningResult(t, results, learningShutdown)
}
