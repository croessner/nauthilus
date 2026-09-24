package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

// redisReply mimics an error reply parsed by go-redis.
type redisReply string

// Error returns the reply text.
func (r redisReply) Error() string { return string(r) }

// RedisError marks the reply as a Redis error.
func (redisReply) RedisError() {}

// errRedisLoading mimics the reply of a Redis node that is still loading its dataset.
var errRedisLoading = redisReply("LOADING Redis is loading the dataset in memory")

// errRedisNoPermission mimics an ACL rejection, which no retry can overcome.
var errRedisNoPermission = redisReply("NOPERM User nauthilus has no permissions to run the 'script|load' command")

// startupRedis replaces the script registry of a real host facade.
type startupRedis struct {
	pluginapi.Redis
	scripts *startupScripts
}

// Scripts returns the scripted registry.
func (r startupRedis) Scripts() pluginapi.RedisScriptRegistry { return r.scripts }

// startupScripts fails the first uploads with uploadErr, the first script runs with runErr, and
// answers the activation scripts.
type startupScripts struct {
	uploadErr      error
	runErr         error
	metadataResult []any
	failures       int
	failed         int
	uploads        int
	runFailures    int
	runFailed      int
}

// Upload fails while failures remain and succeeds afterwards.
func (s *startupScripts) Upload(_ context.Context, name string, _ string) (string, error) {
	s.uploads++

	if s.failed < s.failures {
		s.failed++

		return "", s.uploadErr
	}

	return name, nil
}

// Run fails while run failures remain and then answers metadata and control activation like an empty keyspace.
func (s *startupScripts) Run(_ context.Context, name string, _ []string, _ ...any) (any, error) {
	if s.runFailed < s.runFailures {
		s.runFailed++

		return nil, s.runErr
	}

	if name == scriptMetadata {
		return s.metadataResult, nil
	}

	return []any{storageActive}, nil
}

// warnRecord keeps one captured warn entry.
type warnRecord struct {
	fields map[string]any
	msg    string
}

// recordingLogger captures warn entries of the startup retry.
type recordingLogger struct {
	warnings []warnRecord
	mu       sync.Mutex
}

// Debug discards the entry.
func (*recordingLogger) Debug(context.Context, string, ...pluginapi.LogField) {}

// Info discards the entry.
func (*recordingLogger) Info(context.Context, string, ...pluginapi.LogField) {}

// Error discards the entry.
func (*recordingLogger) Error(context.Context, string, ...pluginapi.LogField) {}

// Warn records the entry with its fields.
func (l *recordingLogger) Warn(_ context.Context, msg string, fields ...pluginapi.LogField) {
	record := warnRecord{msg: msg, fields: make(map[string]any, len(fields))}
	for _, field := range fields {
		record.fields[field.Key] = field.Value
	}

	l.mu.Lock()
	l.warnings = append(l.warnings, record)
	l.mu.Unlock()
}

// newStartupOwner builds a state owner whose uploads fail failures times with uploadErr.
func newStartupOwner(t *testing.T, uploadErr error, failures int) (*stateOwner, *startupScripts) {
	t.Helper()

	client, _ := redismock.NewClientMock()

	t.Cleanup(func() { _ = client.Close() })

	scripts := &startupScripts{uploadErr: uploadErr, failures: failures, metadataResult: []any{storageActive, ""}}
	facade := startupRedis{Redis: pluginruntime.NewRedisFacade(rediscli.NewTestClient(client)), scripts: scripts}

	owner, err := newStateOwner(testConfig(t), manifestTestTagger(t, false), facade)
	requireNoError(t, err)

	return owner, scripts
}

// testStartupRetry returns the production policy without real sleeps.
func testStartupRetry(logger pluginapi.Logger) startupRetry {
	retry := newStartupRetry(logger)
	retry.wait = func(context.Context, time.Duration) error { return nil }

	return retry
}

// TestStateStartRetriesTransientRedisFailures pins that transient Redis failures are retried until the
// start succeeds and that every retry is logged with its attempt and error class.
func TestStateStartRetriesTransientRedisFailures(t *testing.T) {
	owner, scripts := newStartupOwner(t, errRedisLoading, 3)
	logger := &recordingLogger{}

	requireNoError(t, testStartupRetry(logger).run(t.Context(), owner.start))

	if !owner.ready.Load() {
		t.Fatal("writer readiness was not published after the successful attempt")
	}

	if scripts.failed != 3 {
		t.Fatalf("expected 3 failed attempts, got %d", scripts.failed)
	}

	if len(logger.warnings) != 3 {
		t.Fatalf("expected 3 retry warnings, got %d", len(logger.warnings))
	}

	for index, warning := range logger.warnings {
		if warning.fields[startupRetryLogAttempt] != index+1 || warning.fields[startupRetryLogErrorClass] != redisErrorClassLoading {
			t.Fatalf("unexpected retry warning %d: %v", index, warning.fields)
		}

		if !strings.Contains(warning.fields[startupRetryLogError].(string), "LOADING") {
			t.Fatalf("retry warning lost the cause: %v", warning.fields[startupRetryLogError])
		}
	}
}

// TestStateStartRetriesTransientRedisFailuresInAllocationMaintenance pins that the allocation status
// check of a maintenance start keeps the Redis cause, so transient failures are retried there too.
func TestStateStartRetriesTransientRedisFailuresInAllocationMaintenance(t *testing.T) {
	owner, scripts := newStartupOwner(t, nil, 0)
	owner.config.raw.AllocationMaintenance = true
	scripts.runErr = errRedisLoading
	scripts.runFailures = 3
	scripts.metadataResult = []any{storageActive, allocationStatusFixture(t, owner.config.raw.AllocationDrainGeneration)}
	logger := &recordingLogger{}

	requireNoError(t, testStartupRetry(logger).run(t.Context(), owner.start))

	if scripts.runFailed != 3 || scripts.uploads != 4*len(reputationScripts()) {
		t.Fatalf("expected 4 attempts with 3 failed status checks, got uploads=%d failed=%d", scripts.uploads, scripts.runFailed)
	}

	if len(logger.warnings) != 3 {
		t.Fatalf("expected 3 retry warnings, got %d", len(logger.warnings))
	}

	for index, warning := range logger.warnings {
		if warning.fields[startupRetryLogAttempt] != index+1 || warning.fields[startupRetryLogErrorClass] != redisErrorClassLoading {
			t.Fatalf("unexpected retry warning %d: %v", index, warning.fields)
		}

		if !strings.Contains(warning.fields[startupRetryLogError].(string), "run script "+scriptMetadata) {
			t.Fatalf("retry warning lost the failing step: %v", warning.fields[startupRetryLogError])
		}
	}

	if owner.ready.Load() {
		t.Fatal("a maintenance start must not publish writer readiness")
	}
}

// TestRequestTimeAllocationStatusHidesRedisDetails pins that the management status path keeps the
// closed failure class while the start path sees the Redis cause.
func TestRequestTimeAllocationStatusHidesRedisDetails(t *testing.T) {
	owner, _ := newStartupOwner(t, nil, 0)
	owner.redis = failingRedis{Redis: owner.redis, scripts: &failingScripts{err: errRedisLoading}}

	_, err := owner.allocationStatus(t.Context())
	if err == nil || err.Error() != errStateUnavailable.Error() {
		t.Fatalf("expected the bare unavailable class, got %v", err)
	}
}

// allocationStatusFixture encodes a valid active allocation snapshot for generation.
func allocationStatusFixture(t *testing.T, generation int) string {
	t.Helper()

	encoded, err := json.Marshal(allocationView{Mode: storageActive, Generation: generation, NextGeneration: generation + 1,
		Retention: time.Hour.Seconds(), ObservedAt: float64(time.Now().Unix())})
	requireNoError(t, err)

	return string(encoded)
}

// TestStateStartFailsFastOnPermanentErrors pins that permanent Redis errors and state-machine outcomes
// end the start after the first attempt with their cause.
func TestStateStartFailsFastOnPermanentErrors(t *testing.T) {
	t.Run("redis permission", func(t *testing.T) {
		owner, scripts := newStartupOwner(t, errRedisNoPermission, 1)
		logger := &recordingLogger{}

		err := testStartupRetry(logger).run(t.Context(), owner.start)
		if !errors.Is(err, errStateUnavailable) || !strings.Contains(err.Error(), "NOPERM") {
			t.Fatalf("expected the permission error, got %v", err)
		}

		if scripts.uploads != 1 || len(logger.warnings) != 0 {
			t.Fatalf("permanent error was retried: uploads=%d warnings=%d", scripts.uploads, len(logger.warnings))
		}
	})

	t.Run("model mismatch", func(t *testing.T) {
		owner, scripts := newStartupOwner(t, nil, 0)
		scripts.metadataResult = []any{storageModelMismatch}

		err := testStartupRetry(&recordingLogger{}).run(t.Context(), owner.start)
		if !errors.Is(err, errModelMismatch) {
			t.Fatalf("expected the model mismatch, got %v", err)
		}

		if scripts.uploads != len(reputationScripts()) {
			t.Fatalf("state-machine outcome was retried: uploads=%d", scripts.uploads)
		}
	})
}

// TestStateStartGivesUpWithTheLastCause pins that the bounded retry ends after its attempts and that the
// caller receives the concrete Redis error of the last attempt.
func TestStateStartGivesUpWithTheLastCause(t *testing.T) {
	owner, scripts := newStartupOwner(t, errRedisLoading, 100)

	err := testStartupRetry(&recordingLogger{}).run(t.Context(), owner.start)
	if err == nil || !errors.Is(err, errStateUnavailable) {
		t.Fatalf("expected an unavailable state error, got %v", err)
	}

	for _, want := range []string{"after 10 attempts", "upload script", "LOADING Redis is loading the dataset in memory"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q misses %q", err, want)
		}
	}

	if scripts.uploads != startupRetryAttempts || owner.ready.Load() {
		t.Fatalf("unexpected retry end: uploads=%d ready=%t", scripts.uploads, owner.ready.Load())
	}
}

// TestStateStartRetryRespectsTheBudget pins that no attempt starts once the time budget would be exceeded.
func TestStateStartRetryRespectsTheBudget(t *testing.T) {
	owner, scripts := newStartupOwner(t, errRedisLoading, 100)
	clock := time.Unix(0, 0)
	retry := testStartupRetry(&recordingLogger{})
	retry.now = func() time.Time { return clock }
	retry.wait = func(_ context.Context, delay time.Duration) error {
		clock = clock.Add(delay)

		return nil
	}
	retry.attempts = 100

	if err := retry.run(t.Context(), owner.start); err == nil {
		t.Fatal("expected the retry to give up")
	}

	if clock.Sub(time.Unix(0, 0)) > startupRetryBudget {
		t.Fatalf("retry waited %s beyond the budget", clock.Sub(time.Unix(0, 0)))
	}

	if scripts.uploads < 2 {
		t.Fatalf("expected several attempts within the budget, got %d", scripts.uploads)
	}
}

// TestStateStartRetryStopsOnContextCancellation pins that a cancelled start context ends the retry
// while keeping the last Redis cause visible.
func TestStateStartRetryStopsOnContextCancellation(t *testing.T) {
	owner, scripts := newStartupOwner(t, errRedisLoading, 100)
	ctx, cancel := context.WithCancel(t.Context())
	retry := newStartupRetry(&recordingLogger{})
	retry.wait = func(ctx context.Context, delay time.Duration) error {
		cancel()

		return waitStartupRetry(ctx, delay)
	}

	err := retry.run(ctx, owner.start)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "LOADING") {
		t.Fatalf("expected cancellation with the last cause, got %v", err)
	}

	if scripts.uploads != 1 {
		t.Fatalf("retry continued after cancellation: uploads=%d", scripts.uploads)
	}
}

// TestPluginStartReportsTheRedisCause pins that the module Start error carries the concrete Redis
// failure, so the host's startup error log shows it.
func TestPluginStartReportsTheRedisCause(t *testing.T) {
	plugin := NewPlugin()
	plugin.config = testConfig(t)
	tagger := manifestTestTagger(t, false)

	client, mock := redismock.NewClientMock()

	t.Cleanup(func() { _ = client.Close() })

	mock.MatchExpectationsInOrder(false)

	for _, source := range reputationScripts() {
		mock.ExpectScriptLoad(source).SetErr(errRedisNoPermission)
	}

	host := pluginruntime.NewHost(pluginruntime.WithConfig(pluginregistry.NewConfigView(testAdmissionMap())),
		pluginruntime.WithOpaqueIdentifierTagger(tagger), pluginruntime.WithRedis(pluginruntime.NewRedisFacade(rediscli.NewTestClient(client))))

	err := plugin.Start(t.Context(), host)
	if !errors.Is(err, errStateUnavailable) || !strings.Contains(err.Error(), "NOPERM") || !strings.Contains(err.Error(), "upload script reputation.") {
		t.Fatalf("expected the Redis cause in the start error, got %v", err)
	}
}

// TestRequestTimeRunHidesRedisDetails pins that request-time storage calls keep the closed failure class
// without the Redis cause.
func TestRequestTimeRunHidesRedisDetails(t *testing.T) {
	owner, _ := newStartupOwner(t, nil, 0)
	owner.redis = failingRedis{Redis: owner.redis, scripts: &failingScripts{err: errRedisLoading}}

	_, err := owner.run(t.Context(), scriptMetadata, owner.keys.metadata(), owner.metadataRequest("activate"))
	if !errors.Is(err, errStateUnavailable) || err.Error() != errStateUnavailable.Error() {
		t.Fatalf("expected the bare unavailable class, got %v", err)
	}
}

// failingRedis replaces the script registry with one that always fails.
type failingRedis struct {
	pluginapi.Redis
	scripts *failingScripts
}

// Scripts returns the failing registry.
func (r failingRedis) Scripts() pluginapi.RedisScriptRegistry { return r.scripts }

// failingScripts fails every call with err.
type failingScripts struct {
	err error
}

// Upload fails with err.
func (s *failingScripts) Upload(context.Context, string, string) (string, error) { return "", s.err }

// Run fails with err.
func (s *failingScripts) Run(context.Context, string, []string, ...any) (any, error) { return nil, s.err }

// TestClassifyRedisError pins which Redis failures count as transient.
func TestClassifyRedisError(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}

	tests := []struct {
		err       error
		class     string
		transient bool
	}{
		{dialErr, redisErrorClassConnection, true},
		{context.DeadlineExceeded, redisErrorClassTimeout, true},
		{redis.ErrPoolTimeout, redisErrorClassPoolTimeout, true},
		{errRedisLoading, redisErrorClassLoading, true},
		{redisReply("TRYAGAIN Multiple keys request during rehashing of slot"), redisErrorClassTryAgain, true},
		{redisReply("CLUSTERDOWN The cluster is down"), redisErrorClassClusterDown, true},
		{redisReply("READONLY You can't write against a read only replica."), redisErrorClassReadOnly, true},
		{redisReply("MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'."), redisErrorClassMasterDown, true},
		{redisReply("MOVED 3999 127.0.0.1:6381"), redisErrorClassMoved, true},
		{redisReply("NOSCRIPT No matching script. Please use EVAL."), redisErrorClassNoScript, true},
		{errors.New(redisClusterNoNodes), redisErrorClassTopology, true},
		{redis.ErrClosed, redisErrorClassClosed, false},
		{context.Canceled, redisErrorClassPermanent, false},
		{errRedisNoPermission, redisErrorClassPermanent, false},
		{redisReply("ERR Error running script (call to f_x): @user_script:1: boom"), redisErrorClassPermanent, false},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			class, transient := classifyStartupError(newStateTransportError("step", tt.err))
			if class != tt.class || transient != tt.transient {
				t.Fatalf("got class=%s transient=%t, want class=%s transient=%t", class, transient, tt.class, tt.transient)
			}
		})
	}

	if _, transient := classifyStartupError(errStateUnavailable); transient {
		t.Fatal("a sanitized state error must not be retried")
	}
}
