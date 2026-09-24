package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/redis/go-redis/v9"
)

// The storage start retries transient Redis failures on the same budget as the host's Redis
// readiness check: at most ten attempts within about fifty seconds.
const (
	startupRetryAttempts     = 10
	startupRetryInitialDelay = time.Second
	startupRetryMaxDelay     = 5 * time.Second
	startupRetryBudget       = 50 * time.Second
)

// Error classes reported by the startup retry. They name the failure kind without Redis details.
const (
	redisErrorClassAsk         = "ask"
	redisErrorClassClosed      = "closed"
	redisErrorClassClusterDown = "clusterdown"
	redisErrorClassConnection  = "connection"
	redisErrorClassLoading     = "loading"
	redisErrorClassMasterDown  = "masterdown"
	redisErrorClassMaxClients  = "maxclients"
	redisErrorClassMoved       = "moved"
	redisErrorClassNoReplicas  = "noreplicas"
	redisErrorClassNoScript    = "noscript"
	redisErrorClassPermanent   = "permanent"
	redisErrorClassPoolTimeout = "pool_timeout"
	redisErrorClassReadOnly    = "readonly"
	redisErrorClassTimeout     = "timeout"
	redisErrorClassTopology    = "topology"
	redisErrorClassTryAgain    = "tryagain"
)

// Log field keys of the startup retry warning.
const (
	startupRetryLogAttempt     = "attempt"
	startupRetryLogMaxAttempts = "max_attempts"
	startupRetryLogErrorClass  = "error_class"
	startupRetryLogRetryIn     = "retry_in"
	startupRetryLogError       = "error"
)

// redisClusterNoNodes is the go-redis message for a cluster client without a loaded topology.
const redisClusterNoNodes = "redis: cluster has no nodes"

// redisTransientClass pairs a go-redis error predicate with its class.
type redisTransientClass struct {
	matches func(error) bool
	class   string
}

// redisTransientClasses lists the Redis replies that a restarting or resharding deployment returns
// for a short time and that a later attempt can overcome.
var redisTransientClasses = []redisTransientClass{
	{redis.IsLoadingError, redisErrorClassLoading},
	{redis.IsTryAgainError, redisErrorClassTryAgain},
	{redis.IsClusterDownError, redisErrorClassClusterDown},
	{redis.IsReadOnlyError, redisErrorClassReadOnly},
	{redis.IsMasterDownError, redisErrorClassMasterDown},
	{redis.IsMaxClientsError, redisErrorClassMaxClients},
	{redis.IsNoReplicasError, redisErrorClassNoReplicas},
	{func(err error) bool { _, ok := redis.IsMovedError(err); return ok }, redisErrorClassMoved},
	{func(err error) bool { _, ok := redis.IsAskError(err); return ok }, redisErrorClassAsk},
	{func(err error) bool { return strings.HasPrefix(strings.ToUpper(err.Error()), "NOSCRIPT") }, redisErrorClassNoScript},
	{func(err error) bool { return strings.HasPrefix(err.Error(), redisClusterNoNodes) }, redisErrorClassTopology},
}

// startupRetry repeats the storage start while Redis reports transient failures.
type startupRetry struct {
	logger       pluginapi.Logger
	wait         func(context.Context, time.Duration) error
	now          func() time.Time
	attempts     int
	initialDelay time.Duration
	maxDelay     time.Duration
	budget       time.Duration
}

// newStartupRetry returns the production retry policy that reports retries through logger.
func newStartupRetry(logger pluginapi.Logger) startupRetry {
	return startupRetry{
		logger:       logger,
		wait:         waitStartupRetry,
		now:          time.Now,
		attempts:     startupRetryAttempts,
		initialDelay: startupRetryInitialDelay,
		maxDelay:     startupRetryMaxDelay,
		budget:       startupRetryBudget,
	}
}

// run calls start until it succeeds, fails permanently, the attempts or the budget are used up, or
// ctx ends. Every returned failure keeps the concrete cause of the last attempt.
func (r startupRetry) run(ctx context.Context, start func(context.Context) error) error {
	started := r.now()
	delay := r.initialDelay

	for attempt := 1; ; attempt++ {
		err := start(ctx)
		if err == nil {
			return nil
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("reputation storage start stopped after %d attempts: %w: last error: %w", attempt, ctxErr, err)
		}

		class, transient := classifyStartupError(err)
		if !transient {
			return err
		}

		if attempt >= r.attempts || r.now().Sub(started)+delay > r.budget {
			return fmt.Errorf("reputation storage start gave up after %d attempts on %s Redis errors: %w", attempt, class, err)
		}

		r.logRetry(ctx, attempt, class, delay, err)

		if waitErr := r.wait(ctx, delay); waitErr != nil {
			return fmt.Errorf("reputation storage start stopped after %d attempts: %w: last error: %w", attempt, waitErr, err)
		}

		delay = min(2*delay, r.maxDelay)
	}
}

// logRetry reports one failed attempt at warn before the next attempt.
func (r startupRetry) logRetry(ctx context.Context, attempt int, class string, delay time.Duration, err error) {
	if r.logger == nil {
		return
	}

	r.logger.Warn(ctx, "Reputation storage start failed on a transient Redis error; retrying",
		pluginapi.LogField{Key: startupRetryLogAttempt, Value: attempt},
		pluginapi.LogField{Key: startupRetryLogMaxAttempts, Value: r.attempts},
		pluginapi.LogField{Key: startupRetryLogErrorClass, Value: class},
		pluginapi.LogField{Key: startupRetryLogRetryIn, Value: delay.String()},
		pluginapi.LogField{Key: startupRetryLogError, Value: err.Error()},
	)
}

// waitStartupRetry sleeps for delay unless ctx ends first.
func waitStartupRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// classifyStartupError reports the class of a storage start failure and whether a later attempt can
// succeed. Only Redis transport failures qualify; state-machine outcomes such as a model or
// allocation mismatch and invalid stored state are permanent.
func classifyStartupError(err error) (string, bool) {
	transport, ok := errors.AsType[*stateTransportError](err)
	if !ok {
		return redisErrorClassPermanent, false
	}

	return classifyRedisError(transport.cause)
}

// classifyRedisError classifies one Redis client failure. The caller has already checked that its
// own context is still alive, so a deadline here is the per-operation timeout of the host registry.
func classifyRedisError(err error) (string, bool) {
	switch {
	case errors.Is(err, redis.ErrClosed):
		return redisErrorClassClosed, false
	case errors.Is(err, context.Canceled):
		return redisErrorClassPermanent, false
	case errors.Is(err, context.DeadlineExceeded):
		return redisErrorClassTimeout, true
	case errors.Is(err, redis.ErrPoolTimeout):
		return redisErrorClassPoolTimeout, true
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return redisErrorClassConnection, true
	}

	if netErr, ok := errors.AsType[net.Error](err); ok {
		if netErr.Timeout() {
			return redisErrorClassTimeout, true
		}

		return redisErrorClassConnection, true
	}

	for _, candidate := range redisTransientClasses {
		if candidate.matches(err) {
			return candidate.class, true
		}
	}

	return redisErrorClassPermanent, false
}
