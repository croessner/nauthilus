package main

import (
	"context"
	"sync"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	learningBuffered  = "buffered"
	learningQueueFull = "queue_full"
	learningExpired   = "expired"
	learningShutdown  = "shutdown"
	learningRetried   = "retried"
	learningPanic     = "worker_panic"
)

// learningJob retains only bounded independent evidence and tracing identity, never the authentication request.
type learningJob struct {
	source   *sourcePolicy
	input    observationInput
	span     oteltrace.SpanContext
	deadline time.Time
}

// authenticationLearningQueue isolates storage pressure with fixed workers and nonblocking, bounded admission.
type authenticationLearningQueue struct {
	metrics  *learningQueueTelemetry
	process  func(context.Context, learningJob) string
	observe  func(context.Context, string)
	queue    chan learningJob
	done     chan struct{}
	limiter  *rate.Limiter
	cancel   context.CancelFunc
	lifetime context.Context
	settings learningQueueSettings
	workers  int
	mu       sync.Mutex
	closed   bool
}

// newAuthenticationLearningQueue constructs a process-local queue; run owns all execution and cleanup.
func newAuthenticationLearningQueue(settings learningQueueSettings, limits pluginapi.CallbackAdmissionLimits, process func(context.Context, learningJob) string, observe func(context.Context, string)) *authenticationLearningQueue {
	ctx, cancel := context.WithCancel(context.Background())

	return &authenticationLearningQueue{queue: make(chan learningJob, settings.capacity), done: make(chan struct{}),
		limiter: rate.NewLimiter(rate.Limit(limits.RequestsPerSecond), limits.RequestsPerSecond), workers: limits.MaxConcurrency,
		settings: settings, process: process, observe: observe, lifetime: ctx, cancel: cancel}
}

// submit transfers evidence without waiting for worker capacity, storage, or the request lifetime.
func (q *authenticationLearningQueue) submit(ctx context.Context, job learningJob) string {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed || q.lifetime.Err() != nil {
		return learningShutdown
	}

	job.deadline = time.Now().Add(q.settings.maxAge)
	job.span = oteltrace.SpanContextFromContext(ctx)

	q.metrics.change(1, 0)

	select {
	case q.queue <- job:
		return learningBuffered
	default:
		q.metrics.change(-1, 0)
		return learningQueueFull
	}
}

// run owns a fixed worker set and accounts for every pending item when shutdown cancels execution.
func (q *authenticationLearningQueue) run(ctx context.Context) {
	defer close(q.done)
	defer q.cancel()

	stop := context.AfterFunc(ctx, q.cancel)
	defer stop()

	var workers sync.WaitGroup

	for range q.workers {
		workers.Go(q.work)
	}

	workers.Wait()
	q.close()

	for range q.queue {
		q.metrics.change(-1, 0)
		q.observe(context.Background(), learningShutdown)
	}
}

// work consumes queued evidence until a graceful drain completes or the host cancels its lifetime.
func (q *authenticationLearningQueue) work() {
	for {
		select {
		case <-q.lifetime.Done():
			return
		case job, ok := <-q.queue:
			if !ok {
				return
			}

			q.metrics.change(-1, 1)
			q.observe(context.Background(), q.execute(job))
			q.metrics.change(0, -1)
		}
	}
}

// execute bounds rate waiting and delivery while containing panics so worker capacity cannot silently disappear.
func (q *authenticationLearningQueue) execute(job learningJob) (result string) {
	defer func() {
		if recover() != nil {
			result = learningPanic
		}
	}()

	ctx, cancel := context.WithDeadline(oteltrace.ContextWithSpanContext(q.lifetime, job.span), job.deadline)
	defer cancel()

	for {
		if err := q.limiter.Wait(ctx); err != nil {
			if q.lifetime.Err() != nil {
				return learningShutdown
			}

			return learningExpired
		}

		result = q.deliver(ctx, job)
		if result != learningUnavailable && result != learningPartial {
			return result
		}

		if !q.retry(ctx) {
			return result
		}
	}
}

// deliver bounds one storage attempt while preserving the original event identity across retries.
func (q *authenticationLearningQueue) deliver(ctx context.Context, job learningJob) string {
	delivery, stop := context.WithTimeout(ctx, q.settings.timeout)
	defer stop()

	return q.process(delivery, job)
}

// retry bounds outage pressure and reports retries separately from terminal learning outcomes.
func (q *authenticationLearningQueue) retry(ctx context.Context) bool {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		q.observe(ctx, learningRetried)
		return true
	}
}

// close excludes new submissions before closing the channel exactly once.
func (q *authenticationLearningQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.closed {
		q.closed = true
		close(q.queue)
	}
}

// stop drains accepted work within the caller's shutdown budget, then cancels outstanding delivery.
func (q *authenticationLearningQueue) stop(ctx context.Context) error {
	q.close()

	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		q.cancel()
		return ctx.Err()
	}
}
