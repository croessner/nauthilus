package engine

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const maxLatencyMs = 60000

// DefaultStatsCollector describes the exported DefaultStatsCollector type.
type DefaultStatsCollector struct {
	total              atomic.Int64
	matched            atomic.Int64
	mismatched         atomic.Int64
	httpErrs           atomic.Int64
	aborted            atomic.Int64
	skipped            atomic.Int64
	toleratedBF        atomic.Int64
	tooManyRequests    atomic.Int64
	parallelMatched    atomic.Int64
	parallelMismatched atomic.Int64
	latBuckets         [maxLatencyMs + 1]atomic.Int64
	latOverflow        atomic.Int64
	startTime          time.Time
	mu                 sync.RWMutex
	targetRPS          float64
	concurrency        int64
	minLat, maxLat     atomic.Int64 // in nanoseconds
	plateauActive      atomic.Bool
	statusCounts       [600]atomic.Int64
}

// NewDefaultStatsCollector provides the exported NewDefaultStatsCollector function.
func NewDefaultStatsCollector() *DefaultStatsCollector {
	s := &DefaultStatsCollector{
		startTime: time.Now(),
	}
	s.minLat.Store(math.MaxInt64)

	return s
}

// AddSample provides the exported AddSample method.
func (s *DefaultStatsCollector) AddSample(latency time.Duration, _ bool, isMatch bool, isHTTPErr bool, isAborted bool, isSkipped bool, isToleratedBF bool, isTooManyRequests bool, statusCode int) {
	s.total.Add(1)

	if s.recordTerminalSample(isAborted, isSkipped) {
		return
	}

	s.recordStatusCode(statusCode)
	s.recordOutcome(isMatch, isHTTPErr, isToleratedBF, isTooManyRequests)
	s.recordLatency(latency)
}

// recordTerminalSample records samples that do not carry normal response data.
func (s *DefaultStatsCollector) recordTerminalSample(isAborted bool, isSkipped bool) bool {
	if isAborted {
		s.aborted.Add(1)

		return true
	}

	if isSkipped {
		s.skipped.Add(1)

		return true
	}

	return false
}

// recordStatusCode increments the bounded HTTP status-code bucket.
func (s *DefaultStatsCollector) recordStatusCode(statusCode int) {
	if statusCode >= 0 && statusCode < len(s.statusCounts) {
		s.statusCounts[statusCode].Add(1)
	}
}

// recordOutcome updates match, error, and tolerated brute-force counters.
func (s *DefaultStatsCollector) recordOutcome(isMatch bool, isHTTPErr bool, isToleratedBF bool, isTooManyRequests bool) {
	addIf(s.httpErrs.Add, isHTTPErr)
	addIf(s.toleratedBF.Add, isToleratedBF)
	addIf(s.tooManyRequests.Add, isTooManyRequests)

	if isToleratedBF || isMatch {
		s.matched.Add(1)
	} else {
		s.mismatched.Add(1)
	}
}

// addIf increments an atomic counter when the condition is true.
func addIf(add func(int64) int64, condition bool) {
	if condition {
		add(1)
	}
}

// recordLatency updates latency bounds and histogram buckets.
func (s *DefaultStatsCollector) recordLatency(latency time.Duration) {
	latNs := latency.Nanoseconds()
	s.recordLatencyBounds(latNs)
	s.recordLatencyBucket(latency)
}

// recordLatencyBounds updates observed minimum and maximum latency values.
func (s *DefaultStatsCollector) recordLatencyBounds(latNs int64) {
	if latNs < s.minLat.Load() {
		s.minLat.Store(latNs)
	}

	if latNs > s.maxLat.Load() {
		s.maxLat.Store(latNs)
	}
}

// recordLatencyBucket increments the millisecond latency histogram bucket.
func (s *DefaultStatsCollector) recordLatencyBucket(latency time.Duration) {
	ms := max(latency.Milliseconds(), 0)
	if ms > maxLatencyMs {
		s.latOverflow.Add(1)
	} else {
		s.latBuckets[ms].Add(1)
	}
}

// SetTargetRPS provides the exported SetTargetRPS method.
func (s *DefaultStatsCollector) SetTargetRPS(rps float64) {
	s.mu.Lock()
	s.targetRPS = rps
	s.mu.Unlock()
}

// SetConcurrency provides the exported SetConcurrency method.
func (s *DefaultStatsCollector) SetConcurrency(c int64) {
	atomic.StoreInt64(&s.concurrency, c)
}

// SetPlateauActive provides the exported SetPlateauActive method.
func (s *DefaultStatsCollector) SetPlateauActive(active bool) {
	s.plateauActive.Store(active)
}

// IncParallelMatched provides the exported IncParallelMatched method.
func (s *DefaultStatsCollector) IncParallelMatched() {
	s.parallelMatched.Add(1)
}

// IncParallelMismatched provides the exported IncParallelMismatched method.
func (s *DefaultStatsCollector) IncParallelMismatched() {
	s.parallelMismatched.Add(1)
}

// Snapshot provides the exported Snapshot method.
func (s *DefaultStatsCollector) Snapshot() Stats {
	s.mu.RLock()
	trps := s.targetRPS
	s.mu.RUnlock()

	conc := atomic.LoadInt64(&s.concurrency)
	elapsed := time.Since(s.startTime)

	stats := Stats{
		Total:              s.total.Load(),
		Matched:            s.matched.Load(),
		Mismatched:         s.mismatched.Load(),
		HTTPErrs:           s.httpErrs.Load(),
		Aborted:            s.aborted.Load(),
		Skipped:            s.skipped.Load(),
		ToleratedBF:        s.toleratedBF.Load(),
		TooManyRequests:    s.tooManyRequests.Load(),
		ParallelMatched:    s.parallelMatched.Load(),
		ParallelMismatched: s.parallelMismatched.Load(),
		Elapsed:            elapsed,
		TargetRPS:          trps,
		Concurrency:        conc,
		PlateauActive:      s.plateauActive.Load(),
		StatusCounts:       make(map[int]int64),
	}

	for i := range 600 {
		if v := s.statusCounts[i].Load(); v > 0 {
			stats.StatusCounts[i] = v
		}
	}

	// Latency percentiles calculation logic from main.go
	stats.Min = time.Duration(s.minLat.Load())
	if stats.Min == math.MaxInt64 {
		stats.Min = 0
	}

	stats.Max = time.Duration(s.maxLat.Load())

	// Compute percentiles
	stats.P50, stats.P90, stats.P95, stats.P99, stats.Avg = s.computePercentiles()

	return stats
}

// Buckets provides the exported Buckets method.
func (s *DefaultStatsCollector) Buckets() []atomic.Int64 {
	return s.latBuckets[:]
}

// Overflow provides the exported Overflow method.
func (s *DefaultStatsCollector) Overflow() int64 {
	return s.latOverflow.Load()
}

func (s *DefaultStatsCollector) computePercentiles() (p50, p90, p95, p99, avg time.Duration) {
	var (
		totalMs int64
		count   int64
	)

	// We need a consistent snapshot of buckets
	buckets := make([]int64, maxLatencyMs+1)
	for i := 0; i <= maxLatencyMs; i++ {
		v := s.latBuckets[i].Load()
		buckets[i] = v
		count += v
		totalMs += v * int64(i)
	}

	overflow := s.latOverflow.Load()
	count += overflow
	totalMs += overflow * (maxLatencyMs + 1)

	if count == 0 {
		return 0, 0, 0, 0, 0
	}

	avg = time.Duration(totalMs/count) * time.Millisecond

	getPercentile := func(p float64) time.Duration {
		target := int64(math.Ceil(float64(count) * p))

		var current int64
		for i := 0; i <= maxLatencyMs; i++ {
			current += buckets[i]
			if current >= target {
				return time.Duration(i) * time.Millisecond
			}
		}

		return time.Duration(maxLatencyMs) * time.Millisecond
	}

	p50 = getPercentile(0.50)
	p90 = getPercentile(0.90)
	p95 = getPercentile(0.95)
	p99 = getPercentile(0.99)

	return
}

// Reset provides the exported Reset method.
func (s *DefaultStatsCollector) Reset() {
	s.total.Store(0)
	s.matched.Store(0)
	s.mismatched.Store(0)
	s.httpErrs.Store(0)
	s.aborted.Store(0)
	s.skipped.Store(0)
	s.toleratedBF.Store(0)
	s.tooManyRequests.Store(0)
	s.parallelMatched.Store(0)
	s.parallelMismatched.Store(0)

	for i := 0; i <= maxLatencyMs; i++ {
		s.latBuckets[i].Store(0)
	}

	for i := range 600 {
		s.statusCounts[i].Store(0)
	}

	s.latOverflow.Store(0)
	s.minLat.Store(math.MaxInt64)
	s.maxLat.Store(0)
	s.startTime = time.Now()
}
