package engine

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const maxLatencyMs = 60000

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

func NewDefaultStatsCollector() *DefaultStatsCollector {
	s := &DefaultStatsCollector{
		startTime: time.Now(),
	}
	s.minLat.Store(math.MaxInt64)
	return s
}

func (s *DefaultStatsCollector) AddSample(latency time.Duration, _ bool, isMatch bool, isHttpErr bool, isAborted bool, isSkipped bool, isToleratedBF bool, isTooManyRequests bool, statusCode int) {
	s.total.Add(1)
	if isAborted {
		s.aborted.Add(1)
		return
	}
	if isSkipped {
		s.skipped.Add(1)
		return
	}
	if statusCode >= 0 && statusCode < 600 {
		s.statusCounts[statusCode].Add(1)
	}
	if isHttpErr {
		s.httpErrs.Add(1)
	}
	if isToleratedBF {
		s.toleratedBF.Add(1)
	}
	if isTooManyRequests {
		s.tooManyRequests.Add(1)
	}

	if isToleratedBF || isMatch {
		s.matched.Add(1)
	} else {
		s.mismatched.Add(1)
	}

	latNs := latency.Nanoseconds()
	if latNs < s.minLat.Load() {
		s.minLat.Store(latNs)
	}
	if latNs > s.maxLat.Load() {
		s.maxLat.Store(latNs)
	}

	ms := max(latency.Milliseconds(), 0)
	if ms > maxLatencyMs {
		s.latOverflow.Add(1)
	} else {
		s.latBuckets[ms].Add(1)
	}
}

func (s *DefaultStatsCollector) SetTargetRPS(rps float64) {
	s.mu.Lock()
	s.targetRPS = rps
	s.mu.Unlock()
}

func (s *DefaultStatsCollector) SetConcurrency(c int64) {
	atomic.StoreInt64(&s.concurrency, c)
}

func (s *DefaultStatsCollector) SetPlateauActive(active bool) {
	s.plateauActive.Store(active)
}

func (s *DefaultStatsCollector) IncParallelMatched() {
	s.parallelMatched.Add(1)
}

func (s *DefaultStatsCollector) IncParallelMismatched() {
	s.parallelMismatched.Add(1)
}

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
		HttpErrs:           s.httpErrs.Load(),
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

func (s *DefaultStatsCollector) Buckets() []atomic.Int64 {
	return s.latBuckets[:]
}

func (s *DefaultStatsCollector) Overflow() int64 {
	return s.latOverflow.Load()
}

func (s *DefaultStatsCollector) computePercentiles() (p50, p90, p95, p99, avg time.Duration) {
	var totalMs int64
	var count int64

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
