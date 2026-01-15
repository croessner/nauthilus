package engine

import (
	"sync/atomic"
	"time"
)

// Stats is a read-only snapshot of key counters and latency percentiles.
type Stats struct {
	Total, Matched, Mismatched, HttpErrs, Aborted, Skipped, ToleratedBF, TooManyRequests int64
	Avg, P50, P90, P95, P99                                                              time.Duration
	Min, Max                                                                             time.Duration
	Elapsed                                                                              time.Duration
	TargetRPS                                                                            float64
	Concurrency                                                                          int64
}

// StatsCollector handles atomic updates to counters and latency tracking.
type StatsCollector interface {
	AddSample(latency time.Duration, ok bool, isMatch bool, isHttpErr bool, isAborted bool, isSkipped bool, isToleratedBF bool, isTooManyRequests bool)
	Snapshot() Stats
	Reset()
	Buckets() []atomic.Int64
	Overflow() int64
	SetTargetRPS(rps float64)
	SetConcurrency(c int64)
}
