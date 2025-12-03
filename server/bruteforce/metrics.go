package bruteforce

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics for brute-force evaluation path. These are intentionally local
// to the bruteforce package to avoid widening the central metrics interface.

var (
	// BruteForceEvalSeconds measures end-to-end latency of the BF path.
	BruteForceEvalSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "nauthilus_bruteforce_eval_seconds",
			Help:    "End-to-end duration of brute-force evaluation",
			Buckets: prometheus.ExponentialBuckets(0.001, 1.7, 15),
		},
	)

	// BruteForcePhaseSeconds measures sub-phase timings with a phase label.
	BruteForcePhaseSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "nauthilus_bruteforce_phase_seconds",
			Help:    "Duration by phase in brute-force evaluation",
			Buckets: prometheus.ExponentialBuckets(0.0005, 1.7, 16),
		},
		[]string{"phase"},
	)

	// BruteForceCacheHitsTotal counts in-process cache/burst gating hits.
	BruteForceCacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nauthilus_bruteforce_cache_hits_total",
			Help: "Total cache hits in brute-force path",
		},
		[]string{"kind"},
	)

	// BruteForceRulesMatchedTotal counts how often a rule matched (pre or final).
	BruteForceRulesMatchedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "nauthilus_bruteforce_rules_matched_total",
			Help: "Total number of matched brute-force rules",
		},
	)

	// RedisRoundtripsTotal counts Redis roundtrips attributable to the BF path.
	RedisRoundtripsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nauthilus_redis_roundtrips_total",
			Help: "Total Redis roundtrips by kind in brute-force path",
		},
		[]string{"kind"},
	)
)
