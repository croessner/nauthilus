package core

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

var (
	//nolint:gochecknoglobals // Ignore
	HTTPRequestsTotalCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nauthilus_http_requests_total",
			Help: "Number of HTTP requests.",
		},
		[]string{"path"})

	//nolint:gochecknoglobals // Ignore
	LoginsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nauthilus_logins_total",
			Help: "Number of failed and successful login attempts",
		},
		[]string{"logins"})

	//nolint:gochecknoglobals // Ignore
	HTTPResponseTimeSecondsHist = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "nauthilus_http_response_time_seconds",
			Help: "Duration of HTTP requests.",
		},
		[]string{"path"})
)

// Metric is a prometheus metric with a value and a label.
type Metric struct {
	Value float64 `redis:"value"`
	Label string  `redis:"label"`
}

//nolint:errcheck,gochecknoinits // Ignore
func init() {
	prometheus.Register(HTTPRequestsTotalCounter)
	prometheus.Register(LoginsCounter)
	prometheus.Register(HTTPResponseTimeSecondsHist)
}

// bToKb calculates the number of kilobytes (KB) equivalent to the given number of bytes (B).
func bToKb(b uint64) uint64 {
	return b / 1024
}

// kbSuffix returns a string representation of the given value
// with the suffix "KiB" appended to it.
//
// Example: kbSuffix(1024) returns "1024KiB"
func kbSuffix(value uint64) string {
	return fmt.Sprintf("%dKB", value)
}

// PrintStats prints various memory statistics using the default logger.
// It retrieves the memory statistics using the runtime.ReadMemStats function
// and then logs the statistics using level.Info from the logging package.
// The statistics logged include:
//   - alloc: The number of kilobytes (KB) allocated.
//   - heap_alloc: The number of kilobytes (KB) allocated on the heap.
//   - heap_in_use: The number of kilobytes (KB) in use on the heap.
//   - heap_idle: The number of kilobytes (KB) idle on the heap.
//   - stack_in_use: The number of kilobytes (KB) in use on the stack.
//   - stack_sys: The stack size of the program.
//   - sys: The total memory allocated by the program.
//   - total_alloc: The total number of kilobytes (KB) allocated.
//   - num_gc: The number of garbage collections performed.
//
// It uses the kbSuffix function to convert the memory values in bytes to kilobytes (KB)
// by dividing them by 1024.
// The logging is performed using the DefaultLogger from the logging package.
// Note: The declarations of logging.DefaultLogger, decl.LogKeyStatsAlloc, kbSuffix,
// and other related declarations are not shown here.
func PrintStats() {
	var memStats runtime.MemStats

	runtime.ReadMemStats(&memStats)

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyStatsAlloc, kbSuffix(bToKb(memStats.Alloc)),
		decl.LogKeyStatsHeapAlloc, kbSuffix(bToKb(memStats.HeapAlloc)),
		decl.LogKeyStatsHeapInUse, kbSuffix(bToKb(memStats.HeapInuse)),
		decl.LogKeyStatsHeapIdle, kbSuffix(bToKb(memStats.HeapIdle)),
		decl.LogKeyStatsStackInUse, kbSuffix(bToKb(memStats.StackInuse)),
		decl.LogKeyStatsStackSys, kbSuffix(bToKb(memStats.StackSys)),
		decl.LogKeyStatsSys, kbSuffix(bToKb(memStats.Sys)),
		decl.LogKeyStatsTotalAlloc, kbSuffix(bToKb(memStats.TotalAlloc)),
		decl.LogKeyStatsNumGC, memStats.NumGC,
	)
}

// GetCounterValue returns the value for a prometheus counter.
func GetCounterValue(metric *prometheus.CounterVec, lvs ...string) float64 {
	dtoMetric := &dto.Metric{}

	if err := metric.WithLabelValues(lvs...).Write(dtoMetric); err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

		return 0
	}

	return dtoMetric.Counter.GetValue()
}

// LoadStatsFromRedis loads the prometheus statistics at startup from a Redis server.
func LoadStatsFromRedis() {
	var (
		redisValue float64
		err        error
	)

	util.DebugModule(decl.DbgStats, decl.LogKeyMsg, "Load counter statistics from redis")

	LoginsCounter.Reset()

	// Prometheus redis variables
	redisLoginsCounterKey := config.EnvConfig.RedisPrefix + decl.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.EnvConfig.InstanceName)

	for _, counterType := range []string{decl.LabelSuccess, decl.LabelFailure} {
		if redisValue, err = backend.RedisHandleReplica.HGet(backend.RedisHandleReplica.Context(), redisLoginsCounterKey, counterType).Float64(); err != nil {
			if errors.Is(err, redis.Nil) {
				level.Info(logging.DefaultLogger).Log(decl.LogKeyMsg, "No statistics on Redis server")

				return
			}

			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

			return
		}

		LoginsCounter.WithLabelValues(counterType).Add(redisValue)
	}
}

// SaveStatsToRedis saves the prometheus statistics to a Redis server.
func SaveStatsToRedis() {
	var err error

	util.DebugModule(decl.DbgStats, decl.LogKeyMsg, "Save counter statistics to redis")

	metrics := []Metric{
		{Value: GetCounterValue(LoginsCounter, decl.LabelSuccess), Label: decl.LabelSuccess},
		{Value: GetCounterValue(LoginsCounter, decl.LabelFailure), Label: decl.LabelFailure},
	}

	// Prometheus redis variables
	redisLoginsCounterKey := config.EnvConfig.RedisPrefix + decl.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.EnvConfig.InstanceName)

	for index := range metrics {
		if err = backend.RedisHandle.HSet(backend.RedisHandle.Context(), redisLoginsCounterKey, metrics[index].Label, metrics[index].Value).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

			return
		}
	}
}
