package core

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	// httpRequestsTotalCounter variable declaration that creates a new Prometheus CounterVec with the specified name and help message, and with a "path" label.
	httpRequestsTotalCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nauthilus_http_requests_total",
			Help: "Number of HTTP requests.",
		},
		[]string{"path"})

	// httpResponseTimeSecondsHist variable declaration that creates a new Prometheus HistogramVec with the specified name and help message, and with a "path" label.
	httpResponseTimeSecondsHist = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "nauthilus_http_response_time_seconds",
			Help: "Duration of HTTP requests.",
		},
		[]string{"path"})

	// loginsCounter variable declaration that creates a new Prometheus CounterVec with the specified name and help message, and with a "logins" label.
	loginsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nauthilus_logins_total",
			Help: "Number of failed and successful login attempts.",
		},
		[]string{"logins"})

	// cpuUser variable declaration that creates a new Prometheus Gauge with the specified name and help message.
	cpuUser = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "nauthilus_cpu_usser",
		Help: "CPU user",
	})

	// cpuSystem variable declaration that creates a new Prometheus Gauge with the specified name and help message.
	cpuSystem = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "nauthilus_cpu_system",
		Help: "CPU system",
	})

	// redisReadCounter variable declaration that creates a new Prometheus Counter with the specified name and help message, used to count the total number of Redis read operations.
	redisReadCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nauthilus_redis_read_total",
		Help: "Total number of Redis read operations",
	})

	// redisWriteCounter variable declaration that creates a new Prometheus Counter with the specified name and help message, used to count the total number of Redis write operations.
	redisWriteCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nauthilus_redis_write_total",
		Help: "Total number of Redis write operations",
	})
)

// Metric is a prometheus metric with a value and a label.
type Metric struct {
	Value float64 `redis:"value"`
	Label string  `redis:"label"`
}

//nolint:errcheck,gochecknoinits // Ignore
func init() {
	prometheus.MustRegister(httpRequestsTotalCounter, httpResponseTimeSecondsHist)
	prometheus.MustRegister(redisReadCounter, redisWriteCounter)
	prometheus.MustRegister(loginsCounter)
	prometheus.MustRegister(cpuUser, cpuSystem)
}

// MeasureCPU is a function that continuously measures and sets the CPU usage (utilization) percentages.
//
// This function runs indefinitely in a loop and keeps monitoring the CPU utilization and sets the calculated utilization in 'cpuGauge' variable,
// until an event of cancellation comes from the passed context 'ctx'.
//
// The function uses 'cpu.PercentWithContext' function under the hood which returns the used CPU percentages.
// It waits for one second 'time.Second', during each iteration and ignores (does not calculate) CPU percentages for idle or sleeping processes
// (false value passed as last argument to 'cpu.PercentWithContext' function says to not calculate the idle time).
//
// 'ctx.Done()' is used as a form of cancellation signal, it unblocks when the 'ctx' is cancelled. Once such cancellation event happens, the function
// ends (returns), effectively stopping the CPU measurement.
//
// If there is any error while measuring the CPU usage, it gets logged with level error using 'level.Error' method,
// and the function stops thereafter.
//
// If 'cpu.PercentWithContext' reports CPU usage, only the first measure (percent[0]) is considered (if available).
// If no measure is available, nothing is set in this iteration.
//
// The gauge 'cpuGauge', is used to store the computed CPU usage.
//
// Parameters:
// - ctx (context.Context) : Context to handle cancellation.
//
// Note: This function doesn't return anything.
func MeasureCPU(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(2 * time.Second)

			c, err := cpu.Get()
			if err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

				return
			}

			cpuUser.Set(float64(c.User))
			cpuSystem.Set(float64(c.System))
		}
	}
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
// It uses the util.ByteSize function to convert the memory values in bytes to kilobytes (KB)
// by dividing them by 1024.
// The logging is performed using the DefaultLogger from the logging package.
// Note: The declarations of logging.DefaultLogger, global.LogKeyStatsAlloc, util.ByteSize,
// and other related declarations are not shown here.
func PrintStats() {
	var memStats runtime.MemStats

	runtime.ReadMemStats(&memStats)

	level.Info(logging.DefaultLogger).Log(
		// Heap Stats
		global.LogKeyStatsHeapAlloc, util.ByteSize(memStats.HeapAlloc),
		global.LogKeyStatsHeapInUse, util.ByteSize(memStats.HeapInuse),
		global.LogKeyStatsHeapIdle, util.ByteSize(memStats.HeapIdle),
		global.LogKeyStatsHeapSys, util.ByteSize(memStats.HeapSys),
		global.LogKeyStatsHeapReleased, util.ByteSize(memStats.HeapReleased),
		global.LogKeyStatsMallocs, memStats.Mallocs,
		global.LogKeyStatsFrees, memStats.Frees,

		// Stack Stats
		global.LogKeyStatsStackInUse, util.ByteSize(memStats.StackInuse),
		global.LogKeyStatsStackSys, util.ByteSize(memStats.StackSys),

		// GC Stats
		global.LogKeyStatsGCSys, util.ByteSize(memStats.GCSys),
		global.LogKeyStatsNumGC, memStats.NumGC,

		// General Stats
		global.LogKeyStatsAlloc, util.ByteSize(memStats.Alloc),
		global.LogKeyStatsSys, util.ByteSize(memStats.Sys),
		global.LogKeyStatsTotalAlloc, util.ByteSize(memStats.TotalAlloc),
	)
}

// getCounterValue returns the value for a prometheus counter.
func getCounterValue(metric *prometheus.CounterVec, lvs ...string) float64 {
	dtoMetric := &dto.Metric{}

	if err := metric.WithLabelValues(lvs...).Write(dtoMetric); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

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

	util.DebugModule(global.DbgStats, global.LogKeyMsg, "Load counter statistics from redis")

	loginsCounter.Reset()

	// Prometheus redis variables
	redisLoginsCounterKey := config.EnvConfig.RedisPrefix + global.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.EnvConfig.InstanceName)

	for _, counterType := range []string{global.LabelSuccess, global.LabelFailure} {
		if redisValue, err = backend.RedisHandleReplica.HGet(backend.RedisHandleReplica.Context(), redisLoginsCounterKey, counterType).Float64(); err != nil {
			if errors.Is(err, redis.Nil) {
				level.Info(logging.DefaultLogger).Log(global.LogKeyMsg, "No statistics on Redis server")

				return
			}

			level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

			return
		}

		loginsCounter.WithLabelValues(counterType).Add(redisValue)
	}
}

// SaveStatsToRedis saves the prometheus statistics to a Redis server.
func SaveStatsToRedis() {
	var err error

	util.DebugModule(global.DbgStats, global.LogKeyMsg, "Save counter statistics to redis")

	metrics := []Metric{
		{Value: getCounterValue(loginsCounter, global.LabelSuccess), Label: global.LabelSuccess},
		{Value: getCounterValue(loginsCounter, global.LabelFailure), Label: global.LabelFailure},
	}

	// Prometheus redis variables
	redisLoginsCounterKey := config.EnvConfig.RedisPrefix + global.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.EnvConfig.InstanceName)

	for index := range metrics {
		if err = backend.RedisHandle.HSet(backend.RedisHandle.Context(), redisLoginsCounterKey, metrics[index].Label, metrics[index].Value).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

			return
		}

		redisWriteCounter.Inc()
	}
}
