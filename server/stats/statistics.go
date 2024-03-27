package stats

import (
	"context"
	"runtime"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HttpRequestsTotalCounter variable declaration that creates a new Prometheus CounterVec with the specified name and help message, and with a "path" label.
	HttpRequestsTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Number of HTTP requests.",
		},
		[]string{"path"})

	// HttpResponseTimeSecondsHist variable declaration that creates a new Prometheus HistogramVec with the specified name and help message, and with a "path" label.
	HttpResponseTimeSecondsHist = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_response_time_seconds",
			Help: "Duration of HTTP requests.",
		},
		[]string{"path"})

	// LoginsCounter variable declaration that creates a new Prometheus CounterVec with the specified name and help message, and with a "logins" label.
	LoginsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "logins_total",
			Help: "Number of failed and successful login attempts.",
		},
		[]string{"logins"})

	// RedisReadCounter variable declaration that creates a new Prometheus Counter with the specified name and help message, used to count the total number of Redis read operations.
	RedisReadCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "redis_read_total",
		Help: "Total number of Redis read operations",
	})

	// RedisWriteCounter variable declaration that creates a new Prometheus Counter with the specified name and help message, used to count the total number of Redis write operations.
	RedisWriteCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "redis_write_total",
		Help: "Total number of Redis write operations",
	})

	// FunctionDuration variable declaration that creates a new Prometheus SummaryVec with the specified name and help message, and with "service" and "method" labels.
	FunctionDuration = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "function_duration_seconds",
		Help: "Time spent in function",
	}, []string{"service", "task"})

	// CacheHits variable declaration that creates a new Prometheus Counter with the specified name and help message, which counts the total number of cache hits.
	CacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cache_hits_total",
		Help: "The total number of cache hits",
	})

	// CacheMisses variable declaration that creates a new Prometheus Counter with the specified name and help message, representing the total number of cache misses.
	CacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cache_misses_total",
		Help: "The total number of cache misses",
	})

	RedisHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_pool_hits_total",
		Help: "The total number of times a free connection was found in the pool",
	}, []string{"type"})

	RedisMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_pool_misses_total",
		Help: "The total number of times a free connection was NOT found in the pool",
	}, []string{"type"})

	RedisTimeouts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_pool_timeouts_total",
		Help: "The total number of times a wait timeout occurred",
	}, []string{"type"})

	RedisTotalConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_total_connections",
		Help: "The total number of connections in the pool",
	}, []string{"type"})

	RedisIdleConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_idle_connections",
		Help: "The total number of idle connections in the pool",
	}, []string{"type"})

	RedisStaleConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_stale_connections",
		Help: "The total number of stale connections removed from the pool",
	}, []string{"type"})

	// cpuUserUsage variable declaration that creates a new Prometheus Gauge with the specified name and help message, to measure CPU user usage in percent.
	cpuUserUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_user_usage_percent",
		Help: "CPU user usage in percent",
	})

	// cpuSystemUsage variable declaration that creates a new Prometheus Gauge with the specified name and help message, representing the CPU system usage in percent.
	cpuSystemUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_system_usage_percent",
		Help: "CPU system usage in percent",
	})

	// cpuIdleUsage variable declaration that creates a new Prometheus Gauge with the specified name and help message, representing the CPU idle usage in percent.
	cpuIdleUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_idle_usage_percent",
		Help: "CPU idle usage in percent",
	})
)

var oldCpu cpu.Stats

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

			newCpu, err := cpu.Get()
			if err != nil {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

				return
			}

			total := float64(newCpu.Total - oldCpu.Total)

			cpuUserUsage.Set(float64(newCpu.User-oldCpu.User) / total * 100)
			cpuSystemUsage.Set(float64(newCpu.System-oldCpu.System) / total * 100)
			cpuIdleUsage.Set(float64(newCpu.Idle-oldCpu.Idle) / total * 100)

			oldCpu = *newCpu
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
