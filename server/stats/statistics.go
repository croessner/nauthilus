// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package stats

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// LastReloadTime records the timestamp of the last successful configuration reload.
	LastReloadTime time.Time

	// ReloadMutex is used to coordinate access to shared resources during configuration reload operations.
	ReloadMutex sync.RWMutex
)

// init initializes metrics for last reload timestamp, application start timestamp, and current server connections.
func init() {
	LastReloadTime = time.Now()

	promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "last_reload_timestamp",
			Help: "Unix timestamp of the last reload",
		},
		func() float64 {
			ReloadMutex.RLock()

			defer ReloadMutex.RUnlock()

			return float64(LastReloadTime.UnixMilli())
		},
	)

	startTime := time.Now()

	promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "start_timestamp",
			Help: "Unix timestamp of the application start",
		},
		func() float64 {
			return float64(startTime.UnixMilli())
		},
	)
}

var (
	// InstanceInfo provides metrics about the version information using a GaugeVec with a "version" label.
	InstanceInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nauthilus_version_info",
			Help: "Information about the version.",
		}, []string{"instance_name", "version"})

	// CurrentRequests is a Prometheus Gauge metric that tracks the number of current requests being processed by the server.
	CurrentRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "server_concurrent_requests",
			Help: "Number of current requests.",
		})

	// HttpRequestsTotalCounter variable declaration that creates a new Prometheus CounterVec with the specified name and help message, and with a "path" label.
	HttpRequestsTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Number of HTTP requests.",
		}, []string{"path"})

	// HttpResponseTimeSecondsHist variable declaration that creates a new Prometheus HistogramVec with the specified name and help message, and with a "path" label.
	HttpResponseTimeSecondsHist = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_response_time_seconds",
			Help: "Duration of HTTP requests.",
		}, []string{"path"})

	// LoginsCounter variable declaration that creates a new Prometheus CounterVec with the specified name and help message, and with a "logins" label.
	LoginsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "logins_total",
			Help: "Number of failed and successful login attempts.",
		}, []string{"logins"})

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
	FunctionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "function_duration_seconds",
		Help:    "Time spent in function",
		Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
	}, []string{"service", "task"})

	// RBLDuration tracks the duration of DNS RBL (Real-time Blackhole List) lookups.
	RBLDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "rbl_duration_seconds",
		Help:    "Time spent for RBL lookups",
		Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
	}, []string{"rbl"})

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

	// RedisHits gauges the total number of times a free connection was found in the pool, categorized by type.
	RedisHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_connection_hits_total",
		Help: "The total number of times a free connection was found in the pool",
	}, []string{definitions.ReisPromPoolName})

	// RedisMisses is a gauge vector that counts the total number of times a free connection was NOT found in the pool.
	RedisMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_connection_misses_total",
		Help: "The total number of times a free connection was NOT found in the pool",
	}, []string{definitions.ReisPromPoolName})

	// RedisTimeouts tracks the total number of times a wait timeout occurred in Redis connections.
	RedisTimeouts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_connection_timeouts_total",
		Help: "The total number of times a wait timeout occurred",
	}, []string{definitions.ReisPromPoolName})

	// RedisTotalConns tracks the total number of connections in the Redis pool, labeled by connection type.
	RedisTotalConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_total_connections",
		Help: "The total number of connections in the pool",
	}, []string{definitions.ReisPromPoolName})

	// RedisIdleConns is a Prometheus gauge that tracks the total number of idle connections in the Redis pool, labeled by "type".
	RedisIdleConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_idle_connections",
		Help: "The total number of idle connections in the pool",
	}, []string{definitions.ReisPromPoolName})

	// RedisStaleConns is a Prometheus metric that tracks the total number of stale connections removed from the Redis pool.
	RedisStaleConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_stale_connections",
		Help: "The total number of stale connections removed from the pool",
	}, []string{definitions.ReisPromPoolName})

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

	// BruteForceRejected tracks the total number of brute force rejected attempts, labeled by the respective bucket.
	BruteForceRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bruteforce_rejected_total",
		Help: "The total number of brute force rejected attempts",
	}, []string{"bucket"})

	// BruteForceHits is a prometheus counter that tracks the total number of brute force hits before rejection, categorized by bucket.
	BruteForceHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "brutefore_hits_total",
		Help: "The total number of brute force hits before rejection",
	}, []string{"bucket"})

	// RejectedProtocols tracks the total number of rejects per protocol.
	RejectedProtocols = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rejected_protocols_total",
		Help: "The total number of rejects per protocol",
	}, []string{"protocol"})

	// AcceptedProtocols counts the total number of acceptances per protocol.
	AcceptedProtocols = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "accepted_protocols_total",
		Help: "The total number of acceptances per protocol",
	}, []string{"protocol"})

	// BackendServerStatus provides a gauge metric representing the status of monitored backend servers categorized by server_status.
	BackendServerStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "backend_servers_status",
		Help: "Status of monitored backend servers",
	}, []string{"server_status"})

	// LDAPPoolStatus provides a gauge metric representing the number of actively used connections in the LDAP pool.
	LDAPPoolStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ldap_pool_connections_total",
		Help: "Number of actively used connections in the LDAP pool",
	}, []string{"pool"})

	// LDAPOpenConnections counts the number of currently opened connections in the LDAP pool.
	LDAPOpenConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ldap_pool_open_connections_total",
		Help: "Number of currently opened connections",
	}, []string{"pool"})

	// LDAPStaleConnections counts the number of currently staled connections in the LDAP pool which need closing.
	LDAPStaleConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ldap_pool_stale_connections_total",
		Help: "Number of currently staled connections",
	}, []string{"pool"})

	// LDAPPoolSize is a gauge metric that represents the size of the LDAP connection pool.
	LDAPPoolSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ldap_pool_size",
		Help: "Size of LDAP pool",
	}, []string{"pool"})

	// LDAPIdlePoolSize provides the number of idle connections in the LDAP pool, monitored as a Prometheus gauge metric.
	LDAPIdlePoolSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ldap_idle_pool_size",
		Help: "Size of idle LDAP pool",
	}, []string{"pool"})

	// RBLRejected counts the total number of rejected RBL requests, categorized by the RBL that caused the rejection.
	RBLRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rbl_rejected_total",
		Help: "The total number of rejected RBL requests",
	}, []string{"rbl"})

	// GenericConnections tracks the current number of established connections to a target.
	GenericConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "generic_connections",
			Help: "Current number of established connections to a target",
		},
		[]string{"description", "target", "direction"},
	)
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
				level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

				return
			}

			total := float64(newCpu.Total - oldCpu.Total)

			setNewStats(&oldCpu, newCpu, total)

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
// The logging is performed using the Logger from the logging package.
// Note: The declarations of log.Logger, definitions.LogKeyStatsAlloc, util.ByteSize,
// and other related declarations are not shown here.
func PrintStats() {
	var memStats runtime.MemStats

	runtime.ReadMemStats(&memStats)

	level.Info(log.Logger).Log(
		// Heap Stats
		definitions.LogKeyStatsHeapAlloc, util.ByteSize(memStats.HeapAlloc),
		definitions.LogKeyStatsHeapInUse, util.ByteSize(memStats.HeapInuse),
		definitions.LogKeyStatsHeapIdle, util.ByteSize(memStats.HeapIdle),
		definitions.LogKeyStatsHeapSys, util.ByteSize(memStats.HeapSys),
		definitions.LogKeyStatsHeapReleased, util.ByteSize(memStats.HeapReleased),
		definitions.LogKeyStatsMallocs, memStats.Mallocs,
		definitions.LogKeyStatsFrees, memStats.Frees,

		// Stack Stats
		definitions.LogKeyStatsStackInUse, util.ByteSize(memStats.StackInuse),
		definitions.LogKeyStatsStackSys, util.ByteSize(memStats.StackSys),

		// GC Stats
		definitions.LogKeyStatsGCSys, util.ByteSize(memStats.GCSys),
		definitions.LogKeyStatsNumGC, memStats.NumGC,

		// General Stats
		definitions.LogKeyStatsAlloc, util.ByteSize(memStats.Alloc),
		definitions.LogKeyStatsSys, util.ByteSize(memStats.Sys),
		definitions.LogKeyStatsTotalAlloc, util.ByteSize(memStats.TotalAlloc),
	)
}

// HavePrometheusLabelEnabled returns true if the specified Prometheus label is enabled in the server configuration, otherwise false.
func HavePrometheusLabelEnabled(prometheusLabel string) bool {
	if !config.GetFile().GetServer().PrometheusTimer.Enabled {
		return false
	}

	for _, label := range config.GetFile().GetServer().PrometheusTimer.Labels {
		if label != prometheusLabel {
			continue
		}

		return true
	}

	return false
}

// PrometheusTimer is a function that takes a prometheus label (promLabel) and a prometheus observer (prometheusObserver) as arguments.
// The function first checks if the Prometheus Timer is enabled in the server configuration (config.GetFile().GetServer().PrometheusTimer.Enabled).
// If the Prometheus Timer is not enabled, it returns an empty function.
// If enabled, it iterates over the labels of the Prometheus Timer specified in the server configuration (config.GetFile().GetServer().PrometheusTimer.Labels).
// For each label, it checks if it matches with the provided promLabel. If there is a match, it creates a new timer (timer)
// with the given prometheus observer and returns a function that observes the duration of the timer when called.
// If there is no match, it returns an empty function.
// This function is used to measure the time duration using Prometheus, a powerful time-series monitoring service.
func PrometheusTimer(serviceName string, taskName string) func() {
	if HavePrometheusLabelEnabled(serviceName) {
		timer := prometheus.NewTimer(FunctionDuration.WithLabelValues(serviceName, taskName))

		return func() {
			timer.ObserveDuration()
		}
	}

	return nil
}

// UpdateGenericConnections reads from GenericConnectionChan and updates the GenericConnections metric for each connection.
func UpdateGenericConnections() {
	for {
		conn, openConn := <-connmgr.GenericConnectionChan
		if !openConn {
			break
		}

		GenericConnections.WithLabelValues(conn.Description, conn.Target, conn.Direction).Set(float64(conn.Count))
	}
}
