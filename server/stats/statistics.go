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
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib/connmgr"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/mackerelio/go-osstat/cpu"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	reloader     Reloader
	initReloader sync.Once
)

// Reloader defines an interface for components that support reinitialization or refreshing their state or configuration.
type Reloader interface {
	// Reload triggers the reinitialization or refresh of the implementing component, reloading its state or configuration.
	Reload()

	// GetLastReload retrieves the timestamp of the most recent reload operation as a time.Time value.
	GetLastReload() time.Time

	// GetLastReloadFloat64 returns the last reload timestamp as a float64 representing milliseconds since the Unix epoch.
	GetLastReloadFloat64() float64
}

// ReloaderImp is a thread-safe implementation of the Reloader interface, managing state reinitialization timestamps.
type ReloaderImp struct {
	lastReloadTime time.Time
	mu             sync.RWMutex
}

// Reload updates the lastReloadTime with the current timestamp while ensuring thread-safe access via a mutex lock.
func (r *ReloaderImp) Reload() {
	r.mu.Lock()

	defer r.mu.Unlock()

	r.lastReloadTime = time.Now()
}

// GetLastReload returns the timestamp of the last reload action performed by the ReloaderImp instance.
func (r *ReloaderImp) GetLastReload() time.Time {
	r.mu.RLock()

	defer r.mu.RUnlock()

	return r.lastReloadTime
}

// GetLastReloadFloat64 returns the last reload timestamp as a float64 representing milliseconds since the Unix epoch.
func (r *ReloaderImp) GetLastReloadFloat64() float64 {
	return float64(r.GetLastReload().UnixMilli())
}

var _ Reloader = &ReloaderImp{}

// NewReloader creates and returns a new instance of a struct implementing the Reloader interface.
func NewReloader() Reloader {
	return &ReloaderImp{}
}

// GetReloader returns a singleton instance of Reloader, initializing it if not already created.
func GetReloader() Reloader {
	initReloader.Do(func() {
		if reloader == nil {
			reloader = NewReloader()
		}
	})

	return reloader
}

// init initializes metrics for last reload timestamp, application start timestamp, and current server connections.
func init() {
	reloader = GetReloader()

	reloader.Reload()

	promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "last_reload_timestamp",
			Help: "Unix timestamp of the last reload",
		},
		reloader.GetLastReloadFloat64,
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
	metrics     Metrics
	initMetrics sync.Once
)

const (
	metricBackendLabel          = "backend"
	metricBucketLabel           = "bucket"
	metricClientIDLabel         = "client_id"
	metricCodeLabel             = "code"
	metricDescriptionLabel      = "description"
	metricDimensionLabel        = "dimension"
	metricDirectionLabel        = "direction"
	metricEventLabel            = "event"
	metricFromLabel             = "from"
	metricGrantTypeLabel        = "grant_type"
	metricInstanceNameLabel     = "instance_name"
	metricKeyLabel              = "key"
	metricKindLabel             = "kind"
	metricLoginsLabel           = "logins"
	metricMethodLabel           = "method"
	metricOpLabel               = "op"
	metricPathLabel             = "path"
	metricPhaseLabel            = "phase"
	metricPoolLabel             = "pool"
	metricPoolNameLabel         = "pool_name"
	metricProtocolLabel         = "protocol"
	metricResourceLabel         = "resource"
	metricRBLLabel              = "rbl"
	metricServerStatusLabel     = "server_status"
	metricServiceLabel          = "service"
	metricStatusLabel           = "status"
	metricTargetLabel           = "target"
	metricTaskLabel             = "task"
	metricToLabel               = "to"
	metricTypeLabel             = "type"
	metricVersionLabel          = "version"
	pluginCallMetricResultLabel = "result"
)

var pluginCallMetricLabels = []string{"module", "component", "extension_point", metricMethodLabel, pluginCallMetricResultLabel}

// Metrics ist ein Interface, das alle Getter-Methoden für Metriken definiert.
type Metrics interface {
	// GetInstanceInfo provides metrics about the version information using a GaugeVec with a "version" label.
	GetInstanceInfo() *prometheus.GaugeVec

	// GetLdapCacheHitsTotal returns a counter vector tracking the total number of LDAP cache hits with specified labels.
	GetLdapCacheHitsTotal() *prometheus.CounterVec

	// GetLdapAuthRateLimitedTotal returns a CounterVec for rate-limited auth requests.
	GetLdapAuthRateLimitedTotal() *prometheus.CounterVec

	// GetLdapCacheMissesTotal returns a Prometheus CounterVec tracking the total number of LDAP cache misses.
	GetLdapCacheMissesTotal() *prometheus.CounterVec

	// GetLdapCacheEntries provides a metric gauge vector for tracking the current number of LDAP cache entries.
	GetLdapCacheEntries() *prometheus.GaugeVec

	// GetLdapCacheEvictionsTotal returns a CounterVec metric tracking the total number of LDAP cache evictions.
	GetLdapCacheEvictionsTotal() *prometheus.CounterVec

	// GetLdapErrorsTotal returns a CounterVec for LDAP errors with labels {pool, op, code}.
	GetLdapErrorsTotal() *prometheus.CounterVec

	// GetLdapRetriesTotal returns a CounterVec for LDAP retries with labels {pool, op}.
	GetLdapRetriesTotal() *prometheus.CounterVec

	// GetCurrentRequests is a Prometheus Gauge metric that tracks the number of current requests being processed by the server.
	GetCurrentRequests() prometheus.Gauge

	// GetHTTPRequestsTotal returns a Prometheus CounterVec that tracks the total HTTP requests processed, with a "path" label.
	GetHTTPRequestsTotal() *prometheus.CounterVec

	// GetHTTPResponseTimeSeconds provides a Prometheus HistogramVec that tracks HTTP response times, with a "path" label.
	GetHTTPResponseTimeSeconds() *prometheus.HistogramVec

	// GetLoginsCounter tracks the total number of login attempts (failed and successful) as a Prometheus CounterVec.
	GetLoginsCounter() *prometheus.CounterVec

	// GetRedisReadCounter counts the total number of Redis read operations.
	GetRedisReadCounter() prometheus.Counter

	// GetRedisWriteCounter counts the total number of Redis write operations.
	GetRedisWriteCounter() prometheus.Counter

	// GetFunctionDuration tracks the time spent in functions as a Prometheus HistogramVec, with "service" and "task" labels.
	GetFunctionDuration() *prometheus.HistogramVec

	// GetRblDuration tracks the duration of DNS RBL lookups as a Prometheus HistogramVec.
	GetRblDuration() *prometheus.HistogramVec

	// GetCacheHits counts the total number of cache hits as a Prometheus Counter.
	GetCacheHits() prometheus.Counter

	// GetCacheMisses counts the total number of cache misses as a Prometheus Counter.
	GetCacheMisses() prometheus.Counter

	// GetRedisHits tracks the total number of times a free connection was found in the Redis pool as a Prometheus CounterVec.
	GetRedisHits() *prometheus.CounterVec

	// GetRedisMisses tracks the total number of times a free connection was NOT found in the Redis pool as a Prometheus CounterVec.
	GetRedisMisses() *prometheus.CounterVec

	// GetRedisTimeouts tracks the total number of wait timeouts for Redis connections as a Prometheus CounterVec.
	GetRedisTimeouts() *prometheus.CounterVec

	// GetRedisTotalConns tracks the total number of Redis connections in the pool as a Prometheus GaugeVec.
	GetRedisTotalConns() *prometheus.GaugeVec

	// GetRedisIdleConns tracks the total number of idle Redis connections in the pool as a Prometheus GaugeVec.
	GetRedisIdleConns() *prometheus.GaugeVec

	// GetRedisStaleConns tracks the total number of stale connections removed from the Redis pool as a Prometheus GaugeVec.
	GetRedisStaleConns() *prometheus.GaugeVec

	// GetBruteForceRejected tracks the total number of brute force attempts rejected, categorized by bucket, as a Prometheus CounterVec.
	GetBruteForceRejected() *prometheus.CounterVec

	// GetBruteForceHits counts the total number of brute force hits before being rejected as a Prometheus CounterVec.
	GetBruteForceHits() *prometheus.CounterVec

	// GetRejectedProtocols tracks the total number of protocol rejection attempts as a Prometheus CounterVec, categorized by protocol.
	GetRejectedProtocols() *prometheus.CounterVec

	// GetAcceptedProtocols counts the total number of protocol acceptance attempts as a Prometheus CounterVec, categorized by protocol.
	GetAcceptedProtocols() *prometheus.CounterVec

	// GetBackendServerStatus tracks the status of monitored backend servers as a Prometheus GaugeVec, categorized by server status.
	GetBackendServerStatus() *prometheus.GaugeVec

	// GetLdapPoolStatus provides metrics about actively used connections in the LDAP connection pool as a Prometheus GaugeVec.
	GetLdapPoolStatus() *prometheus.GaugeVec

	// GetLdapOpenConnections tracks the number of currently open LDAP connections as a Prometheus GaugeVec.
	GetLdapOpenConnections() *prometheus.GaugeVec

	// GetLdapStaleConnections tracks the number of stale LDAP connections requiring closure as a Prometheus GaugeVec.
	GetLdapStaleConnections() *prometheus.GaugeVec

	// GetLdapPoolSize provides the size of the LDAP connection pool as a Prometheus GaugeVec.
	GetLdapPoolSize() *prometheus.GaugeVec

	// GetLdapIdlePoolSize tracks the number of idle LDAP pool connections as a Prometheus GaugeVec.
	GetLdapIdlePoolSize() *prometheus.GaugeVec

	// GetLdapQueueDepth tracks the current depth of LDAP queues (lookup/auth) per pool as a Prometheus GaugeVec.
	GetLdapQueueDepth() *prometheus.GaugeVec

	// GetLdapQueueWaitSeconds tracks the time spent waiting in LDAP queues (enqueue to dequeue) as a Prometheus HistogramVec.
	GetLdapQueueWaitSeconds() *prometheus.HistogramVec

	// GetLdapQueueDroppedTotal counts dropped LDAP requests due to queue overflow as a Prometheus CounterVec.
	GetLdapQueueDroppedTotal() *prometheus.CounterVec

	// GetLdapBreakerState exposes circuit breaker state per LDAP target: 0=closed, 1=open, 2=half-open.
	GetLdapBreakerState() *prometheus.GaugeVec

	// GetLdapTargetHealth exposes 0/1 health status per LDAP target.
	GetLdapTargetHealth() *prometheus.GaugeVec

	// GetLdapTargetInflight exposes current in-flight requests per LDAP target.
	GetLdapTargetInflight() *prometheus.GaugeVec

	// GetLuaQueueDepth returns a Prometheus GaugeVec metric tracking the depth of the Lua request queue per backend.
	GetLuaQueueDepth() *prometheus.GaugeVec

	// GetLuaQueueWaitSeconds returns a histogram vector tracking wait times for requests in the Lua script execution queue.
	GetLuaQueueWaitSeconds() *prometheus.HistogramVec

	// GetLuaQueueDroppedTotal returns a CounterVec metric that tracks the total number of Lua queue requests dropped.
	GetLuaQueueDroppedTotal() *prometheus.CounterVec

	// GetLuaVMInUse returns a prometheus.GaugeVec tracking the current number of Lua virtual machines in use.
	GetLuaVMInUse() *prometheus.GaugeVec

	// GetLuaVMReplacedTotal returns a prometheus.CounterVec that tracks the total count of replaced Lua virtual machines.
	GetLuaVMReplacedTotal() *prometheus.CounterVec

	// GetRblRejected tracks the total number of DNS RBL request rejections as a Prometheus CounterVec, categorized by RBL.
	GetRblRejected() *prometheus.CounterVec

	// GetGenericConnections tracks the current number of established generic connections as a Prometheus GaugeVec, categorized by description, target, and direction.
	GetGenericConnections() *prometheus.GaugeVec

	// GetBruteForceEvalSeconds measures end-to-end latency of the brute-force evaluation path.
	GetBruteForceEvalSeconds() prometheus.Histogram

	// GetBruteForceCacheHitsTotal counts in-process cache/burst gating hits within the brute-force path, labeled by kind.
	GetBruteForceCacheHitsTotal() *prometheus.CounterVec

	// GetBruteForceRulesMatchedTotal counts how often a brute-force rule matched (pre or final).
	GetBruteForceRulesMatchedTotal() prometheus.Counter

	// GetRedisRoundtripsTotal counts Redis roundtrips attributable to the brute-force path, labeled by kind.
	GetRedisRoundtripsTotal() *prometheus.CounterVec

	// GetIdpLoginsTotal tracks the total number of IDP logins.
	GetIdpLoginsTotal() *prometheus.CounterVec

	// GetIdpTokensIssuedTotal tracks the total number of IDP tokens issued.
	GetIdpTokensIssuedTotal() *prometheus.CounterVec

	// GetIdpConsentTotal tracks the total number of IDP consent operations.
	GetIdpConsentTotal() *prometheus.CounterVec

	// GetIdpMfaOperationsTotal tracks the total number of IDP MFA operations.
	GetIdpMfaOperationsTotal() *prometheus.CounterVec

	// GetAuthFSMTransitionsTotal tracks auth FSM transitions labeled by from/event/to.
	GetAuthFSMTransitionsTotal() *prometheus.CounterVec

	// GetPluginCallsTotal tracks host-invoked native plugin calls with bounded component labels.
	GetPluginCallsTotal() *prometheus.CounterVec

	// GetPluginCallDurationSeconds tracks native plugin call duration with bounded component labels.
	GetPluginCallDurationSeconds() *prometheus.HistogramVec
}

type metricsImpl struct {
	instanceInfo              *prometheus.GaugeVec
	currentRequests           prometheus.Gauge
	httpRequestsTotal         *prometheus.CounterVec
	httpResponseTimeSeconds   *prometheus.HistogramVec
	loginsCounter             *prometheus.CounterVec
	redisReadCounter          prometheus.Counter
	redisWriteCounter         prometheus.Counter
	functionDuration          *prometheus.HistogramVec
	rblDuration               *prometheus.HistogramVec
	cacheHits                 prometheus.Counter
	cacheMisses               prometheus.Counter
	redisHits                 *prometheus.CounterVec
	redisMisses               *prometheus.CounterVec
	redisTimeouts             *prometheus.CounterVec
	redisTotalConns           *prometheus.GaugeVec
	redisIdleConns            *prometheus.GaugeVec
	redisStaleConns           *prometheus.GaugeVec
	bruteForceRejected        *prometheus.CounterVec
	bruteForceHits            *prometheus.CounterVec
	rejectedProtocols         *prometheus.CounterVec
	acceptedProtocols         *prometheus.CounterVec
	backendServerStatus       *prometheus.GaugeVec
	ldapPoolStatus            *prometheus.GaugeVec
	ldapOpenConnections       *prometheus.GaugeVec
	ldapStaleConnections      *prometheus.GaugeVec
	ldapPoolSize              *prometheus.GaugeVec
	ldapIdlePoolSize          *prometheus.GaugeVec
	ldapQueueDepth            *prometheus.GaugeVec
	ldapQueueWaitSeconds      *prometheus.HistogramVec
	ldapQueueDroppedTotal     *prometheus.CounterVec
	ldapBreakerState          *prometheus.GaugeVec
	ldapTargetHealth          *prometheus.GaugeVec
	ldapTargetInflight        *prometheus.GaugeVec
	ldapCacheHitsTotal        *prometheus.CounterVec
	ldapCacheMissesTotal      *prometheus.CounterVec
	ldapCacheEntries          *prometheus.GaugeVec
	ldapCacheEvictionsTotal   *prometheus.CounterVec
	ldapErrorsTotal           *prometheus.CounterVec
	ldapRetriesTotal          *prometheus.CounterVec
	ldapAuthRateLimitedTotal  *prometheus.CounterVec
	luaQueueDepth             *prometheus.GaugeVec
	luaQueueWaitSeconds       *prometheus.HistogramVec
	luaQueueDroppedTotal      *prometheus.CounterVec
	luaVMInUse                *prometheus.GaugeVec
	luaVMReplacedTotal        *prometheus.CounterVec
	rblRejected               *prometheus.CounterVec
	genericConnections        *prometheus.GaugeVec
	bruteForceEvalSeconds     prometheus.Histogram
	bruteForcePhaseSeconds    *prometheus.HistogramVec
	bruteForceCacheHitsTotal  *prometheus.CounterVec
	bruteForceRulesMatchedTot prometheus.Counter
	redisRoundtripsTotal      *prometheus.CounterVec
	idpLoginsTotal            *prometheus.CounterVec
	idpTokensIssuedTotal      *prometheus.CounterVec
	idpConsentTotal           *prometheus.CounterVec
	idpMfaOperationsTotal     *prometheus.CounterVec
	authFSMTransitionsTotal   *prometheus.CounterVec
	pluginCallsTotal          *prometheus.CounterVec
	pluginCallDurationSeconds *prometheus.HistogramVec
}

// GetInstanceInfo returns the instanceInfo field.
func (m *metricsImpl) GetInstanceInfo() *prometheus.GaugeVec {
	return m.instanceInfo
}

// GetCurrentRequests returns the currentRequests field.
func (m *metricsImpl) GetCurrentRequests() prometheus.Gauge {
	return m.currentRequests
}

// GetHTTPRequestsTotal returns the httpRequestsTotal field.
func (m *metricsImpl) GetHTTPRequestsTotal() *prometheus.CounterVec {
	return m.httpRequestsTotal
}

// GetHTTPResponseTimeSeconds returns the httpResponseTimeSeconds field.
func (m *metricsImpl) GetHTTPResponseTimeSeconds() *prometheus.HistogramVec {
	return m.httpResponseTimeSeconds
}

// GetLoginsCounter returns the loginsCounter field.
func (m *metricsImpl) GetLoginsCounter() *prometheus.CounterVec {
	return m.loginsCounter
}

// GetRedisReadCounter returns the redisReadCounter field.
func (m *metricsImpl) GetRedisReadCounter() prometheus.Counter {
	return m.redisReadCounter
}

// GetRedisWriteCounter returns the redisWriteCounter field.
func (m *metricsImpl) GetRedisWriteCounter() prometheus.Counter {
	return m.redisWriteCounter
}

// GetFunctionDuration returns the functionDuration field.
func (m *metricsImpl) GetFunctionDuration() *prometheus.HistogramVec {
	return m.functionDuration
}

// GetRblDuration returns the rblDuration field.
func (m *metricsImpl) GetRblDuration() *prometheus.HistogramVec {
	return m.rblDuration
}

// GetCacheHits returns the cacheHits field.
func (m *metricsImpl) GetCacheHits() prometheus.Counter {
	return m.cacheHits
}

// GetCacheMisses returns the cacheMisses field.
func (m *metricsImpl) GetCacheMisses() prometheus.Counter {
	return m.cacheMisses
}

// GetRedisHits returns the redisHits field.
func (m *metricsImpl) GetRedisHits() *prometheus.CounterVec {
	return m.redisHits
}

// GetRedisMisses returns the redisMisses field.
func (m *metricsImpl) GetRedisMisses() *prometheus.CounterVec {
	return m.redisMisses
}

// GetRedisTimeouts returns the redisTimeouts field.
func (m *metricsImpl) GetRedisTimeouts() *prometheus.CounterVec {
	return m.redisTimeouts
}

// GetRedisTotalConns returns the redisTotalConns field.
func (m *metricsImpl) GetRedisTotalConns() *prometheus.GaugeVec {
	return m.redisTotalConns
}

// GetRedisIdleConns returns the redisIdleConns field.
func (m *metricsImpl) GetRedisIdleConns() *prometheus.GaugeVec {
	return m.redisIdleConns
}

// GetRedisStaleConns returns the redisStaleConns field.
func (m *metricsImpl) GetRedisStaleConns() *prometheus.GaugeVec {
	return m.redisStaleConns
}

// GetBruteForceRejected returns the bruteForceRejected field.
func (m *metricsImpl) GetBruteForceRejected() *prometheus.CounterVec {
	return m.bruteForceRejected
}

// GetBruteForceHits returns the bruteForceHits field.
func (m *metricsImpl) GetBruteForceHits() *prometheus.CounterVec {
	return m.bruteForceHits
}

// GetRejectedProtocols returns the rejectedProtocols field.
func (m *metricsImpl) GetRejectedProtocols() *prometheus.CounterVec {
	return m.rejectedProtocols
}

// GetAcceptedProtocols returns the acceptedProtocols field.
func (m *metricsImpl) GetAcceptedProtocols() *prometheus.CounterVec {
	return m.acceptedProtocols
}

// GetBackendServerStatus returns the backendServerStatus field.
func (m *metricsImpl) GetBackendServerStatus() *prometheus.GaugeVec {
	return m.backendServerStatus
}

// GetLdapPoolStatus returns the ldapPoolStatus field.
func (m *metricsImpl) GetLdapPoolStatus() *prometheus.GaugeVec {
	return m.ldapPoolStatus
}

// GetLdapOpenConnections returns the ldapOpenConnections field.
func (m *metricsImpl) GetLdapOpenConnections() *prometheus.GaugeVec {
	return m.ldapOpenConnections
}

// GetLdapStaleConnections returns the ldapStaleConnections field.
func (m *metricsImpl) GetLdapStaleConnections() *prometheus.GaugeVec {
	return m.ldapStaleConnections
}

// GetLdapPoolSize returns the ldapPoolSize field.
func (m *metricsImpl) GetLdapPoolSize() *prometheus.GaugeVec {
	return m.ldapPoolSize
}

// GetLdapIdlePoolSize returns the ldapIdlePoolSize field.
func (m *metricsImpl) GetLdapIdlePoolSize() *prometheus.GaugeVec {
	return m.ldapIdlePoolSize
}

// GetLdapQueueDepth returns the ldapQueueDepth field.
func (m *metricsImpl) GetLdapQueueDepth() *prometheus.GaugeVec {
	return m.ldapQueueDepth
}

// GetLdapQueueWaitSeconds returns the ldapQueueWaitSeconds field.
func (m *metricsImpl) GetLdapQueueWaitSeconds() *prometheus.HistogramVec {
	return m.ldapQueueWaitSeconds
}

// GetLdapQueueDroppedTotal returns the ldapQueueDroppedTotal field.
func (m *metricsImpl) GetLdapQueueDroppedTotal() *prometheus.CounterVec {
	return m.ldapQueueDroppedTotal
}

// GetRblRejected returns the rblRejected field.
func (m *metricsImpl) GetRblRejected() *prometheus.CounterVec {
	return m.rblRejected
}

// GetGenericConnections returns the genericConnections field.
func (m *metricsImpl) GetGenericConnections() *prometheus.GaugeVec {
	return m.genericConnections
}

// GetBruteForceEvalSeconds returns the bruteForceEvalSeconds field.
func (m *metricsImpl) GetBruteForceEvalSeconds() prometheus.Histogram {
	return m.bruteForceEvalSeconds
}

// GetBruteForceCacheHitsTotal returns the bruteForceCacheHitsTotal field.
func (m *metricsImpl) GetBruteForceCacheHitsTotal() *prometheus.CounterVec {
	return m.bruteForceCacheHitsTotal
}

// GetBruteForceRulesMatchedTotal returns the bruteForceRulesMatchedTot field.
func (m *metricsImpl) GetBruteForceRulesMatchedTotal() prometheus.Counter {
	return m.bruteForceRulesMatchedTot
}

// GetRedisRoundtripsTotal returns the redisRoundtripsTotal field.
func (m *metricsImpl) GetRedisRoundtripsTotal() *prometheus.CounterVec {
	return m.redisRoundtripsTotal
}

// GetLuaQueueDepth returns a Prometheus GaugeVec representing the depth of the Lua job queue.
func (m *metricsImpl) GetLuaQueueDepth() *prometheus.GaugeVec {
	return m.luaQueueDepth
}

// GetLuaQueueWaitSeconds returns a prometheus.HistogramVec for monitoring Lua queue wait durations in seconds.
func (m *metricsImpl) GetLuaQueueWaitSeconds() *prometheus.HistogramVec {
	return m.luaQueueWaitSeconds
}

// GetLuaQueueDroppedTotal retrieves the prometheus CounterVec metric for tracking the total number of dropped Lua queue items.
func (m *metricsImpl) GetLuaQueueDroppedTotal() *prometheus.CounterVec {
	return m.luaQueueDroppedTotal
}

// GetLuaVMInUse returns a GaugeVec metric tracking the number of Lua virtual machines currently in use.
func (m *metricsImpl) GetLuaVMInUse() *prometheus.GaugeVec {
	return m.luaVMInUse
}

// GetLuaVMReplacedTotal returns the CounterVec metric tracking the total number of Lua VM replacements.
func (m *metricsImpl) GetLuaVMReplacedTotal() *prometheus.CounterVec {
	return m.luaVMReplacedTotal
}

// GetLdapBreakerState returns the ldapBreakerState field.
func (m *metricsImpl) GetLdapBreakerState() *prometheus.GaugeVec {
	return m.ldapBreakerState
}

// GetLdapTargetHealth returns the ldapTargetHealth field.
func (m *metricsImpl) GetLdapTargetHealth() *prometheus.GaugeVec {
	return m.ldapTargetHealth
}

// GetLdapTargetInflight returns the ldapTargetInflight field.
func (m *metricsImpl) GetLdapTargetInflight() *prometheus.GaugeVec {
	return m.ldapTargetInflight
}

// GetLdapCacheHitsTotal returns the ldapCacheHitsTotal field, which tracks the total number of LDAP cache hit events.
func (m *metricsImpl) GetLdapCacheHitsTotal() *prometheus.CounterVec {
	return m.ldapCacheHitsTotal
}

// GetLdapCacheMissesTotal returns the ldapCacheMissesTotal field, which tracks the total number of LDAP cache miss events.
func (m *metricsImpl) GetLdapCacheMissesTotal() *prometheus.CounterVec {
	return m.ldapCacheMissesTotal
}

// GetLdapCacheEntries returns the ldapCacheEntries field, which tracks the current number of entries in the LDAP cache.
func (m *metricsImpl) GetLdapCacheEntries() *prometheus.GaugeVec {
	return m.ldapCacheEntries
}

// GetLdapCacheEvictionsTotal returns a prometheus.CounterVec tracking the total number of LDAP cache evictions.
func (m *metricsImpl) GetLdapCacheEvictionsTotal() *prometheus.CounterVec {
	return m.ldapCacheEvictionsTotal
}

// GetLdapErrorsTotal returns the ldapErrorsTotal field.
func (m *metricsImpl) GetLdapErrorsTotal() *prometheus.CounterVec {
	return m.ldapErrorsTotal
}

// GetLdapRetriesTotal returns the ldapRetriesTotal field.
func (m *metricsImpl) GetLdapRetriesTotal() *prometheus.CounterVec {
	return m.ldapRetriesTotal
}

// GetLdapAuthRateLimitedTotal returns the ldapAuthRateLimitedTotal field.
func (m *metricsImpl) GetLdapAuthRateLimitedTotal() *prometheus.CounterVec {
	return m.ldapAuthRateLimitedTotal
}

// GetIdpLoginsTotal returns the idpLoginsTotal field.
func (m *metricsImpl) GetIdpLoginsTotal() *prometheus.CounterVec {
	return m.idpLoginsTotal
}

// GetIdpTokensIssuedTotal returns the idpTokensIssuedTotal field.
func (m *metricsImpl) GetIdpTokensIssuedTotal() *prometheus.CounterVec {
	return m.idpTokensIssuedTotal
}

// GetIdpConsentTotal returns the idpConsentTotal field.
func (m *metricsImpl) GetIdpConsentTotal() *prometheus.CounterVec {
	return m.idpConsentTotal
}

// GetIdpMfaOperationsTotal returns the idpMfaOperationsTotal field.
func (m *metricsImpl) GetIdpMfaOperationsTotal() *prometheus.CounterVec {
	return m.idpMfaOperationsTotal
}

// GetAuthFSMTransitionsTotal returns the authFSMTransitionsTotal field.
func (m *metricsImpl) GetAuthFSMTransitionsTotal() *prometheus.CounterVec {
	return m.authFSMTransitionsTotal
}

// GetPluginCallsTotal returns the native plugin call counter.
func (m *metricsImpl) GetPluginCallsTotal() *prometheus.CounterVec {
	return m.pluginCallsTotal
}

// GetPluginCallDurationSeconds returns the native plugin call duration histogram.
func (m *metricsImpl) GetPluginCallDurationSeconds() *prometheus.HistogramVec {
	return m.pluginCallDurationSeconds
}

// NewMetrics provides the exported NewMetrics function.
func NewMetrics() Metrics {
	return &metricsImpl{
		instanceInfo: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_version_info",
				Help: "Information about the version.",
			}, []string{metricInstanceNameLabel, metricVersionLabel},
		),
		currentRequests: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "server_concurrent_requests",
				Help: "Number of current requests.",
			},
		),
		httpRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Number of HTTP requests.",
			}, []string{metricPathLabel},
		),
		httpResponseTimeSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "http_response_time_seconds",
				Help: "Duration of HTTP requests.",
			}, []string{metricPathLabel},
		),
		loginsCounter: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "logins_total",
				Help: "Number of failed and successful login attempts.",
			}, []string{metricLoginsLabel},
		),
		redisReadCounter: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "redis_read_total",
				Help: "Total number of Redis read operations",
			},
		),
		redisWriteCounter: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "redis_write_total",
				Help: "Total number of Redis write operations",
			},
		),
		functionDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "function_duration_seconds",
				Help:    "Time spent in function",
				Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
			}, []string{metricServiceLabel, metricTaskLabel, metricResourceLabel},
		),
		rblDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rbl_duration_seconds",
				Help:    "Time spent for RBL lookups",
				Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
			}, []string{metricRBLLabel},
		),
		cacheHits: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "cache_hits_total",
				Help: "The total number of cache hits",
			},
		),
		cacheMisses: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "cache_misses_total",
				Help: "The total number of cache misses",
			},
		),
		redisHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "redis_connection_hits_total",
				Help: "The total number of times a free connection was found in the pool",
			}, []string{metricPoolNameLabel},
		),
		redisMisses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "redis_connection_misses_total",
				Help: "The total number of times a free connection was NOT found in the pool",
			}, []string{metricPoolNameLabel},
		),
		redisTimeouts: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "redis_connection_timeouts_total",
				Help: "The total number of times a wait timeout occurred",
			}, []string{metricPoolNameLabel},
		),
		redisTotalConns: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "redis_pool_total_connections",
				Help: "The total number of connections in the pool",
			}, []string{metricPoolNameLabel},
		),
		redisIdleConns: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "redis_pool_idle_connections",
				Help: "The total number of idle connections in the pool",
			}, []string{metricPoolNameLabel},
		),
		redisStaleConns: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "redis_pool_stale_connections",
				Help: "The total number of stale connections removed from the pool",
			}, []string{metricPoolNameLabel},
		),
		bruteForceRejected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bruteforce_rejected_total",
				Help: "The total number of brute force rejected attempts",
			}, []string{metricBucketLabel},
		),
		bruteForceHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bruteforce_hits_total",
				Help: "The total number of brute force hits before rejection",
			}, []string{metricBucketLabel},
		),
		rejectedProtocols: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rejected_protocols_total",
				Help: "The total number of rejects per protocol",
			}, []string{metricProtocolLabel},
		),
		acceptedProtocols: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "accepted_protocols_total",
				Help: "The total number of acceptances per protocol",
			}, []string{metricProtocolLabel},
		),
		backendServerStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "backend_servers_status",
				Help: "Status of monitored backend servers",
			}, []string{metricServerStatusLabel},
		),
		ldapPoolStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_pool_connections_total",
				Help: "Number of actively used connections in the LDAP pool",
			}, []string{metricPoolLabel},
		),
		ldapOpenConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_pool_open_connections_total",
				Help: "Number of currently opened connections",
			}, []string{metricPoolLabel},
		),
		ldapStaleConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_pool_stale_connections_total",
				Help: "Number of currently staled connections",
			}, []string{metricPoolLabel},
		),
		ldapPoolSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_pool_size",
				Help: "Size of LDAP pool",
			}, []string{metricPoolLabel},
		),
		ldapIdlePoolSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_idle_pool_size",
				Help: "Size of idle LDAP pool",
			}, []string{metricPoolLabel},
		),
		ldapQueueDepth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_queue_depth",
				Help: "Current LDAP queue depth",
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapQueueWaitSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ldap_queue_wait_seconds",
				Help:    "Time spent waiting in LDAP queues",
				Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapQueueDroppedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_queue_dropped_total",
				Help: "Total LDAP requests dropped due to queue overflow",
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapBreakerState: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_breaker_state",
				Help: "Circuit breaker state per LDAP target (0=closed,1=open,2=half-open)",
			}, []string{metricPoolLabel, metricTargetLabel},
		),
		ldapTargetHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_target_health",
				Help: "LDAP target health status (1=healthy,0=unhealthy)",
			}, []string{metricPoolLabel, metricTargetLabel},
		),
		ldapTargetInflight: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_target_inflight",
				Help: "Current in-flight requests per LDAP target",
			}, []string{metricPoolLabel, metricTargetLabel},
		),
		// A8 cache metrics
		ldapCacheHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_cache_hits_total",
				Help: "Total LDAP cache hits",
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapCacheMissesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_cache_misses_total",
				Help: "Total LDAP cache misses",
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapCacheEntries: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ldap_cache_entries",
				Help: "Number of entries in LDAP caches",
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapCacheEvictionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_cache_evictions_total",
				Help: "Total LDAP cache evictions",
			}, []string{metricPoolLabel, metricTypeLabel},
		),
		ldapErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_errors_total",
				Help: "Total LDAP errors by operation and LDAP result code",
			}, []string{metricPoolLabel, metricOpLabel, metricCodeLabel},
		),
		ldapRetriesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_retries_total",
				Help: "Total LDAP retries by operation",
			}, []string{metricPoolLabel, metricOpLabel},
		),
		ldapAuthRateLimitedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ldap_auth_rate_limited_total",
				Help: "Total LDAP auth requests rate-limited",
			}, []string{metricPoolLabel, metricDimensionLabel},
		),
		rblRejected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rbl_rejected_total",
				Help: "The total number of rejected RBL requests",
			}, []string{metricRBLLabel},
		),
		genericConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "generic_connections",
				Help: "Current number of established connections to a target",
			}, []string{metricDescriptionLabel, metricTargetLabel, metricDirectionLabel},
		),
		// Lua metrics
		luaQueueDepth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "lua_queue_depth",
				Help: "Current Lua queue depth",
			}, []string{metricBackendLabel},
		),
		luaQueueWaitSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "lua_queue_wait_seconds",
				Help:    "Time spent waiting in Lua queues",
				Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
			}, []string{metricBackendLabel},
		),
		luaQueueDroppedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lua_queue_dropped_total",
				Help: "Total Lua requests dropped due to queue overflow",
			}, []string{metricBackendLabel},
		),
		luaVMInUse: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "lua_vm_in_use",
				Help: "Number of Lua VMs currently in use",
			}, []string{metricKeyLabel},
		),
		luaVMReplacedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lua_vm_replaced_total",
				Help: "Total Lua VMs replaced due to errors or timeouts",
			}, []string{metricKeyLabel},
		),
		// Brute-force path metrics (centralized here)
		bruteForceEvalSeconds: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "bruteforce_eval_seconds",
				Help:    "End-to-end duration of brute-force evaluation",
				Buckets: prometheus.ExponentialBuckets(0.001, 1.7, 15),
			},
		),
		bruteForcePhaseSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bruteforce_phase_seconds",
				Help:    "Duration by phase in brute-force evaluation",
				Buckets: prometheus.ExponentialBuckets(0.0005, 1.7, 16),
			},
			[]string{metricPhaseLabel},
		),
		bruteForceCacheHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bruteforce_cache_hits_total",
				Help: "Total cache hits in brute-force path",
			},
			[]string{metricKindLabel},
		),
		bruteForceRulesMatchedTot: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "bruteforce_rules_matched_total",
				Help: "Total number of matched brute-force rules",
			},
		),
		redisRoundtripsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bruteforce_redis_roundtrips_total",
				Help: "Total Redis roundtrips by kind in brute-force path",
			},
			[]string{metricKindLabel},
		),
		idpLoginsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "idp_logins_total",
				Help: "The total number of IDP logins",
			}, []string{metricProtocolLabel, metricStatusLabel},
		),
		idpTokensIssuedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "idp_tokens_issued_total",
				Help: "The total number of IDP tokens issued",
			}, []string{metricProtocolLabel, metricClientIDLabel, metricGrantTypeLabel},
		),
		idpConsentTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "idp_consent_total",
				Help: "The total number of IDP consent operations",
			}, []string{metricClientIDLabel, metricStatusLabel},
		),
		idpMfaOperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "idp_mfa_operations_total",
				Help: "The total number of IDP MFA operations",
			}, []string{metricTypeLabel, metricMethodLabel, metricStatusLabel},
		),
		authFSMTransitionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_fsm_transitions_total",
				Help: "Total number of auth FSM transitions",
			},
			[]string{metricFromLabel, metricEventLabel, metricToLabel},
		),
		pluginCallsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "plugin_calls_total",
				Help: "Total number of host-invoked native plugin calls",
			},
			pluginCallMetricLabels,
		),
		pluginCallDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "plugin_call_duration_seconds",
				Help:    "Duration of host-invoked native plugin calls",
				Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
			},
			pluginCallMetricLabels,
		),
	}
}

// GetMetrics initializes and returns a singleton instance of the Metrics interface.
func GetMetrics() Metrics {
	initMetrics.Do(func() {
		if metrics == nil {
			metrics = NewMetrics()
		}
	})

	return metrics
}

var oldCPU cpu.Stats

var (
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

// MeasureCPU monitors and calculates CPU usage statistics at periodic intervals until the provided context is canceled.
func MeasureCPU(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(2 * time.Second)

			newCPU, err := cpu.Get()
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, "Failed to get CPU usage statistics",
					definitions.LogKeyError, err,
				)

				return
			}

			total := float64(newCPU.Total - oldCPU.Total)

			setNewStats(&oldCPU, newCPU, total)

			oldCPU = *newCPU
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
func PrintStats(logger *slog.Logger) {
	var memStats runtime.MemStats

	runtime.ReadMemStats(&memStats)

	level.Info(logger).Log(
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

// HavePrometheusLabelEnabled provides the exported HavePrometheusLabelEnabled function.
func HavePrometheusLabelEnabled(cfg config.File, prometheusLabel string) bool {
	if cfg == nil || !cfg.GetServer().GetPrometheusTimer().IsEnabled() {
		return false
	}

	for _, label := range cfg.GetServer().GetPrometheusTimer().GetLabels() {
		if label != prometheusLabel {
			continue
		}

		return true
	}

	return false
}

// PrometheusTimer returns a closure that, when executed, stops a Prometheus timer for a given service and task.
// If the Prometheus Timer is disabled or the specified task is not enabled in the configuration, it returns nil.
func PrometheusTimer(cfg config.File, serviceName string, taskName string, resource string) func() {
	if HavePrometheusLabelEnabled(cfg, serviceName) {
		timer := prometheus.NewTimer(GetMetrics().GetFunctionDuration().WithLabelValues(serviceName, taskName, resource))

		return func() {
			timer.ObserveDuration()
		}
	}

	return nil
}

// UpdateGenericConnections reads from GenericConnectionChan and updates the GenericConnections metric.
// It exits when ctx is canceled.
func UpdateGenericConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn, openConn := <-connmgr.GenericConnectionChan:
			if !openConn {
				return
			}

			GetMetrics().GetGenericConnections().WithLabelValues(conn.Description, conn.Target, conn.Direction).Set(float64(conn.Count))
		}
	}
}
