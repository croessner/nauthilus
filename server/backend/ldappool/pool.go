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

package ldappool

import (
	"context"
	stderrors "errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/singleflight"
)

// LDAPPool is an interface that represents a pool for managing LDAP connections and operations efficiently.
type LDAPPool interface {
	// StartHouseKeeper starts a background process for resource management and cleanup within the LDAP pool.
	StartHouseKeeper()

	// GetNumberOfWorkers returns the total number of workers allocated to the LDAP pool.
	GetNumberOfWorkers() int

	// SetIdleConnections configures and manages idle connections in the pool based on the provided bind parameter.
	SetIdleConnections(bind bool) error

	// HandleLookupRequest handles an LDAP lookup request asynchronously.
	HandleLookupRequest(ldapRequest *bktype.LDAPRequest) error

	// HandleAuthRequest processes an LDAP authentication request.
	HandleAuthRequest(ldapAuthRequest *bktype.LDAPAuthRequest) error

	// Close releases all resources used by the LDAPPool and terminates any background processes or connections.
	Close()
}

type Token struct{}

// ldapPoolImpl represents a pool of LDAP connections.
type ldapPoolImpl struct {
	// poolType denotes the type of the pool.
	poolType int

	// poolSize defines the number of resources maintained in the pool for concurrent operations.
	poolSize int

	// idlePoolSize defines the maximum number of idle connections in the connection pool.
	idlePoolSize int

	// numberOfWorkers specifies the total count of workers allocated for a specific task or operation in the program.
	numberOfWorkers int

	// name specifies the name of the LDAP connection pool.
	name string

	// ctx is the context in which the LDAP connection pool operates.
	ctx context.Context

	// conn is the array of LDAP connections in the pool.
	conn []LDAPConnection

	// conf refers to the configuration details for the LDAP connections in the pool.
	conf []*config.LDAPConf

	// tokens is a counting semaphore limiting concurrent usage to poolSize.
	tokens chan struct{}
}

// StartHouseKeeper is a background task responsible for managing and cleaning up idle LDAP connections in the pool.
// It updates metrics and closes stale or excessive connections periodically while ensuring thread safety.
// The method operates in a loop, triggered by a 30-second ticker or context cancellation for graceful shutdown.
func (l *ldapPoolImpl) StartHouseKeeper() {
	timer := time.NewTicker(30 * time.Second)

	l.updateStatsPoolSize()

	for {
		select {
		case <-l.ctx.Done():
			l.logCompletion()
			timer.Stop()

			return
		case <-timer.C:
			// Tracing one housekeeping iteration
			tr := monittrace.New("nauthilus/ldap_pool")
			hctx, hsp := tr.Start(l.ctx, "ldap.pool.housekeeping",
				attribute.String("pool_name", l.name),
			)
			_ = hctx

			// Observe state before and after to compute how many we closed
			openBefore := l.determineOpenConnections()
			openConnections := l.updateConnectionsStatus()
			stats.GetMetrics().GetLdapOpenConnections().WithLabelValues(l.name).Set(float64(openConnections))

			l.closeIdleConnections(openConnections)
			openAfter := l.determineOpenConnections()

			closed := openBefore - openAfter
			if closed < 0 {
				closed = 0
			}

			// needClosing based on current policy
			needClosing := max(openConnections-l.idlePoolSize, 0)
			hsp.SetAttributes(
				attribute.Int("checked", openConnections),
				attribute.Int("closed", closed),
				attribute.Int("need_closing", needClosing),
				attribute.Int("idle_target", l.idlePoolSize),
			)
			hsp.End()
			l.updateStatsPoolSize()
		}
	}
}

// SetIdleConnections adjusts the number of idle connections in the LDAP connection pool based on its current state.
func (l *ldapPoolImpl) SetIdleConnections(bind bool) (err error) {
	openConnections := l.determineOpenConnections()

	if openConnections < l.idlePoolSize {
		err = l.initializeConnections(bind)
	}

	return
}

// HandleLookupRequest processes an LDAP lookup request using a connection pool and manages asynchronous execution.
func (l *ldapPoolImpl) HandleLookupRequest(ldapRequest *bktype.LDAPRequest) error {
	connNumber, err := l.getConnection(ldapRequest.HTTPClientContext, ldapRequest.GUID)
	if err != nil {
		return err
	}

	stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Inc()
	go l.proccessLookupRequest(connNumber, ldapRequest)

	return nil
}

// HandleAuthRequest processes an LDAP authentication request using the connection pool and updates process metrics.
func (l *ldapPoolImpl) HandleAuthRequest(ldapAuthRequest *bktype.LDAPAuthRequest) error {
	// Optional per-pool auth rate limit check
	if v, ok := authLimiters.Load(l.name); ok {
		if lim, ok2 := v.(*tokenBucket); ok2 {
			if !lim.allow() {
				// increment rate-limit metric
				stats.GetMetrics().GetLdapAuthRateLimitedTotal().WithLabelValues(l.name, "pool").Inc()

				return fmt.Errorf("auth rate limited for pool %s", l.name)
			}
		}
	}

	connNumber, err := l.getConnection(ldapAuthRequest.HTTPClientContext, ldapAuthRequest.GUID)
	if err != nil {
		return err
	}

	stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Inc()

	l.processAuthRequest(connNumber, ldapAuthRequest)

	return nil
}

// Close terminates all active connections in the LDAP pool and logs information about the closure process.
func (l *ldapPoolImpl) Close() {
	for index := 0; index < len(l.conn); index++ {
		if l.conn[index].GetConn() != nil {
			_ = l.conn[index].Unbind()
			if l.conn[index].GetConn() != nil {
				l.conn[index].GetConn().Close()
			}

			util.DebugModule(
				definitions.DbgLDAP,
				definitions.LogKeyLDAPPoolName, l.name,
				definitions.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1),
			)
		}
	}

	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyMsg, "Terminated",
	)
}

// GetNumberOfWorkers returns the number of workers currently configured in the LDAP pool.
func (l *ldapPoolImpl) GetNumberOfWorkers() int {
	return l.numberOfWorkers
}

var _ LDAPPool = (*ldapPoolImpl)(nil)

var (
	negCaches sync.Map // map[string]localcache.SimpleCache
	negSF     singleflight.Group

	// per-pool auth rate limiters
	authLimiters sync.Map // map[string]*tokenBucket
)

// simple token bucket limiter (local, no extra deps)
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64   // tokens per second
	burst  int       // max tokens
	tokens float64   // current tokens
	last   time.Time // last refill
}

// newTokenBucket creates a new token bucket rate limiter with the specified rate (tokens per second) and burst capacity.
func newTokenBucket(rps float64, burst int) *tokenBucket {
	if burst <= 0 {
		burst = 1
	}

	return &tokenBucket{
		rate:   rps,
		burst:  burst,
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// allow controls access based on token bucket rate limiting, returning true if a request is permitted, false otherwise.
func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	if elapsed > 0 {
		tb.tokens += elapsed * tb.rate

		if tb.tokens > float64(tb.burst) {
			tb.tokens = float64(tb.burst)
		}

		tb.last = now
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0

		return true
	}

	return false
}

// getNegCache returns the negative cache for the given pool, creating it if necessary.
// LRU caches are created per-pool (allowing eviction metrics). TTL cache shares the global sharded cache.
func getNegCache(pool string, conf *config.LDAPConf) localcache.SimpleCache {
	if v, ok := negCaches.Load(pool); ok {
		if c, ok2 := v.(localcache.SimpleCache); ok2 {
			return c
		}
	}

	var c localcache.SimpleCache
	if conf != nil && conf.GetCacheImpl() == "lru" {
		lru := localcache.NewLRU(conf.GetCacheMaxEntries())

		// Increment eviction metrics for this pool when entries are evicted.
		lru.SetOnEvict(func(key string, value any) {
			stats.GetMetrics().GetLdapCacheEvictionsTotal().WithLabelValues(pool, "neg").Inc()
		})

		c = lru
	} else {
		// Use LDAP-scoped shared sharded TTL cache; per-call TTL will be respected.
		if st := getSharedTTL(); st != nil {
			c = st
		} else {
			// Fallback to global cache (no janitor by default); safe but without periodic cleanup
			c = localcache.LocalCache.MemoryShardedCache
		}
	}

	negCaches.Store(pool, c)

	return c
}

// NewPool creates and initializes a new LDAPPool based on the specified pool type and context for LDAP operations.
func NewPool(ctx context.Context, poolType int, poolName string) LDAPPool {
	var (
		poolSize        int
		idlePoolSize    int
		numberOfWorkers int
		name            string
		conn            []LDAPConnection
		conf            []*config.LDAPConf
		serverURIs      []string
		bindDN          string
		bindPW          string
		startTLS        bool
		tlsSkipVerify   bool
		tlsCAFile       string
		tlsClientCert   string
		tlsClientKey    string
		saslExternal    bool
	)

	if config.GetFile().GetLDAP() == nil {
		panic("LDAP configuration is not set")
	}

	poolMap := config.GetFile().GetLDAP().GetOptionalLDAPPools()

	if poolName == definitions.DefaultBackendName {
		numberOfWorkers = config.GetFile().GetLDAPConfigNumberOfWorkers()
		serverURIs = config.GetFile().GetLDAPConfigServerURIs()
		bindDN = config.GetFile().GetLDAPConfigBindDN()
		bindPW = config.GetFile().GetLDAPConfigBindPW()
		startTLS = config.GetFile().GetLDAPConfigStartTLS()
		tlsSkipVerify = config.GetFile().GetLDAPConfigTLSSkipVerify()
		tlsCAFile = config.GetFile().GetLDAPConfigTLSCAFile()
		tlsClientCert = config.GetFile().GetLDAPConfigTLSClientCert()
		tlsClientKey = config.GetFile().GetLDAPConfigTLSClientKey()
		saslExternal = config.GetFile().GetLDAPConfigSASLExternal()
	} else {
		if poolMap == nil || poolMap[poolName] == nil {
			panic(fmt.Sprintf("LDAP pool %s is not defined", poolName))
		}

		numberOfWorkers = poolMap[poolName].GetNumberOfWorkers()
		serverURIs = poolMap[poolName].ServerURIs
		bindDN = poolMap[poolName].BindDN
		bindPW = poolMap[poolName].BindPW
		startTLS = poolMap[poolName].StartTLS
		tlsSkipVerify = poolMap[poolName].TLSSkipVerify
		tlsCAFile = poolMap[poolName].TLSCAFile
		tlsClientCert = poolMap[poolName].TLSClientCert
		tlsClientKey = poolMap[poolName].TLSClientKey
		saslExternal = poolMap[poolName].SASLExternal
	}

	switch poolType {
	case definitions.LDAPPoolLookup, definitions.LDAPPoolUnknown:
		name = "lookup"

		if poolName == definitions.DefaultBackendName {
			poolSize = config.GetFile().GetLDAPConfigLookupPoolSize()
			idlePoolSize = config.GetFile().GetLDAPConfigLookupIdlePoolSize()
		} else {
			name = poolName + "-lookup"
			poolSize = poolMap[poolName].LookupPoolSize
			idlePoolSize = poolMap[poolName].LookupIdlePoolSize
		}

		conf = make([]*config.LDAPConf, poolSize)
		conn = make([]LDAPConnection, poolSize)

	case definitions.LDAPPoolAuth:
		name = "auth"
		if poolName == definitions.DefaultBackendName {
			poolSize = config.GetFile().GetLDAPConfigAuthPoolSize()
			idlePoolSize = config.GetFile().GetLDAPConfigAuthIdlePoolSize()
		} else {
			name = poolName + "-auth"
			poolSize = poolMap[poolName].AuthPoolSize
			idlePoolSize = poolMap[poolName].AuthIdlePoolSize
		}

		conf = make([]*config.LDAPConf, poolSize)
		conn = make([]LDAPConnection, poolSize)
	default:
		panic(fmt.Sprintf("LDAP pool type %d is not supported", poolType))
	}

	for index := 0; index < poolSize; index++ {
		conf[index] = &config.LDAPConf{}
		conn[index] = &LDAPConnectionImpl{}

		conf[index].ServerURIs = serverURIs
		conf[index].BindDN = bindDN
		conf[index].BindPW = bindPW
		conf[index].StartTLS = startTLS
		conf[index].TLSSkipVerify = tlsSkipVerify
		conf[index].TLSCAFile = tlsCAFile
		conf[index].TLSClientCert = tlsClientCert
		conf[index].TLSClientKey = tlsClientKey
		conf[index].SASLExternal = saslExternal
		conf[index].PoolName = name

		conn[index].SetState(definitions.LDAPStateClosed)
	}

	util.DebugModule(
		definitions.DbgLDAPPool,
		definitions.LogKeyMsg, "ldap_worker_created",
		definitions.LogKeyLDAPPoolName, name,
		"number_of_workers", numberOfWorkers,
		"pool_type", poolType,
		"pool_size", poolSize,
		"idle_pool_size", idlePoolSize,
	)

	lp := &ldapPoolImpl{
		numberOfWorkers: numberOfWorkers,
		poolType:        poolType,
		poolSize:        poolSize,
		idlePoolSize:    idlePoolSize,
		ctx:             ctx,
		name:            name,
		conn:            conn,
		conf:            conf,
	}

	// Initialize semaphore with poolSize tokens
	lp.tokens = make(chan struct{}, poolSize)
	for i := 0; i < poolSize; i++ {
		lp.tokens <- Token{}
	}

	// Start active target health checker for this pool
	if len(conf) > 0 && conf[0] != nil {
		go startHealthLoop(name, conf[0])
	}

	// Initialize per-pool auth rate limiter if configured
	if poolType == definitions.LDAPPoolAuth && len(conf) > 0 && conf[0] != nil {
		rps := conf[0].GetAuthRateLimitPerSecond()
		burst := conf[0].GetAuthRateLimitBurst()

		if rps > 0 {
			lim := newTokenBucket(rps, burst)
			authLimiters.Store(name, lim)
		}
	}

	return lp
}

// logCompletion logs a debug message indicating that the houseKeeper() method of LDAPPool has been terminated.
func (l *ldapPoolImpl) logCompletion() {
	util.DebugModule(definitions.DbgLDAP, definitions.LogKeyLDAPPoolName, l.name, definitions.LogKeyMsg, "houseKeeper() terminated")
}

// updateConnectionsStatus iterates through the connection pool and updates the status of each connection.
// It returns the total number of open connections after the update.
func (l *ldapPoolImpl) updateConnectionsStatus() (openConnections int) {
	for index := 0; index < l.poolSize; index++ {
		openConnections += l.updateSingleConnectionStatus(index)
	}

	return openConnections
}

// updateSingleConnectionStatus updates the status of a specific LDAP connection and returns 1 if the connection is usable.
func (l *ldapPoolImpl) updateSingleConnectionStatus(index int) int {
	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	if l.conn[index].GetState() != definitions.LDAPStateFree || l.conn[index].GetConn() == nil || l.conn[index].GetConn().IsClosing() {
		l.conn[index].SetState(definitions.LDAPStateClosed)

		util.DebugModule(
			definitions.DbgLDAPPool,
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is busy or closed", index+1))

		return 0
	}

	if _, err := l.conn[index].GetConn().Search(
		ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			30,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		),
	); err != nil {
		util.DebugModule(
			definitions.DbgLDAPPool,
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d has broken connection", index+1))

		l.conn[index].SetConn(nil)
		l.conn[index].SetState(definitions.LDAPStateClosed)

		return 0
	}

	util.DebugModule(definitions.DbgLDAPPool, definitions.LogKeyLDAPPoolName, l.name, definitions.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is free", index+1))

	return 1
}

// closeIdleConnections closes excess idle connections from the pool based on open connections, idle pool size, and total pool size.
func (l *ldapPoolImpl) closeIdleConnections(openConnections int) {
	needClosing := max(openConnections-l.idlePoolSize, 0)

	stats.GetMetrics().GetLdapStaleConnections().WithLabelValues(l.name).Set(float64(needClosing))
	util.DebugModule(
		definitions.DbgLDAPPool,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyMsg, "State open connections", "needClosing", needClosing, "openConnections", openConnections, "idlePoolSize", l.idlePoolSize)

	//goland:noinspection GoDfaConstantCondition
	for index := 0; index < l.poolSize && needClosing > 0; index++ {
		if l.closeSingleIdleConnection(index) {
			needClosing--
		}
	}
}

// closeSingleIdleConnection closes a single idle connection at the specified index if it is not in use, returning true if successful.
func (l *ldapPoolImpl) closeSingleIdleConnection(index int) bool {
	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	if l.conn[index].GetState() != definitions.LDAPStateFree {
		return false
	}

	l.conn[index].GetConn().Close()
	l.conn[index].SetState(definitions.LDAPStateClosed)

	util.DebugModule(
		definitions.DbgLDAPPool,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1))

	return true
}

// updateStatsPoolSize updates the LDAP pool size metric based on the pool type. It handles lookup, unknown, and auth pool types.
func (l *ldapPoolImpl) updateStatsPoolSize() {
	switch l.poolType {
	case definitions.LDAPPoolLookup, definitions.LDAPPoolUnknown:
		stats.GetMetrics().GetLdapPoolSize().WithLabelValues(l.name).Set(float64(config.GetFile().GetLDAPConfigLookupPoolSize()))
		stats.GetMetrics().GetLdapIdlePoolSize().WithLabelValues(l.name).Set(float64(config.GetFile().GetLDAPConfigLookupIdlePoolSize()))
	case definitions.LDAPPoolAuth:
		stats.GetMetrics().GetLdapPoolSize().WithLabelValues(l.name).Set(float64(config.GetFile().GetLDAPConfigAuthPoolSize()))
		stats.GetMetrics().GetLdapIdlePoolSize().WithLabelValues(l.name).Set(float64(config.GetFile().GetLDAPConfigAuthIdlePoolSize()))
	}
}

// determineOpenConnections calculates total number of open connections.
func (l *ldapPoolImpl) determineOpenConnections() (openConnections int) {
	for index := 0; index < l.poolSize; index++ {
		if l.conn[index].GetState() != definitions.LDAPStateClosed {
			openConnections++
		}
	}

	return openConnections
}

// initializeConnections establishes and initializes LDAP connections for the pool, binding them if required.
// Returns an error if unable to connect to the LDAP servers.
func (l *ldapPoolImpl) initializeConnections(bind bool) (err error) {
	idlePoolSize := l.idlePoolSize

	for index := 0; index < l.poolSize; index++ {
		guidStr := fmt.Sprintf("pool-#%d", index+1)

		l.logConnectionInfo(guidStr, index)

		err = l.setupConnection(guidStr, bind, index)
		if err == nil {
			idlePoolSize--
		}

		if idlePoolSize == 0 {
			return nil
		}
	}

	return errors.ErrLDAPConnect
}

// setupConnection initializes and manages the state of an LDAP connection for a specified index in the pool.
// It locks the connection, checks its state, tries to connect if closed, and optionally binds based on the provided flag.
// Returns an error if connection or binding fails.
func (l *ldapPoolImpl) setupConnection(guid string, bind bool, index int) error {
	var err error

	// Trace connection (re)open + optional bind
	tr := monittrace.New("nauthilus/ldap_pool")
	ctx, sp := tr.Start(l.ctx, "ldap.pool.open_conn",
		attribute.String("pool_name", l.name),
		attribute.Int("index", index),
		attribute.String("server_uri", func() string {
			if l.conf != nil && index < len(l.conf) && l.conf[index] != nil {
				uris := l.conf[index].GetServerURIs()
				if len(uris) > 0 {
					return uris[0]
				}
			}

			return ""
		}()),
		attribute.Bool("starttls", func() bool {
			if l.conf != nil && index < len(l.conf) && l.conf[index] != nil {
				return l.conf[index].IsStartTLS()
			}

			return false
		}()),
		attribute.Bool("tls_skip_verify", func() bool {
			if l.conf != nil && index < len(l.conf) && l.conf[index] != nil {
				return l.conf[index].IsTLSSkipVerify()
			}

			return false
		}()),
	)

	_ = ctx

	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	if l.conn[index].GetState() == definitions.LDAPStateClosed {
		err = l.conn[index].Connect(guid, l.conf[index])
		if err != nil {
			l.logConnectionError(guid, err)
			sp.RecordError(err)
		} else {
			if bind {
				err = l.conn[index].Bind(guid, l.conf[index])
				if err != nil {
					l.logConnectionError(guid, err)
					sp.RecordError(err)
				} else {
					l.conn[index].SetState(definitions.LDAPStateFree)
				}
			} else {
				l.conn[index].SetState(definitions.LDAPStateFree)
			}
		}
	}

	if err == nil {
		sp.SetAttributes(attribute.Bool("ok", true))
	}

	sp.End()

	return err
}

// logConnectionInfo logs information about an LDAP connection including pool name, GUID, and specific connection settings.
func (l *ldapPoolImpl) logConnectionInfo(guid string, index int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		"ldap", l.conf[index].String(),
	)
}

// logConnectionError logs an error associated with an LDAP connection using the provided GUID and error message.
func (l *ldapPoolImpl) logConnectionError(guid string, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "LDAP connection error",
		definitions.LogKeyError, err,
	)
}

// acquireTokenWithTimeout tries to acquire a capacity token from the pool within the configured timeout.
// It respects the provided context deadline and caps the wait by the configured connect_abort_timeout.
func (l *ldapPoolImpl) acquireTokenWithTimeout(reqCtx context.Context) error {
	connectAbortTimeout := config.GetFile().GetLDAPConfigConnectAbortTimeout()
	if connectAbortTimeout == 0 {
		connectAbortTimeout = 10 * time.Second
	}

	ctx := reqCtx
	if ctx == nil {
		ctx = l.ctx
	}

	// Trace token acquisition including wait time
	tr := monittrace.New("nauthilus/ldap_pool")
	tctx, tsp := tr.Start(ctx, "ldap.pool.acquire_token",
		attribute.String("pool_name", l.name),
		attribute.Int("pool_size", l.poolSize),
		attribute.Int("idle_pool_size", l.idlePoolSize),
		attribute.Int("tokens_capacity", cap(l.tokens)),
	)
	_ = tctx
	start := time.Now()

	// Ensure we never wait longer than connectAbortTimeout
	var cancel func()

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("context timeout while waiting for LDAP token")
		}

		if remaining > connectAbortTimeout {
			ctx, cancel = context.WithTimeout(ctx, connectAbortTimeout)
		}
	} else {
		ctx, cancel = context.WithTimeout(ctx, connectAbortTimeout)
	}

	if cancel != nil {
		defer cancel()
	}

	select {
	case <-ctx.Done():
		tsp.SetAttributes(attribute.Int("waited_ms", int(time.Since(start).Milliseconds())))
		tsp.RecordError(fmt.Errorf("context timeout while waiting for LDAP token"))
		tsp.End()

		return fmt.Errorf("context timeout while waiting for LDAP token")
	case <-l.tokens:
		tsp.SetAttributes(attribute.Int("waited_ms", int(time.Since(start).Milliseconds())))
		tsp.End()

		return nil
	}
}

// releaseToken returns one capacity token to the pool.
func (l *ldapPoolImpl) releaseToken() {
	// Non-blocking in normal flow due to buffer size == poolSize
	l.tokens <- Token{}
}

// getConnection retrieves an available LDAP connection number from the pool using a semaphore.
// It honors the request context for waiting and scanning, bounded by connect_abort_timeout.
func (l *ldapPoolImpl) getConnection(reqCtx context.Context, guid string) (connNumber int, err error) {
	// Acquire capacity token with timeout
	if err := l.acquireTokenWithTimeout(reqCtx); err != nil {
		return definitions.LDAPPoolExhausted, fmt.Errorf("timeout exceeded: %w", err)
	}

	// Also bound the search for a free connection by the same timeout to avoid infinite wait when all are busy.
	connectAbortTimeout := config.GetFile().GetLDAPConfigConnectAbortTimeout()
	if connectAbortTimeout == 0 {
		connectAbortTimeout = 10 * time.Second
	}

	ctx := reqCtx
	if ctx == nil {
		ctx = l.ctx
	}

	var cancel func()

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			l.releaseToken()

			return definitions.LDAPPoolExhausted, fmt.Errorf("context timeout while waiting for free LDAP connection")
		}

		if remaining > connectAbortTimeout {
			ctx, cancel = context.WithTimeout(ctx, connectAbortTimeout)
		}
	} else {
		ctx, cancel = context.WithTimeout(ctx, connectAbortTimeout)
	}

	if cancel != nil {
		defer cancel()
	}

	borrowStart := time.Now()

	for {
		for index := 0; index < len(l.conn); index++ {
			connNumber = l.processConnection(index, guid)
			if connNumber != definitions.LDAPPoolExhausted {
				// Trace successful borrow under request context
				tr := monittrace.New("nauthilus/ldap_pool")
				bctx, bsp := tr.Start(ctx, "ldap.pool.borrow_conn",
					attribute.String("pool_name", l.name),
					attribute.Int("index", connNumber),
					attribute.Int("waited_ms", int(time.Since(borrowStart).Milliseconds())),
				)
				_ = bctx

				bsp.End()

				return connNumber, nil
			}
		}

		// Check for timeout/cancel to prevent hanging if all connections remain busy
		select {
		case <-ctx.Done():
			// Release the token since we are aborting without acquiring a connection
			l.releaseToken()

			return definitions.LDAPPoolExhausted, fmt.Errorf("context timeout while waiting for free LDAP connection")
		default:
			// Short backoff; token guarantees capacity, a subsequent scan should find a free/connected slot soon.
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// processConnection manages the connection at the specified index in the LDAP pool to determine its usability and state.
// It locks the connection mutex, checks its current state, and either marks it busy, attempts reconnection, or skips it.
// Returns the connection index if usable, or LDAPPoolExhausted if no connection can be utilized.
func (l *ldapPoolImpl) processConnection(index int, guid string) (connNumber int) {
	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	// Connection is already in use, skip to next.
	if l.conn[index].GetState() == definitions.LDAPStateBusy {
		l.logConnectionBusy(guid, index)

		return definitions.LDAPPoolExhausted
	}

	// Connection is free, use it and mark it as busy.
	if l.conn[index].GetState() == definitions.LDAPStateFree {
		l.conn[index].SetState(definitions.LDAPStateBusy)

		l.logConnectionUsage(guid, index)

		return index
	}

	// There is no free connection. We need to get a new one. If we succeed, mark the connection as
	// busy and use it.
	if l.conn[index].GetState() == definitions.LDAPStateClosed {
		err := l.connectAndBindIfNeeded(guid, index)
		if err != nil {
			l.logConnectionFailed(guid, err)

			return definitions.LDAPPoolExhausted
		}

		l.conn[index].SetState(definitions.LDAPStateBusy)

		l.logConnectionUsage(guid, index)

		return index
	}

	return definitions.LDAPPoolExhausted
}

// logConnectionBusy logs the event when the connection at the given index is busy and skips to check the next connection.
func (l *ldapPoolImpl) logConnectionBusy(guid string, index int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is busy, checking next", index+1),
	)
}

// logConnectionUsage logs debug information when a free LDAP connection is utilized by a specific GUID at a given index.
func (l *ldapPoolImpl) logConnectionUsage(guid string, index int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is free, using it", index+1),
	)
}

// connectAndBindIfNeeded establishes a connection if needed and performs a bind operation based on the pool type configuration.
func (l *ldapPoolImpl) connectAndBindIfNeeded(guid string, index int) error {
	err := l.conn[index].Connect(guid, l.conf[index])
	if err == nil && (l.poolType == definitions.LDAPPoolLookup || l.poolType == definitions.LDAPPoolUnknown) {
		err = l.conn[index].Bind(guid, l.conf[index])
	}

	return err
}

// logConnectionFailed logs a failed LDAP connection attempt with the pool name, session GUID, and error message.
func (l *ldapPoolImpl) logConnectionFailed(guid string, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "LDAP connection failed",
		definitions.LogKeyError, err,
	)
}

// checkConnection ensures that the LDAP connection at the given index is valid and operational.
// If the connection is nil or closing, it attempts to reconnect and rebind based on the pool type.
// Returns an error if the connection restoration or binding fails.
func (l *ldapPoolImpl) checkConnection(guid string, index int) (err error) {
	if l.conn[index].GetConn() == nil || l.conn[index].IsClosing() {
		l.conn[index].GetMutex().Lock()

		defer l.conn[index].GetMutex().Unlock()

		l.conn[index].SetState(definitions.LDAPStateClosed)

		level.Warn(log.Logger).Log(
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is closed", index+1),
		)

		if l.conn[index].GetConn() != nil {
			l.conn[index].GetConn().Close()
		}

		if err = l.conn[index].Connect(guid, l.conf[index]); err != nil {
			return
		}

		if l.poolType == definitions.LDAPPoolLookup || l.poolType == definitions.LDAPPoolUnknown {
			if err = l.conn[index].Bind(guid, l.conf[index]); err != nil {
				l.conn[index].GetConn().Close()

				return
			}
		}

		l.conn[index].SetState(definitions.LDAPStateBusy)
	}

	return
}

// sendLDAPReplyAndUnlockState sends the LDAPReply to the request's channel.
// It first frees the connection and releases the capacity token to avoid blocking resource release
// on a potentially unresponsive receiver. The reply is then delivered with a short timeout fallback.
func sendLDAPReplyAndUnlockState[T bktype.PoolRequest[T]](ldapPool *ldapPoolImpl, index int, request T, ldapReply *bktype.LDAPReply) {
	// 1) Free resources immediately
	ldapPool.conn[index].GetMutex().Lock()
	ldapPool.conn[index].SetState(definitions.LDAPStateFree)
	ldapPool.conn[index].GetMutex().Unlock()

	// Release capacity token back to the pool
	ldapPool.releaseToken()

	// 1.5) Trace release under the request context if available
	var rctx context.Context
	switch v := any(request).(type) {
	case *bktype.LDAPRequest:
		rctx = v.HTTPClientContext
	case *bktype.LDAPAuthRequest:
		rctx = v.HTTPClientContext
	default:
		rctx = ldapPool.ctx
	}

	tr := monittrace.New("nauthilus/ldap_pool")
	xctx, xsp := tr.Start(rctx, "ldap.pool.release_conn",
		attribute.String("pool_name", ldapPool.name),
		attribute.Int("index", index),
	)
	_ = xctx
	xsp.End()

	// 2) Deliver reply without risking a permanent block
	select {
	case request.GetLDAPReplyChan() <- ldapReply:
		// delivered
	case <-time.After(250 * time.Millisecond):
		level.Warn(log.Logger).Log(
			definitions.LogKeyLDAPPoolName, ldapPool.name,
			definitions.LogKeyMsg, "reply_channel_blocked_drop",
		)
	}
}

// processLookupSearchRequest processes an LDAP search request on a specific connection index in the LDAP pool.
// It sends the search result or any errors encountered to an LDAP reply structure.
func (l *ldapPoolImpl) processLookupSearchRequest(index int, ldapRequest *bktype.LDAPRequest, ldapReply *bktype.LDAPReply) {
	var (
		err       error
		result    bktype.AttributeMapping
		rawResult []*ldap.Entry
	)

	conf := l.conf[index]

	// Tracing: low-level LDAP search execution
	{
		tr := monittrace.New("nauthilus/ldap_ops")
		sctx, ssp := tr.Start(ldapRequest.HTTPClientContext, "ldap.search",
			attribute.String("pool_name", l.name),
			attribute.String("base_dn", ldapRequest.BaseDN),
			attribute.String("scope", ldapRequest.Scope.String()),
			attribute.String("filter", ldapRequest.Filter),
			attribute.Int("attrs_count", func() int {
				if ldapRequest.SearchAttributes == nil {
					return 0
				}

				return len(ldapRequest.SearchAttributes)
			}()),
			attribute.Int("timeout_ms", func() int {
				if conf.GetSearchTimeout() > 0 {
					return int(conf.GetSearchTimeout().Milliseconds())
				}

				return 0
			}()),
		)

		// Replace request context for downstream (if any LDAP client consults context)
		ldapRequest.HTTPClientContext = sctx

		defer func() {
			if err != nil {
				ssp.RecordError(err)
			}

			// On success or failure, set entries_count if available
			if rawResult != nil {
				ssp.SetAttributes(attribute.Int("entries_count", len(rawResult)))
			} else if result != nil {
				ssp.SetAttributes(attribute.Int("entries_count", len(result)))
			}

			ssp.End()
		}()
	}

	// Obtain per-pool negative cache engine (LRU per pool or shared TTL)
	cache := getNegCache(l.name, conf)

	// Set per-op timeout if configured
	if to := conf.GetSearchTimeout(); to > 0 {
		l.conn[index].GetConn().SetTimeout(to)
	}

	// Negative cache check by (pool|baseDN|filter)
	negKey := l.name + "|" + ldapRequest.BaseDN + "|" + ldapRequest.Filter
	if v, ok := cache.Get(negKey); ok {
		// Cache hit (negative)
		_ = v // value unused; presence is enough
		stats.GetMetrics().GetLdapCacheHitsTotal().WithLabelValues(l.name, "neg").Inc()
		stats.GetMetrics().GetLdapCacheEntries().WithLabelValues(l.name, "neg").Set(float64(cache.Len()))

		ldapReply.Result = make(bktype.AttributeMapping)

		// Optionally include raw result (none for negative)
		if ctxErr := ldapRequest.HTTPClientContext.Err(); ctxErr != nil {
			ldapReply.Err = ctxErr
		}

		return
	}

	stats.GetMetrics().GetLdapCacheMissesTotal().WithLabelValues(l.name, "neg").Inc()

	maxRetries := conf.GetRetryMax()
	base := conf.GetRetryBase()
	maxBackoff := conf.GetRetryMaxBackoff()

	// Singleflight protect identical misses to avoid stampedes
	type sfRes struct {
		res bktype.AttributeMapping
		raw []*ldap.Entry
		err error
	}

	val, _, _ := negSF.Do(negKey, func() (any, error) {
		var e error
		var r bktype.AttributeMapping
		var raw []*ldap.Entry

		for attempt := 0; attempt <= maxRetries; attempt++ {
			r, raw, e = l.conn[index].Search(ldapRequest)
			if e == nil || !isTransientNetworkError(e) {
				break
			}

			// retry on transient errors only
			stats.GetMetrics().GetLdapRetriesTotal().WithLabelValues(l.name, "search").Inc()
			time.Sleep(jitterBackoffDuration(base, attempt, maxBackoff))
		}

		return &sfRes{res: r, raw: raw, err: e}, nil
	})

	pack := val.(*sfRes)
	err = pack.err
	result = pack.res
	rawResult = pack.raw

	if err != nil {
		// error metric for search
		stats.GetMetrics().GetLdapErrorsTotal().WithLabelValues(l.name, "search", ldapErrorCode(err)).Inc()

		var (
			ldapError *ldap.Error
			doLog     bool
		)

		if stderrors.As(err, &ldapError) {
			if !(ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject)) {
				doLog = true
				ldapReply.Err = ldapError.Err
			} else {
				// Negative result: cache it
				negTTL := conf.GetNegativeCacheTTL()

				// If TTL <= 0, treat as disabled: do not store in negative cache.
				if negTTL > 0 {
					cache.Set(negKey, true, negTTL)
					stats.GetMetrics().GetLdapCacheEntries().WithLabelValues(l.name, "neg").Set(float64(cache.Len()))
				}
			}
		} else {
			doLog = true
			ldapReply.Err = err
		}

		if doLog {
			level.Error(log.Logger).Log(
				definitions.LogKeyLDAPPoolName, l.name,
				definitions.LogKeyGUID, ldapRequest.GUID,
				definitions.LogKeyMsg, "LDAP search error",
				definitions.LogKeyError, err,
			)
		}
	}

	ldapReply.Result = result
	if conf.GetIncludeRawResult() {
		ldapReply.RawResult = rawResult
	}

	// Also cache negatives when result is empty without LDAP error
	if err == nil {
		if len(result) == 0 {
			negTTL := conf.GetNegativeCacheTTL()

			cache.Set(negKey, true, negTTL)
			stats.GetMetrics().GetLdapCacheEntries().WithLabelValues(l.name, "neg").Set(float64(cache.Len()))
		}
	}

	if ctxErr := ldapRequest.HTTPClientContext.Err(); ctxErr != nil {
		ldapReply.Err = ctxErr
	}
}

// processLookupModifyRequest handles the Modify LDAP operation for the specified connection index.
// It executes the Modify command and updates the LDAPReply's error field if an error occurs.
func (l *ldapPoolImpl) processLookupModifyRequest(index int, ldapRequest *bktype.LDAPRequest, ldapReply *bktype.LDAPReply) {
	// Tracing: low-level LDAP modify execution
	tr := monittrace.New("nauthilus/ldap_ops")
	mctx, msp := tr.Start(ldapRequest.HTTPClientContext, "ldap.modify",
		attribute.String("pool_name", l.name),
		attribute.String("base_dn", ldapRequest.BaseDN),
		attribute.String("filter", ldapRequest.Filter),
		attribute.String("subcommand", func() string { return fmt.Sprintf("%d", ldapRequest.SubCommand) }()),
		attribute.Int("mod_count", func() int {
			if ldapRequest.ModifyAttributes == nil {
				return 0
			}

			return len(ldapRequest.ModifyAttributes)
		}()),
		attribute.Int("timeout_ms", func() int {
			if l.conf[index].GetModifyTimeout() > 0 {
				return int(l.conf[index].GetModifyTimeout().Milliseconds())
			}

			return 0
		}()),
	)

	// propagate for downstream
	ldapRequest.HTTPClientContext = mctx

	defer msp.End()

	// Set per-op timeout if configured
	if to := l.conf[index].GetModifyTimeout(); to > 0 {
		l.conn[index].GetConn().SetTimeout(to)
	}

	if err := l.conn[index].Modify(ldapRequest); err != nil {
		ldapReply.Err = err

		// error metric
		stats.GetMetrics().GetLdapErrorsTotal().WithLabelValues(l.name, "modify", ldapErrorCode(err)).Inc()
		msp.RecordError(err)
	}
}

// proccessLookupRequest processes an LDAP lookup request based on its command type and manages connection states.
func (l *ldapPoolImpl) proccessLookupRequest(index int, ldapRequest *bktype.LDAPRequest) {
	stopTimer := stats.PrometheusTimer(definitions.PromBackend, "ldap_backend_lookup_request_total")

	defer func() {
		if stopTimer != nil {
			stopTimer()
		}

		stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Dec()
	}()

	ldapReply := &bktype.LDAPReply{}

	if ldapReply.Err = l.checkConnection(ldapRequest.GUID, index); ldapReply.Err != nil {
		sendLDAPReplyAndUnlockState(l, index, ldapRequest, ldapReply)

		return
	}

	switch ldapRequest.Command {
	case definitions.LDAPSearch:
		l.processLookupSearchRequest(index, ldapRequest, ldapReply)
	case definitions.LDAPModify:
		l.processLookupModifyRequest(index, ldapRequest, ldapReply)
	}

	sendLDAPReplyAndUnlockState(l, index, ldapRequest, ldapReply)
}

// processAuthBindRequest handles the authentication bind request to an LDAP server for a specific connection index.
// It attempts to bind to the LDAP server using the credentials provided in the LDAPAuthRequest.
// If the bind operation or the HTTP client context encounters an error, it populates the LDAPReply with the error.
func (l *ldapPoolImpl) processAuthBindRequest(index int, ldapAuthRequest *bktype.LDAPAuthRequest, ldapReply *bktype.LDAPReply) {
	// Tracing: low-level LDAP bind execution
	tr := monittrace.New("nauthilus/ldap_ops")
	bctx, bsp := tr.Start(ldapAuthRequest.HTTPClientContext, "ldap.bind",
		attribute.String("pool_name", l.name),
		attribute.String("dn", ldapAuthRequest.BindDN),
		attribute.Int("timeout_ms", func() int {
			if l.conf[index].GetBindTimeout() > 0 {
				return int(l.conf[index].GetBindTimeout().Milliseconds())
			}

			return 0
		}()),
	)

	// propagate context for downstream
	ldapAuthRequest.HTTPClientContext = bctx

	defer bsp.End()

	// Apply per-op bind timeout if configured
	if to := l.conf[index].GetBindTimeout(); to > 0 {
		l.conn[index].GetConn().SetTimeout(to)
	}

	// Try to authenticate a user (no retries on auth failures).
	if err := l.conn[index].GetConn().Bind(ldapAuthRequest.BindDN, ldapAuthRequest.BindPW); err != nil {
		ldapReply.Err = err

		stats.GetMetrics().GetLdapErrorsTotal().WithLabelValues(l.name, "bind", ldapErrorCode(err)).Inc()
		bsp.RecordError(err)
	}

	/*
		// XXX: As the unbind() call closes the connection, we re-bind...
		ldapPool.conn[index].conn.unbind()
	*/

	if ctxErr := ldapAuthRequest.HTTPClientContext.Err(); ctxErr != nil {
		ldapReply.Err = ctxErr
	}
}

// processAuthRequest processes an LDAP authentication request by using a connection pool and handles related metrics.
func (l *ldapPoolImpl) processAuthRequest(index int, ldapAuthRequest *bktype.LDAPAuthRequest) {
	stopTimer := stats.PrometheusTimer(definitions.PromBackend, "ldap_backend_auth_request_total")

	defer func() {
		if stopTimer != nil {
			stopTimer()
		}

		stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Dec()
	}()

	ldapReply := &bktype.LDAPReply{}

	if ldapReply.Err = l.checkConnection(ldapAuthRequest.GUID, index); ldapReply.Err != nil {
		sendLDAPReplyAndUnlockState(l, index, ldapAuthRequest, ldapReply)

		return
	}

	l.processAuthBindRequest(index, ldapAuthRequest, ldapReply)

	sendLDAPReplyAndUnlockState(l, index, ldapAuthRequest, ldapReply)
}

// helper to extract an LDAP error code string for metrics
func ldapErrorCode(err error) string {
	if err == nil {
		return "0"
	}

	var le *ldap.Error
	if stderrors.As(err, &le) {
		return fmt.Sprintf("%d", le.ResultCode)
	}

	var ne net.Error
	if stderrors.As(err, &ne) {
		return "network"
	}

	return "other"
}

// --- Helpers for transient error detection and jittered backoff ---
func isTransientNetworkError(err error) bool {
	if err == nil {
		return false
	}

	var ne net.Error

	if stderrors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}

		// Best-effort: some implementations expose Temporary()
		type temporary interface{ Temporary() bool }

		if t, ok := any(ne).(temporary); ok && t.Temporary() {
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "eof") || strings.Contains(msg, "timeout") || strings.Contains(msg, "temporary") || strings.Contains(msg, "no route") {
		return true
	}

	return false
}

// jitterBackoffDuration calculates a jittered backoff duration for retries based on base, attempt, and max durations.
// The base duration is doubled with each attempt, capped at max, and random jitter is applied within the calculated bound.
func jitterBackoffDuration(base time.Duration, attempt int, max time.Duration) time.Duration {
	if base <= 0 {
		base = 200 * time.Millisecond
	}

	if max <= 0 {
		max = 2 * time.Second
	}

	b := base * time.Duration(1<<attempt)
	if b > max {
		b = max
	}

	if b <= 0 {
		return 0
	}

	return time.Duration(rand.Int63n(int64(b) + 1))
}
