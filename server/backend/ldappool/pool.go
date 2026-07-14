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
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/ldapendpoint"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/croessner/nauthilus/v3/server/log/level"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
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

// Token describes the exported Token type.
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
	tokens chan Token

	cfg config.File

	logger *slog.Logger
}

type ldapPoolConfigSource struct {
	bindPW          secret.Value
	serverURIs      []string
	bindDN          string
	tlsCAFile       string
	tlsClientCert   string
	tlsClientKey    string
	numberOfWorkers int
	startTLS        bool
	tlsSkipVerify   bool
	saslExternal    bool
}

type ldapPoolLayout struct {
	name         string
	poolSize     int
	idlePoolSize int
}

type ldapSearchSingleflightResult struct {
	res bktype.AttributeMapping
	raw []*ldap.Entry
	err error
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

			closed := max(openBefore-openAfter, 0)

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
				_ = l.conn[index].GetConn().Close()
			}

			util.DebugModuleWithCfg(
				context.Background(),
				l.cfg,
				l.logger,
				definitions.DbgLDAP,
				definitions.LogKeyLDAPPoolName, l.name,
				definitions.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1),
			)
		}
	}

	util.DebugModuleWithCfg(
		context.Background(),
		l.cfg,
		l.logger,
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
	trOps = monittrace.New("nauthilus/ldap_ops")

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
		lru.SetOnEvict(func(_ string, _ any) {
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
func NewPool(ctx context.Context, cfg config.File, logger *slog.Logger, poolType int, poolName string) LDAPPool {
	if cfg.GetLDAP() == nil {
		panic("LDAP configuration is not set")
	}

	poolMap := cfg.GetLDAP().GetOptionalLDAPPools()
	source := resolveLDAPPoolConfigSource(cfg, poolMap, poolName)
	layout := resolveLDAPPoolLayout(cfg, poolMap, poolType, poolName)
	conf, conn := buildLDAPPoolConnections(layout, source)

	logLDAPPoolCreated(cfg, logger, poolType, source, layout)

	lp := newLDAPPoolImpl(ctx, cfg, logger, poolType, source, layout, conf, conn)
	seedLDAPPoolTokens(lp)
	startLDAPPoolHealthLoop(layout.name, conf)
	configureLDAPPoolAuthLimiter(poolType, layout.name, conf)

	return lp
}

// resolveLDAPPoolConfigSource resolves shared LDAP connection settings for the requested pool.
func resolveLDAPPoolConfigSource(cfg config.File, poolMap map[string]*config.LDAPConf, poolName string) ldapPoolConfigSource {
	if poolName == definitions.DefaultBackendName {
		return ldapPoolConfigSource{
			numberOfWorkers: cfg.GetLDAPConfigNumberOfWorkers(),
			serverURIs:      cfg.GetLDAPConfigServerURIs(),
			bindDN:          cfg.GetLDAPConfigBindDN(),
			bindPW:          cfg.GetLDAPConfigBindPW(),
			startTLS:        cfg.GetLDAPConfigStartTLS(),
			tlsSkipVerify:   cfg.GetLDAPConfigTLSSkipVerify(),
			tlsCAFile:       cfg.GetLDAPConfigTLSCAFile(),
			tlsClientCert:   cfg.GetLDAPConfigTLSClientCert(),
			tlsClientKey:    cfg.GetLDAPConfigTLSClientKey(),
			saslExternal:    cfg.GetLDAPConfigSASLExternal(),
		}
	}

	poolConfig := optionalLDAPPoolConfig(poolMap, poolName)

	return ldapPoolConfigSource{
		numberOfWorkers: poolConfig.GetNumberOfWorkers(),
		serverURIs:      poolConfig.ServerURIs,
		bindDN:          poolConfig.BindDN,
		bindPW:          poolConfig.BindPW,
		startTLS:        poolConfig.StartTLS,
		tlsSkipVerify:   poolConfig.TLSSkipVerify,
		tlsCAFile:       poolConfig.TLSCAFile,
		tlsClientCert:   poolConfig.TLSClientCert,
		tlsClientKey:    poolConfig.TLSClientKey,
		saslExternal:    poolConfig.SASLExternal,
	}
}

// optionalLDAPPoolConfig returns the named optional pool or panics with the existing message.
func optionalLDAPPoolConfig(poolMap map[string]*config.LDAPConf, poolName string) *config.LDAPConf {
	if poolMap == nil || poolMap[poolName] == nil {
		panic(fmt.Sprintf("LDAP pool %s is not defined", poolName))
	}

	return poolMap[poolName]
}

// resolveLDAPPoolLayout resolves the pool name and connection counts for the requested pool type.
func resolveLDAPPoolLayout(cfg config.File, poolMap map[string]*config.LDAPConf, poolType int, poolName string) ldapPoolLayout {
	switch poolType {
	case definitions.LDAPPoolLookup, definitions.LDAPPoolUnknown:
		return resolveLookupPoolLayout(cfg, poolMap, poolName)
	case definitions.LDAPPoolAuth:
		return resolveAuthPoolLayout(cfg, poolMap, poolName)
	default:
		panic(fmt.Sprintf("LDAP pool type %d is not supported", poolType))
	}
}

// resolveLookupPoolLayout resolves lookup pool dimensions.
func resolveLookupPoolLayout(cfg config.File, poolMap map[string]*config.LDAPConf, poolName string) ldapPoolLayout {
	if poolName == definitions.DefaultBackendName {
		return ldapPoolLayout{
			name:         "lookup",
			poolSize:     cfg.GetLDAPConfigLookupPoolSize(),
			idlePoolSize: cfg.GetLDAPConfigLookupIdlePoolSize(),
		}
	}

	poolConfig := optionalLDAPPoolConfig(poolMap, poolName)

	return ldapPoolLayout{
		name:         poolName + "-lookup",
		poolSize:     poolConfig.LookupPoolSize,
		idlePoolSize: poolConfig.LookupIdlePoolSize,
	}
}

// resolveAuthPoolLayout resolves auth pool dimensions.
func resolveAuthPoolLayout(cfg config.File, poolMap map[string]*config.LDAPConf, poolName string) ldapPoolLayout {
	if poolName == definitions.DefaultBackendName {
		return ldapPoolLayout{
			name:         "auth",
			poolSize:     cfg.GetLDAPConfigAuthPoolSize(),
			idlePoolSize: cfg.GetLDAPConfigAuthIdlePoolSize(),
		}
	}

	poolConfig := optionalLDAPPoolConfig(poolMap, poolName)

	return ldapPoolLayout{
		name:         poolName + "-auth",
		poolSize:     poolConfig.AuthPoolSize,
		idlePoolSize: poolConfig.AuthIdlePoolSize,
	}
}

// buildLDAPPoolConnections creates pool connections and per-connection configuration clones.
func buildLDAPPoolConnections(layout ldapPoolLayout, source ldapPoolConfigSource) ([]*config.LDAPConf, []LDAPConnection) {
	conf := make([]*config.LDAPConf, layout.poolSize)
	conn := make([]LDAPConnection, layout.poolSize)

	for index := 0; index < layout.poolSize; index++ {
		conf[index] = newLDAPPoolConnectionConfig(layout.name, source)
		conn[index] = &LDAPConnectionImpl{}
		conn[index].SetState(definitions.LDAPStateClosed)
	}

	return conf, conn
}

// newLDAPPoolConnectionConfig copies shared pool settings into one LDAPConf instance.
func newLDAPPoolConnectionConfig(poolName string, source ldapPoolConfigSource) *config.LDAPConf {
	return &config.LDAPConf{
		ServerURIs:    source.serverURIs,
		BindDN:        source.bindDN,
		BindPW:        source.bindPW,
		StartTLS:      source.startTLS,
		TLSSkipVerify: source.tlsSkipVerify,
		TLSCAFile:     source.tlsCAFile,
		TLSClientCert: source.tlsClientCert,
		TLSClientKey:  source.tlsClientKey,
		SASLExternal:  source.saslExternal,
		PoolName:      poolName,
	}
}

// logLDAPPoolCreated emits the existing pool-created debug event.
func logLDAPPoolCreated(cfg config.File, logger *slog.Logger, poolType int, source ldapPoolConfigSource, layout ldapPoolLayout) {
	util.DebugModuleWithCfg(
		context.Background(),
		cfg,
		logger,
		definitions.DbgLDAPPool,
		definitions.LogKeyMsg, "ldap_worker_created",
		definitions.LogKeyLDAPPoolName, layout.name,
		"number_of_workers", source.numberOfWorkers,
		"pool_type", poolType,
		"pool_size", layout.poolSize,
		"idle_pool_size", layout.idlePoolSize,
	)
}

// newLDAPPoolImpl assembles the LDAP pool implementation from resolved settings.
func newLDAPPoolImpl(
	ctx context.Context,
	cfg config.File,
	logger *slog.Logger,
	poolType int,
	source ldapPoolConfigSource,
	layout ldapPoolLayout,
	conf []*config.LDAPConf,
	conn []LDAPConnection,
) *ldapPoolImpl {
	return &ldapPoolImpl{
		numberOfWorkers: source.numberOfWorkers,
		poolType:        poolType,
		poolSize:        layout.poolSize,
		idlePoolSize:    layout.idlePoolSize,
		ctx:             ctx,
		name:            layout.name,
		conn:            conn,
		conf:            conf,
		cfg:             cfg,
		logger:          logger,
	}
}

// seedLDAPPoolTokens initializes the pool capacity semaphore.
func seedLDAPPoolTokens(lp *ldapPoolImpl) {
	lp.tokens = make(chan Token, lp.poolSize)
	for i := 0; i < lp.poolSize; i++ {
		lp.tokens <- Token{}
	}
}

// startLDAPPoolHealthLoop starts the active target health checker for this pool.
func startLDAPPoolHealthLoop(name string, conf []*config.LDAPConf) {
	if len(conf) > 0 && conf[0] != nil {
		go startHealthLoop(name, conf[0])
	}
}

// configureLDAPPoolAuthLimiter initializes the per-pool auth rate limiter when configured.
func configureLDAPPoolAuthLimiter(poolType int, name string, conf []*config.LDAPConf) {
	if poolType == definitions.LDAPPoolAuth && len(conf) > 0 && conf[0] != nil {
		rps := conf[0].GetAuthRateLimitPerSecond()
		burst := conf[0].GetAuthRateLimitBurst()

		if rps > 0 {
			lim := newTokenBucket(rps, burst)
			authLimiters.Store(name, lim)
		}
	}
}

// logCompletion logs a debug message indicating that the houseKeeper() method of LDAPPool has been terminated.
func (l *ldapPoolImpl) logCompletion() {
	util.DebugModuleWithCfg(context.Background(), l.cfg, l.logger, definitions.DbgLDAP, definitions.LogKeyLDAPPoolName, l.name, definitions.LogKeyMsg, "houseKeeper() terminated")
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

		util.DebugModuleWithCfg(
			context.Background(),
			l.cfg,
			l.logger,
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
		util.DebugModuleWithCfg(
			context.Background(),
			l.cfg,
			l.logger,
			definitions.DbgLDAPPool,
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d has broken connection", index+1))

		l.conn[index].SetConn(nil)
		l.conn[index].SetState(definitions.LDAPStateClosed)

		return 0
	}

	util.DebugModuleWithCfg(context.Background(), l.cfg, l.logger, definitions.DbgLDAPPool, definitions.LogKeyLDAPPoolName, l.name, definitions.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is free", index+1))

	return 1
}

// closeIdleConnections closes excess idle connections from the pool based on open connections, idle pool size, and total pool size.
func (l *ldapPoolImpl) closeIdleConnections(openConnections int) {
	needClosing := max(openConnections-l.idlePoolSize, 0)

	stats.GetMetrics().GetLdapStaleConnections().WithLabelValues(l.name).Set(float64(needClosing))
	util.DebugModuleWithCfg(
		context.Background(),
		l.cfg,
		l.logger,
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

	if c := l.conn[index].GetConn(); c != nil {
		_ = c.Close()
	}

	l.conn[index].SetState(definitions.LDAPStateClosed)

	util.DebugModuleWithCfg(
		context.Background(),
		l.cfg,
		l.logger,
		definitions.DbgLDAPPool,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1))

	return true
}

// updateStatsPoolSize updates the LDAP pool size metric based on the pool type. It handles lookup, unknown, and auth pool types.
func (l *ldapPoolImpl) updateStatsPoolSize() {
	switch l.poolType {
	case definitions.LDAPPoolLookup, definitions.LDAPPoolUnknown:
		stats.GetMetrics().GetLdapPoolSize().WithLabelValues(l.name).Set(float64(l.cfg.GetLDAPConfigLookupPoolSize()))
		stats.GetMetrics().GetLdapIdlePoolSize().WithLabelValues(l.name).Set(float64(l.cfg.GetLDAPConfigLookupIdlePoolSize()))
	case definitions.LDAPPoolAuth:
		stats.GetMetrics().GetLdapPoolSize().WithLabelValues(l.name).Set(float64(l.cfg.GetLDAPConfigAuthPoolSize()))
		stats.GetMetrics().GetLdapIdlePoolSize().WithLabelValues(l.name).Set(float64(l.cfg.GetLDAPConfigAuthIdlePoolSize()))
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

		l.logConnectionInfo(context.Background(), guidStr, index)

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
	sp := l.startConnectionOpenSpan(index)
	defer sp.End()

	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	err := l.openConnectionIfClosed(guid, bind, index, sp)
	if err != nil {
		return err
	}

	sp.SetAttributes(attribute.Bool("ok", true))

	return nil
}

// startConnectionOpenSpan starts the trace span for opening one pool connection.
func (l *ldapPoolImpl) startConnectionOpenSpan(index int) trace.Span {
	tr := monittrace.New("nauthilus/ldap_pool")
	_, sp := tr.Start(l.ctx, "ldap.pool.open_conn",
		attribute.String("pool_name", l.name),
		attribute.Int("index", index),
		attribute.String("server_uri", l.firstLDAPServerURIOrEmpty(index)),
		attribute.Bool("starttls", l.connectionStartTLS(index)),
		attribute.Bool("tls_skip_verify", l.connectionTLSSkipVerify(index)),
	)

	return sp
}

// openConnectionIfClosed connects and optionally binds a closed pool connection.
func (l *ldapPoolImpl) openConnectionIfClosed(guid string, bind bool, index int, sp trace.Span) error {
	if l.conn[index].GetState() != definitions.LDAPStateClosed {
		return nil
	}

	if err := l.conn[index].Connect(guid, l.cfg, l.logger, l.conf[index]); err != nil {
		l.logConnectionError(guid, err)
		sp.RecordError(err)

		return err
	}

	if bind {
		return l.bindOpenedConnection(guid, index, sp)
	}

	l.conn[index].SetState(definitions.LDAPStateFree)

	return nil
}

// bindOpenedConnection binds an opened connection and marks it free on success.
func (l *ldapPoolImpl) bindOpenedConnection(guid string, index int, sp trace.Span) error {
	if err := l.conn[index].Bind(context.Background(), guid, l.cfg, l.logger, l.conf[index]); err != nil {
		l.logConnectionError(guid, err)
		sp.RecordError(err)

		return err
	}

	l.conn[index].SetState(definitions.LDAPStateFree)

	return nil
}

// firstLDAPServerURIOrEmpty returns the first configured server URI for tracing.
func (l *ldapPoolImpl) firstLDAPServerURIOrEmpty(index int) string {
	raw, ok := l.firstLDAPServerURI(index)
	if !ok {
		return ""
	}

	return raw
}

// connectionStartTLS reports the StartTLS flag for a pool connection index.
func (l *ldapPoolImpl) connectionStartTLS(index int) bool {
	if l.conf == nil || index >= len(l.conf) || l.conf[index] == nil {
		return false
	}

	return l.conf[index].IsStartTLS()
}

// connectionTLSSkipVerify reports the TLS skip-verify flag for a pool connection index.
func (l *ldapPoolImpl) connectionTLSSkipVerify(index int) bool {
	if l.conf == nil || index >= len(l.conf) || l.conf[index] == nil {
		return false
	}

	return l.conf[index].IsTLSSkipVerify()
}

// logConnectionInfo logs information about an LDAP connection including pool name, GUID, and specific connection settings.
func (l *ldapPoolImpl) logConnectionInfo(ctx context.Context, guid string, index int) {
	util.DebugModuleWithCfg(
		ctx,
		l.cfg,
		l.logger,
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		"ldap", l.conf[index].String(),
	)
}

// logConnectionError logs an error associated with an LDAP connection using the provided GUID and error message.
func (l *ldapPoolImpl) logConnectionError(guid string, err error) {
	level.Error(l.logger).Log(
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "LDAP connection error",
		definitions.LogKeyError, err,
	)
}

// serverAddrPort derives server.address and server.port from the pool configuration
// for the given connection index. If the URI does not include an explicit port,
// the default is inferred from the scheme: 389 for ldap, 636 for ldaps.
func (l *ldapPoolImpl) serverAddrPort(index int) (string, int) {
	raw, ok := l.firstLDAPServerURI(index)
	if !ok {
		return "", 0
	}

	return ldapServerAddrPort(raw)
}

// firstLDAPServerURI returns the first configured server URI for a connection index.
func (l *ldapPoolImpl) firstLDAPServerURI(index int) (string, bool) {
	if l.conf == nil || index >= len(l.conf) || l.conf[index] == nil {
		return "", false
	}

	uris := l.conf[index].GetServerURIs()
	if len(uris) == 0 {
		return "", false
	}

	return uris[0], true
}

// ldapServerAddrPort parses an LDAP URI into OpenTelemetry server address and port values.
func ldapServerAddrPort(raw string) (string, int) {
	endpoint, err := ldapendpoint.Parse(raw)
	if err != nil {
		return "", 0
	}

	return endpoint.Host, endpoint.Port
}

// acquireTokenWithTimeout tries to acquire a capacity token from the pool within the configured timeout.
// It respects the provided context deadline and caps the wait by the configured connect_abort_timeout.
func (l *ldapPoolImpl) acquireTokenWithTimeout(reqCtx context.Context) error {
	connectAbortTimeout := l.cfg.GetLDAPConfigConnectAbortTimeout()
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
			return errors.ErrLDAPPoolExhausted.WithDetail("context timeout while waiting for LDAP token")
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

		return errors.ErrLDAPPoolExhausted.WithDetail("context timeout while waiting for LDAP token")
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
		return definitions.LDAPPoolExhausted, err
	}

	ctx, cancel, err := l.connectionWaitContext(reqCtx)
	if err != nil {
		l.releaseToken()

		return definitions.LDAPPoolExhausted, err
	}

	if cancel != nil {
		defer cancel()
	}

	return l.waitForFreeConnection(ctx, guid)
}

// connectionWaitContext bounds free-connection scanning by the configured abort timeout.
func (l *ldapPoolImpl) connectionWaitContext(reqCtx context.Context) (context.Context, func(), error) {
	ctx := reqCtx
	if ctx == nil {
		ctx = l.ctx
	}

	connectAbortTimeout := l.connectAbortTimeout()

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil, errors.ErrLDAPPoolExhausted.WithDetail("context timeout while waiting for free LDAP connection")
		}

		if remaining <= connectAbortTimeout {
			return ctx, nil, nil
		}
	}

	boundedCtx, cancel := context.WithTimeout(ctx, connectAbortTimeout)

	return boundedCtx, cancel, nil
}

// waitForFreeConnection scans pool slots until one can be borrowed or the wait context expires.
func (l *ldapPoolImpl) waitForFreeConnection(ctx context.Context, guid string) (int, error) {
	borrowStart := time.Now()

	for {
		for index := 0; index < len(l.conn); index++ {
			connNumber := l.processConnection(ctx, index, guid)
			if connNumber != definitions.LDAPPoolExhausted {
				l.traceBorrowedConnection(ctx, connNumber, borrowStart)

				return connNumber, nil
			}
		}

		// Check for timeout/cancel to prevent hanging if all connections remain busy
		select {
		case <-ctx.Done():
			// Release the token since we are aborting without acquiring a connection
			l.releaseToken()

			return definitions.LDAPPoolExhausted, errors.ErrLDAPPoolExhausted.WithDetail("context timeout while waiting for free LDAP connection")
		default:
			// Short backoff; token guarantees capacity, a subsequent scan should find a free/connected slot soon.
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// traceBorrowedConnection records a successful LDAP connection borrow.
func (l *ldapPoolImpl) traceBorrowedConnection(ctx context.Context, connNumber int, borrowStart time.Time) {
	tr := monittrace.New("nauthilus/ldap_pool")
	_, bsp := tr.Start(ctx, "ldap.pool.borrow_conn",
		attribute.String("pool_name", l.name),
		attribute.Int("index", connNumber),
		attribute.Int("waited_ms", int(time.Since(borrowStart).Milliseconds())),
	)

	bsp.End()
}

// connectAbortTimeout returns the configured LDAP connect abort timeout with the default fallback.
func (l *ldapPoolImpl) connectAbortTimeout() time.Duration {
	connectAbortTimeout := l.cfg.GetLDAPConfigConnectAbortTimeout()
	if connectAbortTimeout == 0 {
		return 10 * time.Second
	}

	return connectAbortTimeout
}

// processConnection manages the connection at the specified index in the LDAP pool to determine its usability and state.
// It locks the connection mutex, checks its current state, and either marks it busy, attempts reconnection, or skips it.
// Returns the connection index if usable, or LDAPPoolExhausted if no connection can be utilized.
func (l *ldapPoolImpl) processConnection(ctx context.Context, index int, guid string) (connNumber int) {
	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	// Connection is already in use, skip to next.
	if l.conn[index].GetState() == definitions.LDAPStateBusy {
		l.logConnectionBusy(ctx, guid, index)

		return definitions.LDAPPoolExhausted
	}

	// Connection is free, use it and mark it as busy.
	if l.conn[index].GetState() == definitions.LDAPStateFree {
		l.conn[index].SetState(definitions.LDAPStateBusy)

		l.logConnectionUsage(ctx, guid, index)

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

		l.logConnectionUsage(ctx, guid, index)

		return index
	}

	return definitions.LDAPPoolExhausted
}

// logConnectionBusy logs the event when the connection at the given index is busy and skips to check the next connection.
func (l *ldapPoolImpl) logConnectionBusy(ctx context.Context, guid string, index int) {
	util.DebugModuleWithCfg(
		ctx,
		l.cfg,
		l.logger,
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is busy, checking next", index+1),
	)
}

// logConnectionUsage logs debug information when a free LDAP connection is utilized by a specific GUID at a given index.
func (l *ldapPoolImpl) logConnectionUsage(ctx context.Context, guid string, index int) {
	util.DebugModuleWithCfg(
		ctx,
		l.cfg,
		l.logger,
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is free, using it", index+1),
	)
}

// connectAndBindIfNeeded establishes a connection if needed and performs a bind operation based on the pool type configuration.
func (l *ldapPoolImpl) connectAndBindIfNeeded(guid string, index int) error {
	err := l.conn[index].Connect(guid, l.cfg, l.logger, l.conf[index])
	if err == nil && (l.poolType == definitions.LDAPPoolLookup || l.poolType == definitions.LDAPPoolUnknown) {
		err = l.conn[index].Bind(context.Background(), guid, l.cfg, l.logger, l.conf[index])
	}

	return err
}

// logConnectionFailed logs a failed LDAP connection attempt with the pool name, session GUID, and error message.
func (l *ldapPoolImpl) logConnectionFailed(guid string, err error) {
	level.Error(l.logger).Log(
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

		level.Warn(l.logger).Log(
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is closed", index+1),
		)

		if l.conn[index].GetConn() != nil {
			_ = l.conn[index].GetConn().Close()
		}

		if err = l.conn[index].Connect(guid, l.cfg, l.logger, l.conf[index]); err != nil {
			return
		}

		if l.poolType == definitions.LDAPPoolLookup || l.poolType == definitions.LDAPPoolUnknown {
			if err = l.conn[index].Bind(context.Background(), guid, l.cfg, l.logger, l.conf[index]); err != nil {
				_ = l.conn[index].GetConn().Close()

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
		level.Warn(ldapPool.logger).Log(
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

	normalizeLookupSearchRequest(ldapRequest)

	conf := l.conf[index]

	searchSpan := l.startLDAPSearchSpan(index, ldapRequest, conf)
	defer finishLDAPSearchSpan(searchSpan, &err, &result, &rawResult)

	cache := getNegCache(l.name, conf)

	l.applySearchTimeout(index, conf)

	negKey := negativeLDAPCacheKey(l.name, ldapRequest)
	if l.applyNegativeCacheHit(cache, negKey, ldapRequest, ldapReply) {
		return
	}

	stats.GetMetrics().GetLdapCacheMissesTotal().WithLabelValues(l.name, "neg").Inc()

	result, rawResult, err = l.searchWithNegativeSingleflight(index, ldapRequest, conf, negKey)
	if err != nil {
		l.handleLDAPSearchError(err, conf, cache, negKey, ldapRequest, ldapReply)
	}

	l.applyLDAPSearchReply(conf, cache, negKey, ldapRequest, ldapReply, result, rawResult, err)
}

// normalizeLookupSearchRequest expands macros before negative-cache lookup and sanitizes the filter.
func normalizeLookupSearchRequest(ldapRequest *bktype.LDAPRequest) {
	if ldapRequest.MacroSource != nil {
		ldapRequest.Filter = util.ExpandLDAPFilter(ldapRequest.Filter, ldapRequest.MacroSource)
		ldapRequest.MacroSource = nil
	}

	ldapRequest.Filter = util.RemoveCRLFFromQueryOrFilter(ldapRequest.Filter, "")
}

// startLDAPSearchSpan starts low-level LDAP search tracing and updates the request context.
func (l *ldapPoolImpl) startLDAPSearchSpan(index int, ldapRequest *bktype.LDAPRequest, conf *config.LDAPConf) trace.Span {
	tr := monittrace.New("nauthilus/ldap_ops")
	srvAddr, srvPort := l.serverAddrPort(index)

	sctx, ssp := tr.StartClient(ldapRequest.HTTPClientContext, "ldap.search",
		attribute.String("rpc.system", "ldap"),
		semconv.PeerService("ldap"),
		semconv.ServerAddress(srvAddr),
		semconv.ServerPort(srvPort),
		attribute.String("ldap.operation", "search"),
		attribute.String("pool_name", l.name),
		attribute.String("base_dn", ldapRequest.BaseDN),
		attribute.String("scope", ldapRequest.Scope.String()),
		attribute.String("filter", ldapRequest.Filter),
		attribute.Int("attrs_count", len(ldapRequest.SearchAttributes)),
		attribute.Int("timeout_ms", ldapSearchTimeoutMilliseconds(conf)),
	)

	ldapRequest.HTTPClientContext = sctx

	return ssp
}

// finishLDAPSearchSpan records search outcome attributes and ends the span.
func finishLDAPSearchSpan(span trace.Span, err *error, result *bktype.AttributeMapping, rawResult *[]*ldap.Entry) {
	if *err != nil {
		span.RecordError(*err)
	}

	if *rawResult != nil {
		span.SetAttributes(attribute.Int("entries_count", len(*rawResult)))
	} else if *result != nil {
		span.SetAttributes(attribute.Int("entries_count", len(*result)))
	}

	span.End()
}

// ldapSearchTimeoutMilliseconds returns the configured search timeout in milliseconds.
func ldapSearchTimeoutMilliseconds(conf *config.LDAPConf) int {
	if conf.GetSearchTimeout() > 0 {
		return int(conf.GetSearchTimeout().Milliseconds())
	}

	return 0
}

// applySearchTimeout applies the per-operation LDAP search timeout to the active connection.
func (l *ldapPoolImpl) applySearchTimeout(index int, conf *config.LDAPConf) {
	if to := conf.GetSearchTimeout(); to > 0 {
		l.conn[index].GetConn().SetTimeout(to)
	}
}

// negativeLDAPCacheKey builds the negative-cache key after filter macro expansion.
func negativeLDAPCacheKey(poolName string, ldapRequest *bktype.LDAPRequest) string {
	return poolName + "|" + ldapRequest.BaseDN + "|" + ldapRequest.Filter
}

// applyNegativeCacheHit writes an empty reply when a negative-cache entry exists.
func (l *ldapPoolImpl) applyNegativeCacheHit(cache localcache.SimpleCache, negKey string, ldapRequest *bktype.LDAPRequest, ldapReply *bktype.LDAPReply) bool {
	if _, ok := cache.Get(negKey); !ok {
		return false
	}

	stats.GetMetrics().GetLdapCacheHitsTotal().WithLabelValues(l.name, "neg").Inc()
	l.recordNegativeCacheEntries(cache)

	ldapReply.Result = make(bktype.AttributeMapping)
	if ctxErr := ldapRequest.HTTPClientContext.Err(); ctxErr != nil {
		ldapReply.Err = ctxErr
	}

	return true
}

// searchWithNegativeSingleflight protects identical negative-cache misses from stampeding LDAP.
func (l *ldapPoolImpl) searchWithNegativeSingleflight(
	index int,
	ldapRequest *bktype.LDAPRequest,
	conf *config.LDAPConf,
	negKey string,
) (bktype.AttributeMapping, []*ldap.Entry, error) {
	val, _, _ := negSF.Do(negKey, func() (any, error) {
		result, rawResult, err := l.searchWithRetries(index, ldapRequest, conf)

		return &ldapSearchSingleflightResult{res: result, raw: rawResult, err: err}, nil
	})

	pack := val.(*ldapSearchSingleflightResult)

	return pack.res, pack.raw, pack.err
}

// searchWithRetries retries transient LDAP search failures according to pool settings.
func (l *ldapPoolImpl) searchWithRetries(index int, ldapRequest *bktype.LDAPRequest, conf *config.LDAPConf) (bktype.AttributeMapping, []*ldap.Entry, error) {
	var (
		err       error
		result    bktype.AttributeMapping
		rawResult []*ldap.Entry
	)

	for attempt := 0; attempt <= conf.GetRetryMax(); attempt++ {
		result, rawResult, err = l.conn[index].Search(ldapRequest.HTTPClientContext, l.cfg, l.logger, ldapRequest)
		if err == nil || !isTransientNetworkError(err) {
			break
		}

		stats.GetMetrics().GetLdapRetriesTotal().WithLabelValues(l.name, "search").Inc()
		time.Sleep(jitterBackoff(conf.GetRetryBase(), attempt, conf.GetRetryMaxBackoff()))
	}

	return result, rawResult, err
}

// handleLDAPSearchError maps LDAP search errors to replies, metrics, logs, and negative cache entries.
func (l *ldapPoolImpl) handleLDAPSearchError(
	err error,
	conf *config.LDAPConf,
	cache localcache.SimpleCache,
	negKey string,
	ldapRequest *bktype.LDAPRequest,
	ldapReply *bktype.LDAPReply,
) {
	stats.GetMetrics().GetLdapErrorsTotal().WithLabelValues(l.name, "search", ldapErrorCode(err)).Inc()

	if ldapError, ok := stderrors.AsType[*ldap.Error](err); ok {
		if l.handleTypedLDAPSearchError(err, ldapError, conf, cache, negKey, ldapReply) {
			l.logLDAPSearchError(ldapRequest, err)
		}

		return
	}

	if isTimeoutErr(err) {
		ldapReply.Err = errors.ErrLDAPSearchTimeout.WithDetail(err.Error())
	} else {
		ldapReply.Err = err
	}

	l.logLDAPSearchError(ldapRequest, err)
}

// handleTypedLDAPSearchError handles LDAP protocol errors and returns whether the error should be logged.
func (l *ldapPoolImpl) handleTypedLDAPSearchError(
	err error,
	ldapError *ldap.Error,
	conf *config.LDAPConf,
	cache localcache.SimpleCache,
	negKey string,
	ldapReply *bktype.LDAPReply,
) bool {
	if ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject) {
		l.cacheLDAPNegativeResult(cache, negKey, conf)

		return false
	}

	if isTimeoutErr(err) || ldapError.ResultCode == uint16(ldap.LDAPResultTimeLimitExceeded) {
		ldapReply.Err = errors.ErrLDAPSearchTimeout.WithDetail(err.Error())
	} else {
		ldapReply.Err = ldapError.Err
	}

	return true
}

// applyLDAPSearchReply copies search results into the reply and records cache/context side effects.
func (l *ldapPoolImpl) applyLDAPSearchReply(
	conf *config.LDAPConf,
	cache localcache.SimpleCache,
	negKey string,
	ldapRequest *bktype.LDAPRequest,
	ldapReply *bktype.LDAPReply,
	result bktype.AttributeMapping,
	rawResult []*ldap.Entry,
	err error,
) {
	ldapReply.Result = result
	if conf.GetIncludeRawResult() {
		ldapReply.RawResult = rawResult
	}

	if err == nil && len(result) == 0 {
		l.cacheLDAPNegativeResult(cache, negKey, conf)
	}

	if ctxErr := ldapRequest.HTTPClientContext.Err(); ctxErr != nil {
		ldapReply.Err = ctxErr
	}
}

// cacheLDAPNegativeResult stores a negative lookup when the configured TTL enables it.
func (l *ldapPoolImpl) cacheLDAPNegativeResult(cache localcache.SimpleCache, negKey string, conf *config.LDAPConf) {
	if negTTL := conf.GetNegativeCacheTTL(); negTTL > 0 {
		cache.Set(negKey, true, negTTL)
		l.recordNegativeCacheEntries(cache)
	}
}

// recordNegativeCacheEntries updates the negative-cache entry metric for the pool.
func (l *ldapPoolImpl) recordNegativeCacheEntries(cache localcache.SimpleCache) {
	stats.GetMetrics().GetLdapCacheEntries().WithLabelValues(l.name, "neg").Set(float64(cache.Len()))
}

// logLDAPSearchError logs a failed LDAP search with pool and request context.
func (l *ldapPoolImpl) logLDAPSearchError(ldapRequest *bktype.LDAPRequest, err error) {
	level.Error(l.logger).Log(
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, ldapRequest.GUID,
		definitions.LogKeyMsg, "LDAP search error",
		definitions.LogKeyError, err,
	)
}

// processLookupModifyRequest handles the Modify LDAP operation for the specified connection index.
// It executes the Modify command and updates the LDAPReply's error field if an error occurs.
func (l *ldapPoolImpl) processLookupModifyRequest(index int, ldapRequest *bktype.LDAPRequest, ldapReply *bktype.LDAPReply) {
	// Tracing: low-level LDAP modify execution
	tr := monittrace.New("nauthilus/ldap_ops")

	// derive server.address/port
	srvAddr, srvPort := l.serverAddrPort(index)

	mctx, msp := tr.StartClient(ldapRequest.HTTPClientContext, "ldap.modify",
		attribute.String("rpc.system", "ldap"),
		attribute.String("peer.service", "ldap"),
		attribute.String("peer.address", srvAddr),
		attribute.Int("peer.port", srvPort),
		attribute.String("ldap.operation", "modify"),
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

	if err := l.conn[index].Modify(ldapRequest.HTTPClientContext, l.cfg, l.logger, ldapRequest); err != nil {
		ldapReply.Err = err

		// error metric
		stats.GetMetrics().GetLdapErrorsTotal().WithLabelValues(l.name, "modify", ldapErrorCode(err)).Inc()
		msp.RecordError(err)
	}
}

// proccessLookupRequest processes an LDAP lookup request based on its command type and manages connection states.
func (l *ldapPoolImpl) proccessLookupRequest(index int, ldapRequest *bktype.LDAPRequest) {
	_, span := trOps.Start(ldapRequest.HTTPClientContext, "ldap.worker.process_request",
		attribute.String("pool", l.name),
		attribute.Int("index", index),
	)
	defer span.End()

	stopTimer := stats.PrometheusTimer(l.cfg, definitions.PromBackend, "ldap_backend_lookup_request_total", l.name)

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

	// derive server.address/port
	srvAddr, srvPort := l.serverAddrPort(index)

	bctx, bsp := tr.StartClient(ldapAuthRequest.HTTPClientContext, "ldap.bind",
		attribute.String("rpc.system", "ldap"),
		attribute.String("peer.service", "ldap"),
		attribute.String("peer.address", srvAddr),
		attribute.Int("peer.port", srvPort),
		attribute.String("ldap.operation", "bind"),
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
		if isTimeoutErr(err) || isLDAPTimeLimitExceeded(err) {
			ldapReply.Err = errors.ErrLDAPBindTimeout.WithDetail(err.Error())
		} else {
			ldapReply.Err = err
		}

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
	_, span := trOps.Start(ldapAuthRequest.HTTPClientContext, "ldap.worker.process_auth_request",
		attribute.String("pool", l.name),
		attribute.Int("index", index),
	)
	defer span.End()

	stopTimer := stats.PrometheusTimer(l.cfg, definitions.PromBackend, "ldap_backend_auth_request_total", l.name)

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

	if le, ok := stderrors.AsType[*ldap.Error](err); ok {
		return fmt.Sprintf("%d", le.ResultCode)
	}

	if _, ok := stderrors.AsType[net.Error](err); ok {
		return "network"
	}

	return "other"
}

// --- Helpers for transient error detection and jittered backoff ---
// isTimeoutErr determines whether the given error represents a timeout
// condition (client-side context deadline exceeded or net timeout). It also
// unwraps common LDAP error wrappers.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}

	// context deadline exceeded
	if stderrors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// net.Error with Timeout() == true
	if ne, ok := stderrors.AsType[net.Error](err); ok && ne.Timeout() {
		return true
	}

	// LDAP error may wrap an underlying timeout
	if le, ok := stderrors.AsType[*ldap.Error](err); ok {
		if le != nil && le.Err != nil {
			if isTimeoutErr(le.Err) {
				return true
			}
		}
	}

	// Fallback by message
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") {
		return true
	}

	return false
}

// isLDAPTimeLimitExceeded checks if the error corresponds to the server-side
// time limit exceeded condition for LDAP operations.
func isLDAPTimeLimitExceeded(err error) bool {
	if err == nil {
		return false
	}

	if le, ok := stderrors.AsType[*ldap.Error](err); ok {
		if le.ResultCode == uint16(ldap.LDAPResultTimeLimitExceeded) {
			return true
		}
	}

	return false
}

func isTransientNetworkError(err error) bool {
	if err == nil {
		return false
	}

	if ne, ok := stderrors.AsType[net.Error](err); ok {
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
