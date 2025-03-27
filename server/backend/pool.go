package backend

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
)

// LDAPPool is an interface that represents a pool for managing LDAP connections and operations efficiently.
type LDAPPool interface {
	// StartHouseKeeper starts a background process for resource management and cleanup within the LDAP pool.
	StartHouseKeeper()

	// SetIdleConnections configures and manages idle connections in the pool based on the provided bind parameter.
	SetIdleConnections(bind bool) error

	// HandleLookupRequest handles an LDAP lookup request and utilizes a WaitGroup for managing concurrency.
	HandleLookupRequest(ldapRequest *LDAPRequest, ldapWaitGroup *sync.WaitGroup)

	// HandleAuthRequest processes an LDAP authentication request and manages concurrency using a WaitGroup.
	HandleAuthRequest(ldapAuthRequest *LDAPAuthRequest, ldapWaitGroup *sync.WaitGroup)

	// Close releases all resources used by the LDAPPool and terminates any background processes or connections.
	Close()
}

// ldapPoolImpl represents a pool of LDAP connections.
type ldapPoolImpl struct {
	// poolType denotes the type of the pool.
	poolType int

	// name specifies the name of the LDAP connection pool.
	name string

	// ctx is the context in which the LDAP connection pool operates.
	ctx context.Context

	// conn is the array of LDAP connections in the pool.
	conn []LDAPConnection

	// conf refers to the configuration details for the LDAP connections in the pool.
	conf []*config.LDAPConf
}

// StartHouseKeeper is a background task responsible for managing and cleaning up idle LDAP connections in the pool.
// It updates metrics and closes stale or excessive connections periodically while ensuring thread safety.
// The method operates in a loop, triggered by a 30-second ticker or context cancellation for graceful shutdown.
func (l *ldapPoolImpl) StartHouseKeeper() {
	idlePoolSize := l.getIdlePoolSize()
	timer := time.NewTicker(30 * time.Second)

	l.updateStatsPoolSize()

	// The list of connections is shared and must remain thread-safe. Length won't change inside this function.
	poolSize := len(l.conn)

	for {
		select {
		case <-l.ctx.Done():
			l.logCompletion()
			timer.Stop()

			return
		case <-timer.C:
			openConnections := l.updateConnectionsStatus(poolSize)
			stats.GetMetrics().GetLdapOpenConnections().WithLabelValues(l.name).Set(float64(openConnections))

			l.closeIdleConnections(openConnections, idlePoolSize, poolSize)
			l.updateStatsPoolSize()
		}
	}
}

// SetIdleConnections adjusts the number of idle connections in the LDAP connection pool based on its current state.
func (l *ldapPoolImpl) SetIdleConnections(bind bool) (err error) {
	poolSize := len(l.conn)
	idlePoolSize, openConnections := determineIdlePoolSize(l, poolSize)

	if openConnections < idlePoolSize {
		err = l.initializeConnections(bind, idlePoolSize, poolSize)
	}

	return
}

// HandleLookupRequest processes an LDAP lookup request using a connection pool and manages asynchronous execution.
func (l *ldapPoolImpl) HandleLookupRequest(ldapRequest *LDAPRequest, ldapWaitGroup *sync.WaitGroup) {
	connNumber := l.getConnection(ldapRequest.GUID, ldapWaitGroup)

	ldapWaitGroup.Add(1)
	stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Inc()

	go l.proccessLookupRequest(connNumber, ldapRequest, ldapWaitGroup)
}

// HandleAuthRequest processes an LDAP authentication request using the connection pool and updates process metrics.
func (l *ldapPoolImpl) HandleAuthRequest(ldapAuthRequest *LDAPAuthRequest, ldapWaitGroup *sync.WaitGroup) {
	connNumber := l.getConnection(ldapAuthRequest.GUID, ldapWaitGroup)

	ldapWaitGroup.Add(1)
	stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Inc()

	l.processAuthRequest(connNumber, ldapAuthRequest, ldapWaitGroup)
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

var _ LDAPPool = (*ldapPoolImpl)(nil)

// NewPool creates and initializes a new LDAPPool based on the specified pool type and context for LDAP operations.
func NewPool(ctx context.Context, poolType int) LDAPPool {
	var (
		poolSize int
		name     string
		conn     []LDAPConnection
		conf     []*config.LDAPConf
	)

	if config.GetFile().GetLDAP() == nil {
		return nil
	}

	switch poolType {
	case definitions.LDAPPoolLookup, definitions.LDAPPoolUnknown:
		name = "lookup"
		poolSize = config.GetFile().GetLDAPConfigLookupPoolSize()

		conf = make([]*config.LDAPConf, poolSize)
		conn = make([]LDAPConnection, poolSize)

	case definitions.LDAPPoolAuth:
		name = "auth"
		poolSize = config.GetFile().GetLDAPConfigAuthPoolSize()

		conf = make([]*config.LDAPConf, poolSize)
		conn = make([]LDAPConnection, poolSize)
	default:
		return nil
	}

	for index := 0; index < poolSize; index++ {
		conf[index] = &config.LDAPConf{}
		conn[index] = &LDAPConnectionImpl{}

		conf[index].ServerURIs = config.GetFile().GetLDAPConfigServerURIs()
		conf[index].BindDN = config.GetFile().GetLDAPConfigBindDN()
		conf[index].BindPW = config.GetFile().GetLDAPConfigBindPW()
		conf[index].StartTLS = config.GetFile().GetLDAPConfigStartTLS()
		conf[index].TLSSkipVerify = config.GetFile().GetLDAPConfigTLSSkipVerify()
		conf[index].TLSCAFile = config.GetFile().GetLDAPConfigTLSCAFile()
		conf[index].TLSClientCert = config.GetFile().GetLDAPConfigTLSClientCert()
		conf[index].TLSClientKey = config.GetFile().GetLDAPConfigTLSClientKey()
		conf[index].SASLExternal = config.GetFile().GetLDAPConfigSASLExternal()

		conn[index].SetState(definitions.LDAPStateClosed)
	}

	return &ldapPoolImpl{
		poolType: poolType,
		ctx:      ctx,
		name:     name,
		conn:     conn,
		conf:     conf,
	}
}

// getIdlePoolSize retrieves the idle pool size for the LDAP connection pool based on its type.
func (l *ldapPoolImpl) getIdlePoolSize() int {
	switch l.poolType {
	case definitions.LDAPPoolLookup, definitions.LDAPPoolUnknown:
		return config.GetFile().GetLDAPConfigLookupIdlePoolSize()
	case definitions.LDAPPoolAuth:
		return config.GetFile().GetLDAPConfigAuthIdlePoolSize()
	default:
		return 0
	}
}

// logCompletion logs a debug message indicating that the houseKeeper() method of LDAPPool has been terminated.
func (l *ldapPoolImpl) logCompletion() {
	util.DebugModule(definitions.DbgLDAP, definitions.LogKeyLDAPPoolName, l.name, definitions.LogKeyMsg, "houseKeeper() terminated")
}

// updateConnectionsStatus iterates through the connection pool and updates the status of each connection.
// It returns the total number of open connections after the update.
func (l *ldapPoolImpl) updateConnectionsStatus(poolSize int) (openConnections int) {
	for index := 0; index < poolSize; index++ {
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
func (l *ldapPoolImpl) closeIdleConnections(openConnections, idlePoolSize, poolSize int) {
	needClosing := max(openConnections-idlePoolSize, 0)

	stats.GetMetrics().GetLdapStaleConnections().WithLabelValues(l.name).Set(float64(needClosing))
	util.DebugModule(
		definitions.DbgLDAPPool,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyMsg, "State open connections", "needClosing", needClosing, "openConnections", openConnections, "idlePoolSize", idlePoolSize)

	//goland:noinspection GoDfaConstantCondition
	for index := 0; index < poolSize && needClosing > 0; index++ {
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

// determineIdlePoolSize calculates the number of idle connections in the pool and the total number of open connections.
func determineIdlePoolSize(l *ldapPoolImpl, poolSize int) (idlePoolSize int, openConnections int) {
	idlePoolSize = l.getIdlePoolSize()

	for index := 0; index < poolSize; index++ {
		if l.conn[index].GetState() != definitions.LDAPStateClosed {
			openConnections++
		}
	}

	return idlePoolSize, openConnections
}

// initializeConnections initializes a specified number of LDAP connections in the pool based on the provided parameters.
// It logs connection info and attempts to set up connections. If successful, it decrements the idle pool size.
// Returns an error if the required idle connections cannot be established within the pool size limit.
func (l *ldapPoolImpl) initializeConnections(bind bool, idlePoolSize int, poolSize int) (err error) {
	for index := 0; index < poolSize; index++ {
		guidStr := fmt.Sprintf("pool-#%d", index+1)

		l.logConnectionInfo(&guidStr, index)

		err = l.setupConnection(&guidStr, bind, index)
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
func (l *ldapPoolImpl) setupConnection(guid *string, bind bool, index int) error {
	var err error

	l.conn[index].GetMutex().Lock()

	defer l.conn[index].GetMutex().Unlock()

	if l.conn[index].GetState() == definitions.LDAPStateClosed {
		err = l.conn[index].Connect(guid, l.conf[index])
		if err != nil {
			l.logConnectionError(guid, err)
		} else {
			if bind {
				err = l.conn[index].Bind(guid, l.conf[index])
				if err != nil {
					l.logConnectionError(guid, err)
				} else {
					l.conn[index].SetState(definitions.LDAPStateFree)
				}
			} else {
				l.conn[index].SetState(definitions.LDAPStateFree)
			}
		}
	}

	return err
}

// logConnectionInfo logs information about an LDAP connection including pool name, GUID, and specific connection settings.
func (l *ldapPoolImpl) logConnectionInfo(guid *string, index int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, *guid,
		"ldap", l.conf[index].String(),
	)
}

// logConnectionError logs an error associated with an LDAP connection using the provided GUID and error message.
func (l *ldapPoolImpl) logConnectionError(guid *string, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, *guid,
		definitions.LogKeyMsg, err,
	)
}

// waitForFreeConnection waits for a free connection if the LDAP connection pool is exhausted and logs related events.
func (l *ldapPoolImpl) waitForFreeConnection(guid *string, ldapConnIndex int, ldapWaitGroup *sync.WaitGroup) {
	if ldapConnIndex == definitions.LDAPPoolExhausted {
		level.Warn(log.Logger).Log(
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyGUID, *guid,
			definitions.LogKeyMsg, "Pool exhausted. Waiting for a free connection")

		// XXX: Very hard decision, but an exhausted pool needs a human interaction!
		ldapWaitGroup.Wait()

		level.Warn(log.Logger).Log(
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyGUID, *guid,
			definitions.LogKeyMsg, "Pool got free connections")
	}
}

// getConnection retrieves an available LDAP connection number from the pool and waits if the pool is exhausted.
func (l *ldapPoolImpl) getConnection(guid *string, ldapWaitGroup *sync.WaitGroup) (connNumber int) {
EndlessLoop:
	for {
		for index := 0; index < len(l.conn); index++ {
			connNumber = l.processConnection(index, guid)
			if connNumber != definitions.LDAPPoolExhausted {
				break EndlessLoop
			}
		}

		l.waitForFreeConnection(guid, connNumber, ldapWaitGroup)
	}

	return connNumber
}

// processConnection manages the connection at the specified index in the LDAP pool to determine its usability and state.
// It locks the connection mutex, checks its current state, and either marks it busy, attempts reconnection, or skips it.
// Returns the connection index if usable, or LDAPPoolExhausted if no connection can be utilized.
func (l *ldapPoolImpl) processConnection(index int, guid *string) (connNumber int) {
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
func (l *ldapPoolImpl) logConnectionBusy(guid *string, index int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, *guid,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is busy, checking next", index+1),
	)
}

// logConnectionUsage logs debug information when a free LDAP connection is utilized by a specific GUID at a given index.
func (l *ldapPoolImpl) logConnectionUsage(guid *string, index int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, *guid,
		definitions.LogKeyMsg, fmt.Sprintf("Connection #%d is free, using it", index+1),
	)
}

// connectAndBindIfNeeded establishes a connection if needed and performs a bind operation based on the pool type configuration.
func (l *ldapPoolImpl) connectAndBindIfNeeded(guid *string, index int) error {
	err := l.conn[index].Connect(guid, l.conf[index])
	if err == nil && (l.poolType == definitions.LDAPPoolLookup || l.poolType == definitions.LDAPPoolUnknown) {
		err = l.conn[index].Bind(guid, l.conf[index])
	}

	return err
}

// logConnectionFailed logs a failed LDAP connection attempt with the pool name, session GUID, and error message.
func (l *ldapPoolImpl) logConnectionFailed(guid *string, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyLDAPPoolName, l.name,
		definitions.LogKeyGUID, *guid,
		definitions.LogKeyMsg, err)
}

// checkConnection ensures that the LDAP connection at the given index is valid and operational.
// If the connection is nil or closing, it attempts to reconnect and rebind based on the pool type.
// Returns an error if the connection restoration or binding fails.
func (l *ldapPoolImpl) checkConnection(guid *string, index int) (err error) {
	if l.conn[index].GetConn() == nil || l.conn[index].IsClosing() {
		l.conn[index].GetMutex().Lock()

		defer l.conn[index].GetMutex().Unlock()

		l.conn[index].SetState(definitions.LDAPStateClosed)

		level.Warn(log.Logger).Log(
			definitions.LogKeyLDAPPoolName, l.name,
			definitions.LogKeyGUID, *guid,
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

// sendLDAPReplyAndUnlockState sends the LDAPReply to the request's channel, sets the connection state to free, and unlocks it.
func sendLDAPReplyAndUnlockState[T PoolRequest[T]](ldapPool *ldapPoolImpl, index int, request T, ldapReply *LDAPReply) {
	request.GetLDAPReplyChan() <- ldapReply

	ldapPool.conn[index].GetMutex().Lock()

	ldapPool.conn[index].SetState(definitions.LDAPStateFree)

	ldapPool.conn[index].GetMutex().Unlock()
}

// processLookupSearchRequest processes an LDAP search request on a specific connection index in the LDAP pool.
// It sends the search result or any errors encountered to an LDAP reply structure.
func (l *ldapPoolImpl) processLookupSearchRequest(index int, ldapRequest *LDAPRequest, ldapReply *LDAPReply) {
	var (
		err       error
		result    DatabaseResult
		rawResult []*ldap.Entry
	)

	if result, rawResult, err = l.conn[index].Search(ldapRequest); err != nil {
		var (
			ldapError *ldap.Error
			doLog     bool
		)

		if stderrors.As(err, &ldapError) {
			if !(ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject)) {
				doLog = true
				ldapReply.Err = ldapError.Err
			}

			// Unknown user!
		} else {
			doLog = true
			ldapReply.Err = err
		}

		if doLog {
			level.Error(log.Logger).Log(
				definitions.LogKeyLDAPPoolName, l.name,
				definitions.LogKeyGUID, *ldapRequest.GUID,
				definitions.LogKeyMsg, ldapError.Error(),
			)
		}
	}

	ldapReply.Result = result
	ldapReply.RawResult = rawResult

	if ctxErr := ldapRequest.HTTPClientContext.Err(); ctxErr != nil {
		ldapReply.Err = ctxErr
	}
}

// processLookupModifyAddRequest handles the ModifyAdd LDAP operation for the specified connection index.
// It executes the ModifyAdd command and updates the LDAPReply's error field if an error occurs.
func (l *ldapPoolImpl) processLookupModifyAddRequest(index int, ldapRequest *LDAPRequest, ldapReply *LDAPReply) {
	if err := l.conn[index].ModifyAdd(ldapRequest); err != nil {
		ldapReply.Err = err
	}
}

// proccessLookupRequest processes an LDAP lookup request based on its command type and manages connection states.
func (l *ldapPoolImpl) proccessLookupRequest(index int, ldapRequest *LDAPRequest, ldapWaitGroup *sync.WaitGroup) {
	stopTimer := stats.PrometheusTimer(definitions.PromBackend, "ldap_backend_lookup_request_total")

	defer func() {
		if stopTimer != nil {
			stopTimer()
		}

		stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Dec()
		ldapWaitGroup.Done()
	}()

	ldapReply := &LDAPReply{}

	if ldapReply.Err = l.checkConnection(ldapRequest.GUID, index); ldapReply.Err != nil {
		ldapRequest.LDAPReplyChan <- ldapReply

		return
	}

	switch ldapRequest.Command {
	case definitions.LDAPSearch:
		l.processLookupSearchRequest(index, ldapRequest, ldapReply)
	case definitions.LDAPModifyAdd:
		l.processLookupModifyAddRequest(index, ldapRequest, ldapReply)
	}

	sendLDAPReplyAndUnlockState(l, index, ldapRequest, ldapReply)
}

// processAuthBindRequest handles the authentication bind request to an LDAP server for a specific connection index.
// It attempts to bind to the LDAP server using the credentials provided in the LDAPAuthRequest.
// If the bind operation or the HTTP client context encounters an error, it populates the LDAPReply with the error.
func (l *ldapPoolImpl) processAuthBindRequest(index int, ldapAuthRequest *LDAPAuthRequest, ldapReply *LDAPReply) {
	// Try to authenticate a user.
	if err := l.conn[index].GetConn().Bind(ldapAuthRequest.BindDN, ldapAuthRequest.BindPW); err != nil {
		ldapReply.Err = err
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
func (l *ldapPoolImpl) processAuthRequest(index int, ldapAuthRequest *LDAPAuthRequest, ldapWaitGroup *sync.WaitGroup) {
	stopTimer := stats.PrometheusTimer(definitions.PromBackend, "ldap_backend_auth_request_total")

	defer func() {
		if stopTimer != nil {
			stopTimer()
		}

		stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(l.name).Dec()
		ldapWaitGroup.Done()
	}()

	ldapReply := &LDAPReply{}

	if ldapReply.Err = l.checkConnection(ldapAuthRequest.GUID, index); ldapReply.Err != nil {
		ldapAuthRequest.LDAPReplyChan <- ldapReply

		return
	}

	l.processAuthBindRequest(index, ldapAuthRequest, ldapReply)

	sendLDAPReplyAndUnlockState(l, index, ldapAuthRequest, ldapReply)
}
