package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
)

var (
	// LDAPEndChan is the quit-channel for LDAP on shutdown.
	LDAPEndChan chan Done //nolint:gochecknoglobals // Quit-Channel for LDAP on shutdown

	// LDAPRequestChan is a channel for sending LDAP requests.
	LDAPRequestChan chan *LDAPRequest //nolint:gochecknoglobals // Needed for LDAP pooling

	// LDAPAuthEndChan is the quit-channel for LDAP authentication on shutdown.
	LDAPAuthEndChan chan Done //nolint:gochecknoglobals // Quit-Channel for LDAP on shutdown

	// LDAPAuthRequestChan is a channel for sending LDAP authentication requests.
	LDAPAuthRequestChan chan *LDAPAuthRequest //nolint:gochecknoglobals // Needed for LDAP pooling
)

// LDAPConnection represents the connection with an LDAP server.
// It encapsulates the LDAP connection state and provides a means to synchronize access to it.
type LDAPConnection struct {
	// ldapConnectionState holds the current state of the LDAP connection.
	ldapConnectionState

	// Mu is a Mutex used to synchronize access to the Conn field,
	// essential when multiple goroutines need to access or modify the same connection concurrently.
	Mu sync.Mutex

	// Conn is the active LDAP connection. It is a pointer to an ldap.Conn object.
	Conn *ldap.Conn
}

// LDAPPool represents a pool of LDAP connections.
type LDAPPool struct {
	// poolType denotes the type of the pool.
	poolType int

	// name specifies the name of the LDAP connection pool.
	name string

	// ctx is the context in which the LDAP connection pool operates.
	ctx context.Context

	// conn is the array of LDAP connections in the pool.
	conn []*LDAPConnection

	// conf refers to the configuration details for the LDAP connections in the pool.
	conf []*config.LDAPConf
}

// LDAPModifyAttributes represents a type that maps attribute names to slices of string values.
// This structure is typically used in LDAP operations to modify the attributes of uniquely identified objects/entities.
//
// Key (of type string) - Represents the name of the attribute. The key might be the standard or user-defined attribute name.
// Value (of type []string) - Represents a slice of strings for the attribute values. These are the values that are assigned to the respective attribute.
type LDAPModifyAttributes map[string][]string

// LDAPRequest represents an LDAP request.
type LDAPRequest struct {
	// GUID is the globally unique identifier for this LDAP request, optional.
	GUID *string

	// Filter is the criteria that the LDAP request uses to filter during the search.
	Filter string

	// BaseDN is the base distinguished name used as the search base.
	BaseDN string

	// SearchAttributes are the attributes for which values are to be returned in the search results.
	SearchAttributes []string

	// MacroSource is the source of macros to be used, optional.
	MacroSource *util.MacroSource

	// Scope defines the scope for LDAP search (base, one, or sub).
	Scope config.LDAPScope

	// Command represents the LDAP command to be executed (add, modify, delete, or search).
	Command global.LDAPCommand

	// ModifyAttributes contains attributes information used in modify command.
	ModifyAttributes LDAPModifyAttributes

	// LDAPReplyChan is the channel where reply from LDAP server is sent.
	LDAPReplyChan chan *LDAPReply

	// HTTPClientContext is the context for managing HTTP requests and responses.
	HTTPClientContext context.Context
}

// LDAPAuthRequest represents a request to authenticate with an LDAP server.
type LDAPAuthRequest struct {
	// GUID is the unique identifier for the LDAP auth request.
	// It can be nil.
	GUID *string

	// BindDN is the Distinguished Name for binding to the LDAP server.
	BindDN string

	// BindPW is the password for binding to the LDAP server.
	BindPW string

	// LDAPReplyChan is a channel where the LDAP responses will be sent.
	LDAPReplyChan chan *LDAPReply

	// HTTPClientContext is the context for the HTTP client
	// carrying the LDAP auth request.
	HTTPClientContext context.Context
}

// LDAPReply encapsulates the result of an LDAP operation.
// It holds the results from both the database and the LDAP directory,
// as well as any error that might have occurred during the operation.
type LDAPReply struct {
	// Result holds the result retrieved from the database.
	// It is of type DatabaseResult which can accommodate different types of database operations.
	Result DatabaseResult

	// RawResult holds a list of entries returned by the LDAP operation.
	// It is an array of pointers to ldap.Entry objects.
	// Each ldap.Entry object represents a single directory entry in the LDAP directory.
	RawResult []*ldap.Entry

	// Err holds any error that occurred during the LDAP operation.
	// It is of type 'error', the built-in interface type for representing an error condition.
	Err error
}

// ldapConnectionState is a struct that helps manage LDAP connections,
// by keeping track of the connection's current state.
type ldapConnectionState struct {
	// state indicates the current LDAP connection state.
	// The value is a constant from the global.LDAPState set.
	state global.LDAPState
}

// NewPool creates a new LDAPPool object based on the provided context and poolType.
// If config.LoadableConfig.LDAP is nil, it returns nil.
// The poolType can be global.LDAPPoolLookup, global.LDAPPoolUnknown, or global.LDAPPoolAuth.
// It initializes the name and poolSize variables based on the poolType.
// It creates slices for the conn and conf variables based on the poolSize.
// It iterates through the poolSize and initializes each element of conf and conn.
// Then it assigns values from config.LoadableConfig to each element of conf and sets the state of each element of conn to global.LDAPStateClosed.
// Finally, it returns an LDAPPool object with the provided context, name, conn, and conf.
func NewPool(ctx context.Context, poolType int) *LDAPPool {
	var (
		poolSize int
		name     string
		conn     []*LDAPConnection
		conf     []*config.LDAPConf
	)

	if config.LoadableConfig.LDAP == nil {
		return nil
	}

	switch poolType {
	case global.LDAPPoolLookup, global.LDAPPoolUnknown:
		name = "lookup"
		poolSize = config.LoadableConfig.GetLDAPConfigLookupPoolSize()

		conf = make([]*config.LDAPConf, poolSize)
		conn = make([]*LDAPConnection, poolSize)

	case global.LDAPPoolAuth:
		name = "auth"
		poolSize = config.LoadableConfig.GetLDAPConfigAuthPoolSize()

		conf = make([]*config.LDAPConf, poolSize)
		conn = make([]*LDAPConnection, poolSize)
	default:
		return nil
	}

	for index := 0; index < poolSize; index++ {
		conf[index] = &config.LDAPConf{}
		conn[index] = &LDAPConnection{}

		conf[index].ServerURIs = config.LoadableConfig.GetLDAPConfigServerURIs()
		conf[index].BindDN = config.LoadableConfig.GetLDAPConfigBindDN()
		conf[index].BindPW = config.LoadableConfig.GetLDAPConfigBindPW()
		conf[index].StartTLS = config.LoadableConfig.GetLDAPConfigStartTLS()
		conf[index].TLSSkipVerify = config.LoadableConfig.GetLDAPConfigTLSSkipVerify()
		conf[index].TLSCAFile = config.LoadableConfig.GetLDAPConfigTLSCAFile()
		conf[index].TLSClientCert = config.LoadableConfig.GetLDAPConfigTLSClientCert()
		conf[index].TLSClientKey = config.LoadableConfig.GetLDAPConfigTLSClientKey()
		conf[index].SASLExternal = config.LoadableConfig.GetLDAPConfigSASLExternal()

		conn[index].state = global.LDAPStateClosed
	}

	return &LDAPPool{
		ctx:  ctx,
		name: name,
		conn: conn,
		conf: conf,
	}
}

// Close closes all connections in the LDAPPool. It iterates over each connection in the pool and performs the following actions:
// - If the connection is not nil, it calls the unbind method on the connection.
// - If the connection is still not nil, it closes the connection.
// - Logs a debug message indicating that the connection has been closed.
// After closing all connections, it logs a debug message indicating that the pool has been terminated.
func (l *LDAPPool) Close() {
	for index := 0; index < len(l.conn); index++ {
		if l.conn[index].Conn != nil {
			_ = l.conn[index].unbind()
			if l.conn[index].Conn != nil {
				l.conn[index].Conn.Close()
			}

			util.DebugModule(
				global.DbgLDAP,
				global.LogKeyLDAPPoolName, l.name,
				global.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1),
			)
		}
	}

	util.DebugModule(
		global.DbgLDAP,
		global.LogKeyLDAPPoolName, l.name,
		global.LogKeyMsg, "Terminated",
	)
}

// getIdlePoolSize returns the idle pool size based on the LDAP pool type.
// It checks the value of `l.poolType` and returns the corresponding idle pool size from the configuration.
// If the pool type is `LDAPPoolLookup` or `LDAPPoolUnknown`, it returns the idle pool size from `config.LoadableConfig.GetLDAPConfigLookupIdlePoolSize()`.
// If the pool type is `LDAPPoolAuth`, it returns the idle pool size from `config.LoadableConfig.GetLDAPConfigAuthIdlePoolSize()`.
// For any other pool type, it returns 0.
func (l *LDAPPool) getIdlePoolSize() int {
	switch l.poolType {
	case global.LDAPPoolLookup, global.LDAPPoolUnknown:
		return config.LoadableConfig.GetLDAPConfigLookupIdlePoolSize()
	case global.LDAPPoolAuth:
		return config.LoadableConfig.GetLDAPConfigAuthIdlePoolSize()
	default:
		return 0
	}
}

// logCompletion logs a debug message indicating that the houseKeeper() method of LDAPPool has been terminated.
func (l *LDAPPool) logCompletion() {
	util.DebugModule(global.DbgLDAP, global.LogKeyLDAPPoolName, l.name, global.LogKeyMsg, "houseKeeper() terminated")
}

// updateConnectionsStatus updates the status of all connections in the LDAPPool.
// It iterates over each connection in the pool and calls the updateSingleConnectionStatus method to update the status of the connection.
// It returns the total number of open connections.
func (l *LDAPPool) updateConnectionsStatus(poolSize int) (openConnections int) {
	for index := 0; index < poolSize; index++ {
		openConnections += l.updateSingleConnectionStatus(index)
	}

	return openConnections
}

// updateSingleConnectionStatus updates the status of a single LDAP connection in the pool.
// It takes an index parameter which indicates the index of the connection to be updated.
// The function performs the following actions:
//   - Locks the connection's mutex using `Mu.Lock()` to ensure thread safety.
//   - Checks if the connection's state is not `LDAPStateFree` or if the connection is nil or closing.
//     If any of these conditions are true, it sets the connection's state to `LDAPStateClosed`,
//     logs a debug message indicating that the connection is busy or closed, and returns 0.
//   - If the above conditions are not met, it performs an LDAP search operation on the connection using the `search` method.
//     If there is an error during the search, it sets the connection to nil, sets the state to `LDAPStateClosed`,
//     logs a debug message indicating that the connection is broken, and returns 0.
//   - If the search operation is successful, it logs a debug message indicating that the connection is free and returns 1.
//   - Unlocks the connection's mutex using `Mu.Unlock()` to release the lock.
//
// The function returns an integer indicating the updated status of the connection.
func (l *LDAPPool) updateSingleConnectionStatus(index int) int {
	l.conn[index].Mu.Lock()

	defer l.conn[index].Mu.Unlock()

	if l.conn[index].state != global.LDAPStateFree || l.conn[index].Conn == nil || l.conn[index].Conn.IsClosing() {
		l.conn[index].state = global.LDAPStateClosed

		util.DebugModule(global.DbgLDAPPool, global.LogKeyLDAPPoolName, l.name, global.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is busy or closed", index+1))

		return 0
	}

	if _, err := l.conn[index].Conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", []string{"1.1"}, nil)); err != nil {
		util.DebugModule(global.DbgLDAPPool, global.LogKeyLDAPPoolName, l.name, global.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d has broken connection", index+1))

		l.conn[index].Conn = nil
		l.conn[index].state = global.LDAPStateClosed

		return 0
	}

	util.DebugModule(global.DbgLDAPPool, global.LogKeyLDAPPoolName, l.name, global.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is free", index+1))

	return 1
}

// closeIdleConnections method on the LDAPPool structure decreases open connections in LDAPPool.
// It evaluates the total number of connections that need to be closed which are idle by evaluating
// the difference between openConnections and idlePoolSize. The difference is adjusted to 0 if negative.
//
// Iteratively, the method tries to close idle connections until we reach the desired poolSize or until
// there are no more connections that need closing, whichever comes first.
// The method keeps track of the total connections closed and adjust the count stored in the variable needClosing.
//
// Parameters:
// openConnections (int): Number of current open connections.
// idlePoolSize (int): Size of idlepool.
// poolSize (int): Maximum size of the connection pool.
//
// The method is not expected to return anything.
func (l *LDAPPool) closeIdleConnections(openConnections, idlePoolSize, poolSize int) {
	needClosing := max(openConnections-idlePoolSize, 0)

	util.DebugModule(global.DbgLDAPPool, global.LogKeyLDAPPoolName, l.name, global.LogKeyMsg, "State open connections", "needClosing", needClosing, "openConnections", openConnections, "idlePoolSize", idlePoolSize)

	for index := 0; index < poolSize && needClosing > 0; index++ {
		if l.closeSingleIdleConnection(index) {
			needClosing--
		}
	}
}

// closeSingleIdleConnection closes a single idle connection in the LDAPPool at the specified index.
// It acquires the lock on the connection to ensure thread safety.
// If the state of the connection is not "free", it returns false.
// Otherwise, it closes the connection, updates the state to "closed", and logs a debug message indicating the connection has been closed.
// Finally, it returns true to indicate that the connection has been closed successfully.
func (l *LDAPPool) closeSingleIdleConnection(index int) bool {
	l.conn[index].Mu.Lock()

	defer l.conn[index].Mu.Unlock()

	if l.conn[index].state != global.LDAPStateFree {
		return false
	}

	l.conn[index].Conn.Close()
	l.conn[index].state = global.LDAPStateClosed

	util.DebugModule(global.DbgLDAPPool, global.LogKeyLDAPPoolName, l.name, global.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1))

	return true
}

// houseKeeper is a method of the LDAPPool struct. It constantly updates the status of connections,
// closes any idle connections, and stops if the context is done. It uses a ticker for regular updates.
// This function ensures that the pool of connections remains thread-safe.
// The function also calls logCompletion once the context is done.
func (l *LDAPPool) houseKeeper() {
	idlePoolSize := l.getIdlePoolSize()
	timer := time.NewTicker(30 * time.Second)

	// List of connections is shared and must remain thread-safe. Length won't change inside this function.
	poolSize := len(l.conn)

	for {
		select {
		case <-l.ctx.Done():
			l.logCompletion()
			timer.Stop()

			return
		case <-timer.C:
			openConnections := l.updateConnectionsStatus(poolSize)

			l.closeIdleConnections(openConnections, idlePoolSize, poolSize)
		}
	}
}

// determineIdlePoolSize calculates and returns the size of the idlePool and
// the number of open connections. It takes a pointer to an LDAPPool
// and an integer representing the size of the pool as parameters.
//
// For each index in the poolSize it checks the state of the connection
// at that index and increments the openConnections counter
// each time it encounters a connection that is not closed.
//
// It returns the size of the idlePool and the number of openConnections.
func determineIdlePoolSize(l *LDAPPool, poolSize int) (idlePoolSize int, openConnections int) {
	idlePoolSize = l.getIdlePoolSize()

	for index := 0; index < poolSize; index++ {
		if l.conn[index].state != global.LDAPStateClosed {
			openConnections++
		}
	}

	return idlePoolSize, openConnections
}

// initializeConnections initializes the connections for the given LDAPPool object l.
// It takes a boolean bind parameter to specify whether to perform binding on the connections.
// The idlePoolSize parameter specifies the number of connections to initialize.
// It creates a WaitGroup wg and sets diffConnections to the idlePoolSize.
//
// It then iterates through the idlePoolSize and performs the following steps:
// - Increments the WaitGroup wg by 1.
// - Generates a unique GUID string based on the index.
// - Logs the connection info using the logConnectionInfo method of the LDAPPool.
// - Calls the setupConnection method of the LDAPPool to set up the connection.
//   - If the setupConnection method returns nil (no error), it decrements diffConnections by 1.
//
// - Checks if diffConnections is equal to 0. If so, it breaks the loop.
//
// Finally, it checks if diffConnections is not equal to 0 and waits for all goroutines to complete using the Wait method of the WaitGroup wg.
func initializeConnections(l *LDAPPool, bind bool, idlePoolSize int) {
	wg := sync.WaitGroup{}
	diffConnections := idlePoolSize

	for index := 0; index < idlePoolSize; index++ {
		wg.Add(1)

		guidStr := fmt.Sprintf("pool-#%d", index+1)

		l.logConnectionInfo(&guidStr, index)

		err := l.setupConnection(&guidStr, bind, index)
		if err == nil {
			diffConnections--
		}

		if diffConnections == 0 {
			break
		}
	}

	if diffConnections != 0 {
		wg.Wait()
	}
}

// setupConnection sets up a connection in the LDAPPool. It takes the following parameters:
// - `guid *string`: The unique identifier for the connection.
// - `bind bool`: A flag indicating whether the connection needs to be bound or not.
// - `index int`: The index of the connection in the pool.
//
// The function performs the following steps:
// 1. It locks the connection mutex to ensure exclusive access to the connection.
// 2. If the connection's state is `LDAPStateClosed`, it calls the `connect` method on the connection to establish a new connection.
//   - If an error occurs during the connection setup, it calls the `logConnectionError` method to log the error.
//   - If no error occurs, it checks if `bind` flag is `true`.
//   - If `bind` is `true`, it calls the `bind` method on the connection to perform the binding.
//   - If an error occurs during the binding, it calls the `logConnectionError` method to log the error.
//   - If no error occurs, it sets the connection's state to `LDAPStateFree`.
//   - If `bind` is `false`, it directly sets the connection's state to `LDAPStateFree`.
//
// 3. It unlocks the connection mutex.
//
// The function returns an error, which will be nil if no errors occurred during the connection setup and binding.
func (l *LDAPPool) setupConnection(guid *string, bind bool, index int) error {
	var err error

	l.conn[index].Mu.Lock()

	defer l.conn[index].Mu.Unlock()

	if l.conn[index].state == global.LDAPStateClosed {
		err = l.conn[index].connect(guid, l.conf[index])
		if err != nil {
			l.logConnectionError(guid, err)
		} else {
			if bind {
				err = l.conn[index].bind(guid, l.conf[index])
				if err != nil {
					l.logConnectionError(guid, err)
				} else {
					l.conn[index].state = global.LDAPStateFree
				}
			} else {
				l.conn[index].state = global.LDAPStateFree
			}
		}
	}

	return err
}

// logConnectionInfo logs the connection information for a specific connection in the LDAPPool.
// It takes in the GUID (Globally Unique Identifier) and the index of the connection.
// It logs the LDAPPool name, GUID, and the LDAP connection details.
// The LDAP connection details include the server address, port number, bind DN, and whether the connection is encrypted or not.
func (l *LDAPPool) logConnectionInfo(guid *string, index int) {
	util.DebugModule(
		global.DbgLDAP,
		global.LogKeyLDAPPoolName, l.name,
		global.LogKeyGUID, *guid,
		"ldap", l.conf[index].String(),
	)
}

// logConnectionError logs an LDAP connection error. It takes a string pointer `guid` and an error `err` as input parameters.
// It logs the error using the `Error` level of the default error logger by calling the `Log` method.
// The log message includes the LDAP pool name, the GUID, and the error message.
// Example usage:
//
//	guid := "abc123"
//	err := errors.New("connection error")
//	l.logConnectionError(&guid, err)
func (l *LDAPPool) logConnectionError(guid *string, err error) {
	level.Error(logging.DefaultErrLogger).Log(
		global.LogKeyLDAPPoolName, l.name,
		global.LogKeyGUID, *guid,
		global.LogKeyError, err,
	)
}

// setIdleConnections sets the idle connections in the LDAPPool.
// It determines the idle pool size by calling the determineIdlePoolSize function.
// If the number of open connections is less than the idle pool size,
// it initializes new connections by calling the initializeConnections function,
// and optionally binds them based on the bind parameter.
func (l *LDAPPool) setIdleConnections(bind bool) {
	poolSize := len(l.conn)
	idlePoolSize, openConnections := determineIdlePoolSize(l, poolSize)

	if openConnections < idlePoolSize {
		initializeConnections(l, bind, idlePoolSize)
	}
}

// waitForFreeConnection waits for a free connection in the LDAPPool.
// It takes a GUID string pointer, the index of the current LDAP connection, and a wait group as parameters.
// If the ldapConnIndex is equal to global.LDAPPoolExhausted, it means that the LDAPPool is exhausted and no free connections are available.
// In this case, it logs a warning message indicating that the pool is exhausted and waiting for a free connection.
// It then waits until the wait group counter reaches zero, meaning all connections have been released.
// Finally, it logs a warning message indicating that the pool has obtained free connections.
func (l *LDAPPool) waitForFreeConnection(guid *string, ldapConnIndex int, ldapWaitGroup *sync.WaitGroup) {
	if ldapConnIndex == global.LDAPPoolExhausted {
		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyLDAPPoolName, l.name,
			global.LogKeyGUID, *guid,
			global.LogKeyMsg, "Pool exhausted. Waiting for a free connection")

		// XXX: Very hard decision, but an exhausted pool needs a human interaction!
		ldapWaitGroup.Wait()

		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyLDAPPoolName, l.name,
			global.LogKeyGUID, *guid,
			global.LogKeyMsg, "Pool got free connections")
	}
}

// getConnection retrieves a connection from the LDAPPool. It iterates over each connection in the pool using a nested loop.
// Within the inner loop, it calls `processConnection` to process each connection and assign a connection number.
// If a connection number other than global.LDAPPoolExhausted is returned, it breaks out of the loop and returns the connection number.
// Otherwise, it waits for a free connection by calling `waitForFreeConnection` and continues the loop until a connection is obtained.
// Finally, it returns the obtained connection number.
func (l *LDAPPool) getConnection(guid *string, ldapWaitGroup *sync.WaitGroup) (connNumber int) {
EndlessLoop:
	for {
		for index := 0; index < len(l.conn); index++ {
			connNumber = l.processConnection(index, guid)
			if connNumber != global.LDAPPoolExhausted {
				break EndlessLoop
			}
		}

		l.waitForFreeConnection(guid, connNumber, ldapWaitGroup)
	}

	return connNumber
}

// processConnection checks the state of a connection at the specified index in the LDAPPool.
// It performs the following actions based on the state of the connection:
//   - If the connection is busy, it logs a debug message indicating that the connection is in use and returns LDAPPoolExhausted.
//   - If the connection is free, it marks the connection as busy, logs a debug message indicating that the connection is being used, and returns the index of the connection.
//   - If the connection is closed, it attempts to establish a new connection and bind if necessary. If successful, it marks the connection as busy,
//     logs a debug message indicating that the connection is being used, and returns the index of the connection.
//
// If none of these conditions are met, it returns LDAPPoolExhausted.
func (l *LDAPPool) processConnection(index int, guid *string) (connNumber int) {
	l.conn[index].Mu.Lock()

	defer l.conn[index].Mu.Unlock()

	// Connection is already in use, skip to next.
	if l.conn[index].state == global.LDAPStateBusy {
		l.logConnectionBusy(guid, index)

		return global.LDAPPoolExhausted
	}

	// Connection is free, use it and mark it as busy.
	if l.conn[index].state == global.LDAPStateFree {
		l.conn[index].state = global.LDAPStateBusy

		l.logConnectionUsage(guid, index)

		return index
	}

	// There is no free connection. We need to get a new one. If we succeed, mark the connection as
	// busy and use it.
	if l.conn[index].state == global.LDAPStateClosed {
		err := l.connectAndBindIfNeeded(guid, index)
		if err != nil {
			l.logConnectionFailed(guid, err)

			return global.LDAPPoolExhausted
		}

		l.conn[index].state = global.LDAPStateBusy

		l.logConnectionUsage(guid, index)

		return index
	}

	return global.LDAPPoolExhausted
}

// logConnectionBusy logs a debug message indicating that a connection in the LDAPPool is busy.
// It takes a pointer to a string representing the GUID and the index of the connection as parameters.
// The GUID is included in the log message for identification purposes.
// The debug message includes the name of the LDAPPool, the GUID, and the index of the connection.
// The log message also informs that the connection is busy and that the next connection will be checked.
func (l *LDAPPool) logConnectionBusy(guid *string, index int) {
	util.DebugModule(
		global.DbgLDAP,
		global.LogKeyLDAPPoolName, l.name,
		global.LogKeyGUID, *guid,
		global.LogKeyMsg, fmt.Sprintf("Connection #%d is busy, checking next", index+1),
	)
}

// logConnectionUsage records the usage of LDAP connections, mainly for debugging purposes.
// It logs a message indicating which connection (based on its index in the pool) is being utilized.
// Parameters:
// - 'guid' is a pointer to the unique identifier of the LDAP connection.
// - 'index' represents the position of the LDAP connection in the pool.
// This function doesn't return any values.
func (l *LDAPPool) logConnectionUsage(guid *string, index int) {
	util.DebugModule(
		global.DbgLDAP,
		global.LogKeyLDAPPoolName, l.name,
		global.LogKeyGUID, *guid,
		global.LogKeyMsg, fmt.Sprintf("Connection #%d is free, using it", index+1),
	)
}

// connectAndBindIfNeeded connects to and binds the LDAP server using provided GUID and config.
// The bind operation is only carried out if the pool type is LDAPPoolLookup or LDAPPoolUnknown.
//
// Parameters:
//   - guid: pointer to GUID.
//   - index: index of config.
//
// Returns:
//   - error: returns error if either connection or binding fails, otherwise nil.
func (l *LDAPPool) connectAndBindIfNeeded(guid *string, index int) error {
	err := l.conn[index].connect(guid, l.conf[index])
	if err == nil && (l.poolType == global.LDAPPoolLookup || l.poolType == global.LDAPPoolUnknown) {
		err = l.conn[index].bind(guid, l.conf[index])
	}

	return err
}

// logConnectionFailed is a method of the LDAPPool type.
// It logs an error message when a connection to the LDAP server fails.
// The function takes a GUID string pointer and an error object as input parameters.
// It logs the LDAP pool name, GUID, and the error encountered.
func (l *LDAPPool) logConnectionFailed(guid *string, err error) {
	level.Error(logging.DefaultErrLogger).Log(
		global.LogKeyLDAPPoolName, l.name,
		global.LogKeyGUID, *guid,
		global.LogKeyError, err)
}

// checkConnection checks the state of a connection at the specified index.
// If the connection is nil or closing, it performs the following actions:
// - Acquires a lock on the connection.
// - Sets the state of the connection to closed.
// - Logs a warning message indicating that the connection is closed.
// - If the connection is not nil, it closes the connection.
// - Calls the connect method on the connection.
// - If the pool type is lookup or unknown, it calls the bind method on the connection.
// - Sets the state of the connection to busy.
func (l *LDAPPool) checkConnection(guid *string, index int) (err error) {
	if l.conn[index].Conn == nil || l.conn[index].isClosing() {
		l.conn[index].Mu.Lock()

		defer l.conn[index].Mu.Unlock()

		l.conn[index].state = global.LDAPStateClosed

		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyLDAPPoolName, l.name,
			global.LogKeyGUID, *guid,
			global.LogKeyMsg, fmt.Sprintf("Connection #%d is closed", index+1),
		)

		if l.conn[index].Conn != nil {
			l.conn[index].Conn.Close()
		}

		if err = l.conn[index].connect(guid, l.conf[index]); err != nil {
			return
		}

		if l.poolType == global.LDAPPoolLookup || l.poolType == global.LDAPPoolUnknown {
			if err = l.conn[index].bind(guid, l.conf[index]); err != nil {
				l.conn[index].Conn.Close()

				return
			}
		}

		l.conn[index].state = global.LDAPStateBusy
	}

	return
}

// isClosing checks if the connection is in the process of closing.
// It calls the isClosing method on the underlying ldap.Conn object and returns the result.
// The isClosing method returns true if the connection is being closed and false otherwise.
func (l *LDAPConnection) isClosing() bool {
	return l.Conn.IsClosing()
}

// setTLSConfig loads the CA chain and creates a TLS configuration for the LDAP connection. It takes the URL of the LDAP server, an array of certificates, and the LDAPConf configuration
func (l *LDAPConnection) setTLSConfig(u *url.URL, certificates []tls.Certificate, ldapConf *config.LDAPConf) (*tls.Config, error) {
	// Load CA chain
	caCert, err := os.ReadFile(ldapConf.TLSCAFile)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	host := u.Host

	if strings.Contains(u.Host, ":") {
		host, _, err = net.SplitHostPort(u.Host)
		if err != nil {
			return nil, err
		}
	}

	return &tls.Config{
		Certificates:       certificates,
		RootCAs:            caCertPool,
		InsecureSkipVerify: ldapConf.TLSSkipVerify,
		ServerName:         host,
	}, nil
}

// dialAndStartTLS dials the LDAP server and starts a TLS connection if configured.
func (l *LDAPConnection) dialAndStartTLS(guid *string, ldapConf *config.LDAPConf, ldapCounter int, tlsConfig *tls.Config) error {
	var err error

	l.Conn, err = ldap.DialURL(ldapConf.ServerURIs[ldapCounter], ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return err
	}

	if ldapConf.StartTLS {
		err = l.Conn.StartTLS(tlsConfig)

		if err != nil {
			return err
		}

		util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "STARTTLS")
	}

	return nil
}

// logURIInfo logs the URI information and connection attempt details for debugging purposes.
func (l *LDAPConnection) logURIInfo(guid *string, ldapConf *config.LDAPConf, ldapCounter int, retryLimit int) {
	util.DebugModule(
		global.DbgLDAP,
		global.LogKeyGUID, guid,
		"ldap_uri", ldapConf.ServerURIs[ldapCounter],
		"current_attempt", retryLimit+1,
		"max_attempt", global.LDAPMaxRetries+1,
	)
}

// handleLDAPConnectTimeout waits for a timeout event from connectTicker.C and sends a Done{} value to the timeout channel.
// It also listens for a Done{} value from the done channel and returns if received.
// This function is typically used as a goroutine to handle the LDAP connection timeout in the connect method of the LDAPConnection struct.
//
// Example usage:
// connectTicker := time.NewTicker(global.LDAPConnectTimeout * time.Second)
// ldapConnectTimeout := make(chan Done)
// tickerEndChan := make(chan Done)
//
// go handleLDAPConnectTimeout(connectTicker, ldapConnectTimeout, tickerEndChan)
//
// Loop:
//
//	for {
//	    select {
//	    case <-ldapConnectTimeout:
//	        timeout = true
//
//	    case <-done:
//	        break Loop
//	    }
//	}
//
// connectTicker.Stop()
// tickerEndChan <- Done{}
func handleLDAPConnectTimeout(connectTicker *time.Ticker, timeout chan Done, done chan Done) {
	for {
		select {
		case <-connectTicker.C:
			timeout <- Done{}
		case <-done:
			return
		}
	}
}

// connect establishes a connection with an LDAP server specified by the given LDAPConf.
//
// The function attempts to connect to each LDAP server URI in the LDAPConf until a successful connection is established or the maximum number of retries is reached.
// It uses a timeout of 30 seconds for each connection attempt.
// If the connection-attempts exceed the maximum number of retries, an ErrLDAPConnect error is returned.
// If a connection timeout occurs, an ErrLDAPConnectTimeout error is returned.
//
// If the LDAP server URI scheme is "ldaps" or StartTLS is enabled, the function sets up a TLS configuration using the TLS certificate files specified in LDAPConf or the system's certificate
func (l *LDAPConnection) connect(guid *string, ldapConf *config.LDAPConf) error {
	var (
		connected    bool
		timeout      bool
		retryLimit   int
		ldapCounter  int
		err          error
		certificates []tls.Certificate
		tlsConfig    *tls.Config
	)

	connectTicker := time.NewTicker(global.LDAPConnectTimeout * time.Second)

	ldapConnectTimeout := make(chan Done)
	tickerEndChan := make(chan Done)

	go handleLDAPConnectTimeout(connectTicker, ldapConnectTimeout, tickerEndChan)

EndlessLoop:
	for {
		select {
		case <-ldapConnectTimeout:
			timeout = true

		default:
			if retryLimit > global.LDAPMaxRetries {
				return errors2.ErrLDAPConnect.WithDetail(
					fmt.Sprintf("Could not connect to any of the LDAP servers: %v", ldapConf.ServerURIs))
			}

			if ldapCounter > len(ldapConf.ServerURIs)-1 {
				ldapCounter = 0
			}

			l.logURIInfo(guid, ldapConf, ldapCounter, retryLimit)

			u, _ := url.Parse(ldapConf.ServerURIs[ldapCounter])
			if u.Scheme == "ldaps" || ldapConf.StartTLS {
				tlsConfig, err = l.setTLSConfig(u, certificates, ldapConf)
				if err != nil {
					break EndlessLoop
				}
			}

			err = l.dialAndStartTLS(guid, ldapConf, ldapCounter, tlsConfig)
			if err != nil {
				ldapCounter++
				retryLimit++

				continue EndlessLoop
			}

			// other operations including SASL External setup unchanged...
			connected = true
		}

		if connected {
			util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "Connection established")

			break EndlessLoop
		}

		if timeout {
			err = errors2.ErrLDAPConnectTimeout.WithDetail("Connection timeout reached")

			break EndlessLoop
		}
	}

	connectTicker.Stop()

	tickerEndChan <- Done{}

	return err
}

// exteranlBind binds to the LDAP server using the SASL EXTERNAL mechanism.
// It logs the action as "SASL/EXTERNAL" and then calls the ExternalBind() method on the LDAP connection.
// If the ExternalBind() method returns an error, it is returned from this method.
// If the verbosity level is set to LogLevelDebug, it calls the displayWhoAmI() method to display information about the bound user.
// This method does not take any arguments.
func (l *LDAPConnection) exteranlBind(guid *string) error {
	util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "SASL/EXTERNAL")

	err := l.Conn.ExternalBind()
	if err != nil {
		return err
	}

	if config.EnvConfig.Verbosity.Level() >= global.LogLevelDebug {
		l.displayWhoAmI(guid)
	}
	return nil
}

// simpleBind performs a simple bind operation using the provided LDAPConf credentials.
// It takes the GUID (Globally Unique Identifier) of the operation and the LDAPConf configuration as parameters.
// It logs debug information related to the bind process and then calls the Conn.SimpleBind() method to perform the bind operation.
// If the bind operation fails, it returns the error.
// If the verbosity level is set to LogLevelDebug or higher, it displays the WhoAmI information after successful authentication.
// It returns nil if the bind operation is successful.
func (l *LDAPConnection) simpleBind(guid *string, ldapConf *config.LDAPConf) error {
	util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "simple bind")
	util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "bind_dn", ldapConf.BindDN)

	if config.EnvConfig.DevMode {
		util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "bind_password", ldapConf.BindPW)
	}

	_, err := l.Conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: ldapConf.BindDN,
		Password: ldapConf.BindPW,
	})

	if err != nil {
		return err
	}

	if config.EnvConfig.Verbosity.Level() >= global.LogLevelDebug {
		l.displayWhoAmI(guid)
	}

	return nil
}

// displayWhoAmI retrieves information about the current LDAP connection and logs it using the util.DebugModule function. It takes a GUID pointer as input.
// It calls the WhoAmI method of the LDAP connection to get the result. If there is no error, it logs the result using util.DebugModule.
// Example usage:
// guid := "session123"
// ldapConn := &LDAPConnection{}
// ldapConn.displayWhoAmI(&guid)
func (l *LDAPConnection) displayWhoAmI(guid *string) {
	res, err := l.Conn.WhoAmI(nil) //nolint:govet // Ignore
	if err == nil {
		util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "whoami", fmt.Sprintf("%+v", res))
	}
}

// bind performs a bind operation on the LDAP connection.
// If SASLExternal is true, it calls externalBind(guid).
// Otherwise, it calls simpleBind(guid, ldapConf).
//
// Parameters:
// - guid: The GUID associated with the LDAP connection.
// - ldapConf: The LDAP configuration containing the bind information.
//
// Returns:
// - error: An error if the bind operation fails, otherwise nil.
func (l *LDAPConnection) bind(guid *string, ldapConf *config.LDAPConf) error {
	if ldapConf.SASLExternal {
		return l.exteranlBind(guid)
	}

	return l.simpleBind(guid, ldapConf)
}

// unbind closes the LDAP connection and unbinds from the server.
func (l *LDAPConnection) unbind() (err error) {
	err = l.Conn.Unbind()

	return
}

// search function on the LDAPConnection object initiates a search in the LDAP directory based on the provided LDAPRequest.
// The function first constructs an LDAP SearchRequest from the LDAPRequest, replacing macros and removing CRLF from filter queries.
// The SearchRequest is then executed on the LDAP Connection, and the search results are processed to form a DatabaseResult,
// which consists of attribute-value pairs returned from the LDAP directory.
// In addition to the result, the method also returns the raw LDAP entries obtained from the search.
// If errors occur during the process, they are propagated back to the caller.
//
// Parameters:
// ldapRequest: A pointer to an LDAPRequest object which encapsulates the parameters for the LDAP search, including baseDN, scope, filter, and search attributes.
//
// Return values:
// result: A DatabaseResult object that encapsulates the attribute-value pairs obtained from the search. Each attribute has a slice of values associated with it.
// rawResult: A slice of pointers to ldap.Entry objects that represent the raw data results returned by the LDAP search.
// err: An error object that encapsulates any error that occurred during the execution of the search. If no error occurred, this object is nil.
//
// Example of use:
// ldapRequest := LDAPRequest{BaseDN: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)", SearchAttributes: []string{"cn", "mail"}}
// result, rawResult, err := ldapConnection.search(&ldapRequest)
// if err != nil { fmt.Println("Error:", err) }
// else { fmt.Println("Result:", result) }
func (l *LDAPConnection) search(ldapRequest *LDAPRequest) (result DatabaseResult, rawResult []*ldap.Entry, err error) {
	var searchResult *ldap.SearchResult

	ldapRequest.Filter = strings.ReplaceAll(ldapRequest.Filter, "%s", ldapRequest.MacroSource.Username)
	ldapRequest.Filter = ldapRequest.MacroSource.ReplaceMacros(ldapRequest.Filter)
	ldapRequest.Filter = util.RemoveCRLFFromQueryOrFilter(ldapRequest.Filter, "")

	util.DebugModule(global.DbgLDAP, global.LogKeyGUID, ldapRequest.GUID, "filter", ldapRequest.Filter)

	searchRequest := ldap.NewSearchRequest(
		ldapRequest.BaseDN,
		ldapRequest.Scope.Get(),
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		ldapRequest.Filter,
		ldapRequest.SearchAttributes,
		nil,
	)

	searchResult, err = l.Conn.Search(searchRequest)
	if err != nil {
		return nil, nil, err
	}

	result = make(DatabaseResult)

	for entryIndex := range searchResult.Entries {
		for attrIndex := range ldapRequest.SearchAttributes {
			var anySlice []any

			values := searchResult.Entries[entryIndex].GetAttributeValues(ldapRequest.SearchAttributes[attrIndex])

			// Do not add empty results
			if len(values) == 0 {
				continue
			}

			for index := range values {
				anySlice = append(anySlice, values[index])
			}

			if len(result[ldapRequest.SearchAttributes[attrIndex]]) > 0 {
				result[ldapRequest.SearchAttributes[attrIndex]] = append(result[ldapRequest.SearchAttributes[attrIndex]], anySlice...)
			} else {
				result[ldapRequest.SearchAttributes[attrIndex]] = anySlice
			}
		}

		if _, assertOk := result[global.DistinguishedName]; assertOk {
			result[global.DistinguishedName] = append(result[global.DistinguishedName], searchResult.Entries[entryIndex].DN)
		} else {
			result[global.DistinguishedName] = []any{searchResult.Entries[entryIndex].DN}
		}
	}

	return result, searchResult.Entries, nil
}

// modifyAdd performs an 'Add' operation in an LDAP directory for the given LDAPRequest.
//
// It starts with a search operation using the filter in the LDAPRequest.
// If the search result does not contain a distinguished name (DN) attribute, error ErrNoLDAPSearchResult will occur.
// If the search result finds no corresponding entries, error ErrNoLDAPSearchResult will also occur.
//
// If the search operation is successful, a modify request is created with the DN.
// Then, for each attribute in ModifyAttributes of LDAPRequest, the Add method is called to add them to the modifyRequest.
// Finally, the 'Add' request is sent to the LDAP directory.
//
// Parameters:
//
//	ldapRequest: A pointer to LDAPRequest. It contains the attributes to be added and the filter for the search operation.
//
// Returns:
//
//	err: Error. If an error occurs during the search operation or modification, it will return an error, otherwise this function will return nil.
//
// Note: This operation is destructive. It modifies the LDAP directory. Therefore, it should be used judiciously and you should make sure that ldapRequest contains correct values.
func (l *LDAPConnection) modifyAdd(ldapRequest *LDAPRequest) (err error) {
	var (
		assertOk           bool
		distinguishedNames any
		result             DatabaseResult
	)

	if result, _, err = l.search(ldapRequest); err != nil {
		return
	}

	if distinguishedNames, assertOk = result[global.DistinguishedName]; !assertOk {
		err = errors2.ErrNoLDAPSearchResult.WithDetail(
			fmt.Sprintf("No search result for filter: %v", ldapRequest.Filter))

		return
	}

	if len(distinguishedNames.([]any)) == 0 {
		err = errors2.ErrNoLDAPSearchResult.WithDetail(
			fmt.Sprintf("No search result for filter: %v", ldapRequest.Filter))

		return
	}

	dn := distinguishedNames.([]any)[global.LDAPSingleValue].(string)

	modifyRequest := ldap.NewModifyRequest(dn, nil)

	if ldapRequest.ModifyAttributes != nil {
		for attributeName, attributeValues := range ldapRequest.ModifyAttributes {
			modifyRequest.Add(attributeName, attributeValues)
		}

		err = l.Conn.Modify(modifyRequest)
	}

	return
}

// LDAPMainWorker is the main working function for managing LDAP (Lightweight Directory Access Protocol) operations.
// It operates as a Goroutine performing numerous LDAP tasks such as search, add, and modify operations on an LDAP directory.
// This function incrementally fetches requests from the LDAPRequestChan and processes them in a separate Goroutine.
// Each request is processed using a certain connection from the connection pool.
// Connections are freed up once they have completed their task.
// The function operates continuously until the context is cancelled, at which point it closes the connection pool and
// sends a signal to the LDAPEndChan, signifying its completion.
//
// Parameters:
//
//	ctx (context.Context): The context in which the function operates.
//
// Note: This function does not return a value.
func LDAPMainWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := NewPool(ctx, global.LDAPPoolLookup)
	if ldapPool == nil {
		return
	}

	// Start background cleaner process
	go ldapPool.houseKeeper()

	for {
		select {
		case <-ctx.Done():
			ldapPool.Close()

			LDAPEndChan <- Done{}

			return

		case ldapRequest := <-LDAPRequestChan:
			// Check that we have enough idle connections.
			ldapPool.setIdleConnections(true)

			connNumber := ldapPool.getConnection(ldapRequest.GUID, &ldapWaitGroup)

			ldapWaitGroup.Add(1)

			go func(index int, ldapRequest *LDAPRequest) {
				var (
					err       error
					result    DatabaseResult
					rawResult []*ldap.Entry
				)

				defer func() {
					ldapWaitGroup.Done()
				}()

				ldapReply := &LDAPReply{}
				ldapReplyChan := ldapRequest.LDAPReplyChan

				if ldapReply.Err = ldapPool.checkConnection(ldapRequest.GUID, index); ldapReply.Err != nil {
					ldapReplyChan <- ldapReply

					return
				}

				switch ldapRequest.Command {
				case global.LDAPSearch:
					if result, rawResult, err = ldapPool.conn[index].search(ldapRequest); err != nil {
						if err != nil {
							var ldapError *ldap.Error

							if errors.As(err, &ldapError) {
								if !(ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject)) {
									level.Error(logging.DefaultErrLogger).Log(
										global.LogKeyLDAPPoolName, ldapPool.name,
										global.LogKeyGUID, *ldapRequest.GUID,
										global.LogKeyError, ldapError.Error(),
									)

									ldapReply.Err = ldapError.Err
								}
							}
						}
					}

				case global.LDAPModifyAdd:
					if err = ldapPool.conn[index].modifyAdd(ldapRequest); err != nil {
						ldapReply.Err = err
					}
				}

				ldapReply.Result = result
				ldapReply.RawResult = rawResult

				if ctxErr := ldapRequest.HTTPClientContext.Err(); ctxErr != nil {
					ldapReply.Err = ctxErr
				}

				ldapReplyChan <- ldapReply

				ldapPool.conn[index].Mu.Lock()

				ldapPool.conn[index].state = global.LDAPStateFree

				ldapPool.conn[index].Mu.Unlock()
			}(connNumber, ldapRequest)
		}
	}
}

// LDAPAuthWorker is a function that performs multiple tasks as part of LDAP Authentication.
//
//  1. LDAP Connection Pool Management: It initializes a new LDAP connection pool and conducts housekeeping tasks
//     in a separate Go routine. If a housekeeping task completes or fails, the function closes the LDAP pool and
//     sends a message to the LDAPAuthEndChan.
//
//  2. LDAP Request Processing: The function continuously listens to requests on LDAPAuthRequestChan.
//     For each incoming request, it takes the following steps:
//     - Checks if there are enough idle connections in the pool.
//     - Gets a connection from the pool.
//     - Spawns a new Go routine to deal with the authentication. This concurrency allows the function to handle
//     subsequent requests without waiting for the previous ones. Inside this Go routine:
//     - The integrity of the connection is verified.
//     - It tries to authenticate the user against the LDAP using the Bind credentials provided in the request.
//     - Checks for any errors in the HTTPClientContext of the request and reflects them in the LDAPReply object.
//     - Sends the LDAPReply object through the LDAPReplyChan provided in the request.
//     - Frees up the state of the LDAP connection for future use.
//
// The function runs continuously until its context is canceled or it encounters a fatal error.
// If the context is canceled, the function ensures it cleans up any open LDAP connections before termination.
func LDAPAuthWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := NewPool(ctx, global.LDAPPoolAuth)
	if ldapPool == nil {
		return
	}

	// Start background cleaner process
	go ldapPool.houseKeeper()

	for {
		select {
		case <-ctx.Done():
			ldapPool.Close()

			LDAPAuthEndChan <- Done{}

			return
		case ldapAuthRequest := <-LDAPAuthRequestChan:
			// Check that we have enough idle connections.
			ldapPool.setIdleConnections(true)

			connNumber := ldapPool.getConnection(ldapAuthRequest.GUID, &ldapWaitGroup)

			ldapWaitGroup.Add(1)

			go func(index int, ldapUserBindRequest *LDAPAuthRequest) {
				var err error

				defer func() {
					ldapWaitGroup.Done()
				}()

				ldapReply := &LDAPReply{}
				ldapReplyChan := ldapUserBindRequest.LDAPReplyChan

				if ldapReply.Err = ldapPool.checkConnection(ldapUserBindRequest.GUID, index); ldapReply.Err != nil {
					ldapReplyChan <- ldapReply

					return
				}

				// Try to authenticate a user.
				if err = ldapPool.conn[index].Conn.Bind(ldapUserBindRequest.BindDN, ldapUserBindRequest.BindPW); err != nil {
					ldapReply.Err = err
				}

				/*
					// XXX: As the unbind() call closes the connection, we re-bind...
					ldapPool.conn[index].Conn.unbind()
				*/

				if ctxErr := ldapUserBindRequest.HTTPClientContext.Err(); ctxErr != nil {
					ldapReply.Err = ctxErr
				}

				ldapReplyChan <- ldapReply

				ldapPool.conn[index].Mu.Lock()

				ldapPool.conn[index].state = global.LDAPStateFree

				ldapPool.conn[index].Mu.Unlock()
			}(connNumber, ldapAuthRequest)
		}
	}
}
