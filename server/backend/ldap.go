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
	LDAPEndChan     chan Done         //nolint:gochecknoglobals // Quit-Channel for LDAP on shutdown
	LDAPRequestChan chan *LDAPRequest //nolint:gochecknoglobals // Needed for LDAP pooling

	LDAPAuthEndChan     chan Done             //nolint:gochecknoglobals // Quit-Channel for LDAP on shutdown
	LDAPAuthRequestChan chan *LDAPAuthRequest //nolint:gochecknoglobals // Needed for LDAP pooling
)

type LDAPConnection struct {
	ldapConnectionState

	Mu   sync.Mutex
	Conn *ldap.Conn
}

type LDAPPool struct {
	poolType int
	name     string
	ctx      context.Context

	conn []*LDAPConnection
	conf []*config.LDAPConf
}

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

func (l *LDAPPool) Close() {
	for index := 0; index < len(l.conn); index++ {
		if l.conn[index].Conn != nil {
			_ = l.conn[index].Unbind()
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

func (l *LDAPPool) HouseKeeper() {
	var idlePoolSize int

	// Cleanup interval
	timer := time.NewTicker(30 * time.Second) //nolint:gomnd // 30 seconds

	// Make (idle) pool size thread safe!
	poolSize := len(l.conn)

	switch l.poolType {
	case global.LDAPPoolLookup, global.LDAPPoolUnknown:
		idlePoolSize = config.LoadableConfig.GetLDAPConfigLookupIdlePoolSize()
	case global.LDAPPoolAuth:
		idlePoolSize = config.LoadableConfig.GetLDAPConfigAuthIdlePoolSize()
	}

	for {
		select {
		case <-l.ctx.Done():
			timer.Stop()

			util.DebugModule(
				global.DbgLDAP,
				global.LogKeyLDAPPoolName, l.name,
				global.LogKeyMsg, "HouseKeeper() terminated",
			)

			return

		case <-timer.C:
			openConnections := 0

			for index := 0; index < poolSize; index++ {
				func() {
					l.conn[index].Mu.Lock()
					defer l.conn[index].Mu.Unlock()

					if l.conn[index].state == global.LDAPStateFree {
						if !(l.conn[index].Conn == nil || l.conn[index].Conn.IsClosing()) {
							_, err := l.conn[index].Conn.Search(ldap.NewSearchRequest(
								"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30,
								false, "(objectClass=*)", []string{"1.1"}, nil,
							))

							if err != nil {
								// Lost connection
								util.DebugModule(
									global.DbgLDAPPool,
									global.LogKeyLDAPPoolName, l.name,
									global.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d has broken connection", index+1),
								)

								l.conn[index].Conn = nil
								l.conn[index].state = global.LDAPStateClosed
							} else {
								openConnections++

								util.DebugModule(
									global.DbgLDAPPool,
									global.LogKeyLDAPPoolName, l.name,
									global.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is free", index+1),
								)
							}
						} else {
							// Fix wrong state flag
							l.conn[index].state = global.LDAPStateClosed
						}
					} else {
						util.DebugModule(
							global.DbgLDAPPool,
							global.LogKeyLDAPPoolName, l.name,
							global.LogKeyMsg, fmt.Sprintf("LDAP free/busy state #%d is busy or closed", index+1),
						)
					}
				}()
			}

			needClosing := 0

			if diff := openConnections - idlePoolSize; diff > 0 {
				needClosing = diff
			}

			util.DebugModule(
				global.DbgLDAPPool,
				global.LogKeyLDAPPoolName, l.name,
				global.LogKeyMsg, "State open connections",
				"needClosing", needClosing, "openConnections", openConnections, "idlePoolSize", idlePoolSize,
			)

			for index := 0; index < poolSize && needClosing > 0; index++ {
				func() {
					l.conn[index].Mu.Lock()
					defer l.conn[index].Mu.Unlock()

					if l.conn[index].state == global.LDAPStateFree {
						l.conn[index].Conn.Close()
						l.conn[index].state = global.LDAPStateClosed

						needClosing--

						util.DebugModule(
							global.DbgLDAPPool,
							global.LogKeyLDAPPoolName, l.name,
							global.LogKeyMsg, fmt.Sprintf("Connection #%d closed", index+1),
						)
					}
				}()

				if needClosing == 0 {
					break
				}
			}
		}
	}
}

func (l *LDAPPool) SetIdleConnections(guid string, bind bool) {
	var idlePoolSize int

	openConnections := 0
	poolSize := len(l.conn)

	switch l.poolType {
	case global.LDAPPoolLookup, global.LDAPPoolUnknown:
		idlePoolSize = config.LoadableConfig.GetLDAPConfigLookupIdlePoolSize()
	case global.LDAPPoolAuth:
		idlePoolSize = config.LoadableConfig.GetLDAPConfigAuthIdlePoolSize()
	}

	for index := 0; index < poolSize; index++ {
		if l.conn[index].state != global.LDAPStateClosed {
			openConnections++
		}
	}

	if openConnections < idlePoolSize {
		diffConnections := idlePoolSize - openConnections

		wg := sync.WaitGroup{}

		// Initialize the idle pool
		for index := 0; index < idlePoolSize; index++ {
			wg.Add(1)

			util.DebugModule(
				global.DbgLDAP,
				global.LogKeyLDAPPoolName, l.name,
				global.LogKeyGUID, guid,
				"ldap", l.conf[index].String(),
			)

			guidStr := fmt.Sprintf("pool-#%d", index+1)

			//go func(index int) {
			l.conn[index].Mu.Lock()

			if l.conn[index].state == global.LDAPStateClosed {
				err := l.conn[index].Connect(&guidStr, l.conf[index])
				if err != nil {
					level.Error(logging.DefaultErrLogger).Log(
						global.LogKeyLDAPPoolName, l.name,
						global.LogKeyGUID, guid,
						global.LogKeyError, err,
					)
				} else if bind {
					err = l.conn[index].Bind(&guidStr, l.conf[index])
					if err != nil {
						level.Error(logging.DefaultErrLogger).Log(
							global.LogKeyLDAPPoolName, l.name,
							global.LogKeyGUID, guid,
							global.LogKeyError, err,
						)
					}
				}

				if err == nil {
					l.conn[index].state = global.LDAPStateFree
					diffConnections--
				}

				l.conn[index].Mu.Unlock()
				wg.Done()
			}

			if diffConnections == 0 {
				break
			}
		}

		if diffConnections != 0 {
			wg.Wait()
		}
	}
}

func (l *LDAPPool) waitForFreeConnection(guid *string, ldapConnIndex int, ldapWaitGroup *sync.WaitGroup) {
	if ldapConnIndex == global.LDAPPoolExhausted {
		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyLDAPPoolName, l.name,
			global.LogKeyGUID, *guid,
			global.LogKeyMsg, "Pool exhausted. Waiting for a free connection")

		ldapWaitGroup.Wait()

		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyLDAPPoolName, l.name,
			global.LogKeyGUID, *guid,
			global.LogKeyMsg, "Pool got free connections")
	}
}

func (l *LDAPPool) getConnection(guid *string, ldapWaitGroup *sync.WaitGroup) (connNumber int) {
	for {
		for index := 0; index < len(l.conn); index++ {
			l.conn[index].Mu.Lock()

			// Connection is already in use, skip to next.
			if l.conn[index].state == global.LDAPStateBusy {
				l.conn[index].Mu.Unlock()

				util.DebugModule(
					global.DbgLDAP,
					global.LogKeyLDAPPoolName, l.name,
					global.LogKeyGUID, *guid,
					global.LogKeyMsg, fmt.Sprintf("Connection #%d is busy, checking next", index+1),
				)

				continue
			}

			// Connection is free, use it and mark it as busy.
			if l.conn[index].state == global.LDAPStateFree {
				l.conn[index].state = global.LDAPStateBusy

				l.conn[index].Mu.Unlock()

				util.DebugModule(
					global.DbgLDAP,
					global.LogKeyLDAPPoolName, l.name,
					global.LogKeyGUID, *guid,
					global.LogKeyMsg, fmt.Sprintf("Connection #%d is free, using it", index+1),
				)

				connNumber = index

				break
			}

			// There was no free connection. We need to get a new one. If we succeeded, mark the connection as
			// busy and use it.
			if l.conn[index].state == global.LDAPStateClosed {
				err := l.conn[index].Connect(guid, l.conf[index])
				if err != nil {
					level.Error(logging.DefaultErrLogger).Log(
						global.LogKeyLDAPPoolName, l.name,
						global.LogKeyGUID, *guid,
						global.LogKeyError, err)
				} else {
					if l.poolType == global.LDAPPoolLookup || l.poolType == global.LDAPPoolUnknown {
						err = l.conn[index].Bind(guid, l.conf[index])
						if err != nil {
							level.Error(logging.DefaultErrLogger).Log(
								global.LogKeyLDAPPoolName, l.name,
								global.LogKeyGUID, *guid,
								global.LogKeyError, err)
						}
					}
				}

				if err == nil {
					l.conn[index].state = global.LDAPStateBusy

					l.conn[index].Mu.Unlock()

					connNumber = index

					util.DebugModule(
						global.DbgLDAP,
						global.LogKeyLDAPPoolName, l.name,
						global.LogKeyGUID, *guid,
						global.LogKeyMsg, fmt.Sprintf("New LDAP connection opened: #%d", index+1))

					break
				}
			}

			l.conn[index].Mu.Unlock()
		}

		if connNumber != global.LDAPPoolExhausted {
			break
		}

		l.waitForFreeConnection(guid, connNumber, ldapWaitGroup)
	}

	return
}

func (l *LDAPPool) checkConnection(guid *string, index int) (err error) {
	if l.conn[index].Conn == nil || l.conn[index].IsClosing() {
		l.conn[index].Mu.Lock()

		l.conn[index].state = global.LDAPStateClosed

		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyLDAPPoolName, l.name,
			global.LogKeyGUID, *guid,
			global.LogKeyMsg, fmt.Sprintf("Connection #%d is closed", index+1),
		)

		if l.conn[index].Conn != nil {
			l.conn[index].Conn.Close()
		}

		if err = l.conn[index].Connect(guid, l.conf[index]); err != nil {
			l.conn[index].Mu.Unlock()

			return
		}

		if l.poolType == global.LDAPPoolLookup || l.poolType == global.LDAPPoolUnknown {
			if err = l.conn[index].Bind(guid, l.conf[index]); err != nil {
				l.conn[index].Mu.Unlock()

				l.conn[index].Conn.Close()

				return
			}
		}

		l.conn[index].state = global.LDAPStateBusy

		l.conn[index].Mu.Unlock()
	}

	return
}

type LDAPModifyAttributes map[string][]string

type LDAPRequest struct {
	GUID              *string
	Filter            string
	BaseDN            string
	SearchAttributes  []string
	MacroSource       *util.MacroSource
	Scope             config.LDAPScope
	Command           global.LDAPCommand
	ModifyAttributes  LDAPModifyAttributes
	LDAPReplyChan     chan *LDAPReply
	HTTPClientContext context.Context
}

type LDAPAuthRequest struct {
	GUID              *string
	BindDN            string
	BindPW            string
	LDAPReplyChan     chan *LDAPReply
	HTTPClientContext context.Context
}

type LDAPReply struct {
	Result    DatabaseResult
	RawResult []*ldap.Entry
	Err       error
}

type ldapConnectionState struct {
	state global.LDAPState
}

func (l *LDAPConnection) IsClosing() bool {
	return l.Conn.IsClosing()
}

func (l *LDAPConnection) Connect(guid *string, ldapConf *config.LDAPConf) error {
	var (
		connected    bool
		timeout      bool
		retryLimit   int
		ldapCounter  int
		err          error
		certificates []tls.Certificate
		tlsConfig    *tls.Config
	)

	// Activate a 30 seconds timeout
	ldapConnectTimeout := make(chan Done)

	go func() {
		time.Sleep(30 * time.Second)

		ldapConnectTimeout <- Done{}
	}()

	for {
		select {
		case <-ldapConnectTimeout:
			timeout = true

			break
		default:
			if retryLimit > global.LDAPMaxRetries {
				return errors2.ErrLDAPConnect.WithDetail(
					fmt.Sprintf("Could not connect to any of the LDAP servers: %v", ldapConf.ServerURIs))
			}

			if ldapCounter > len(ldapConf.ServerURIs)-1 {
				ldapCounter = 0
			}

			util.DebugModule(
				global.DbgLDAP,
				global.LogKeyGUID, guid,
				"ldap_uri", ldapConf.ServerURIs[ldapCounter],
				"current_attempt", retryLimit+1,
				"max_attempt", global.LDAPMaxRetries+1,
			)

			u, _ := url.Parse(ldapConf.ServerURIs[ldapCounter])

			if u.Scheme == "ldaps" || ldapConf.StartTLS {
				// Load CA chain
				caCert, err := os.ReadFile(ldapConf.TLSCAFile)
				if err != nil {
					return err
				}

				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)

				host := u.Host
				if strings.Contains(u.Host, ":") {
					host, _, err = net.SplitHostPort(u.Host)
					if err != nil {
						return err
					}
				}

				tlsConfig = &tls.Config{
					Certificates:       certificates,
					RootCAs:            caCertPool,
					InsecureSkipVerify: ldapConf.TLSSkipVerify, //nolint:gosec // Support self-signed certificates
					ServerName:         host,
				}
			}

			l.Conn, err = ldap.DialURL(ldapConf.ServerURIs[ldapCounter], ldap.DialWithTLSConfig(tlsConfig))
			if err != nil {
				ldapCounter++
				retryLimit++

				continue
			}

			if ldapConf.SASLExternal {
				// Certificates are not needed with ldapi//
				if ldapConf.TLSClientCert != "" && ldapConf.TLSClientKey != "" {
					cert, err := tls.LoadX509KeyPair(ldapConf.TLSClientCert, ldapConf.TLSClientKey)
					if err != nil {
						return err
					}

					certificates = []tls.Certificate{cert}
				}
			}

			if ldapConf.StartTLS {
				err = l.Conn.StartTLS(tlsConfig)
				if err != nil {
					return err
				}

				util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "STARTTLS")
			}

			connected = true

			break
		}

		if connected {
			util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "Connection established")

			break
		}

		if timeout {
			err = errors2.ErrLDAPConnectTimeout.WithDetail("Connection timeout reached")

			break
		}
	}

	return err
}

func (l *LDAPConnection) Bind(guid *string, ldapConf *config.LDAPConf) error {
	var err error

	if ldapConf.SASLExternal {
		util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "SASL/EXTERNAL")

		err = l.Conn.ExternalBind()
		if err != nil {
			return err
		}

		if config.EnvConfig.Verbosity.Level() >= global.LogLevelDebug {
			res, err := l.Conn.WhoAmI(nil) //nolint:govet // Ignore
			if err == nil {
				util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "whoami", fmt.Sprintf("%+v", res))
			}
		}
	} else {
		util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, global.LogKeyMsg, "simple bind")
		util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "bind_dn", ldapConf.BindDN)

		if config.EnvConfig.DevMode {
			util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "bind_password", ldapConf.BindPW)
		}

		_, err = l.Conn.SimpleBind(&ldap.SimpleBindRequest{
			Username: ldapConf.BindDN,
			Password: ldapConf.BindPW,
		})

		if err != nil {
			return err
		}

		if config.EnvConfig.Verbosity.Level() >= global.LogLevelDebug {
			res, err := l.Conn.WhoAmI(nil)
			if err == nil {
				util.DebugModule(global.DbgLDAP, global.LogKeyGUID, guid, "whoami", fmt.Sprintf("%+v", res))
			}
		}
	}

	return nil
}

func (l *LDAPConnection) Unbind() (err error) {
	err = l.Conn.Unbind()

	return
}

func (l *LDAPConnection) Search(ldapRequest *LDAPRequest) (result DatabaseResult, rawResult []*ldap.Entry, err error) {
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

func (l *LDAPConnection) ModifyAdd(ldapRequest *LDAPRequest) (err error) {
	var (
		assertOk           bool
		distinguishedNames any
		result             DatabaseResult
	)

	if result, _, err = l.Search(ldapRequest); err != nil {
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

//nolint:gocognit,maintidx // Ignore
func LDAPMainWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := NewPool(ctx, global.LDAPPoolLookup)
	if ldapPool == nil {
		return
	}

	// Start background cleaner process
	go ldapPool.HouseKeeper()

	for {
		select {
		case <-ctx.Done():
			ldapPool.Close()

			LDAPEndChan <- Done{}

			return

		case ldapRequest := <-LDAPRequestChan:
			// Check that we have enough idle connections.
			ldapPool.SetIdleConnections(*ldapRequest.GUID, true)

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
					if result, rawResult, err = ldapPool.conn[index].Search(ldapRequest); err != nil {
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
					if err = ldapPool.conn[index].ModifyAdd(ldapRequest); err != nil {
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

func LDAPAuthWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := NewPool(ctx, global.LDAPPoolAuth)
	if ldapPool == nil {
		return
	}

	// Start background cleaner process
	go ldapPool.HouseKeeper()

	for {
		select {
		case <-ctx.Done():
			ldapPool.Close()

			LDAPAuthEndChan <- Done{}

			return
		case ldapAuthRequest := <-LDAPAuthRequestChan:
			// Check that we have enough idle connections.
			ldapPool.SetIdleConnections(*ldapAuthRequest.GUID, true)

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
					// XXX: As the Unbind() call closes the connection, we re-bind...
					ldapPool.conn[index].Conn.Unbind()
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
