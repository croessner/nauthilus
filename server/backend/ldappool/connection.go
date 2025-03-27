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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-ldap/ldap/v3"
)

// LDAPConnection defines behaviors for managing and interacting with an LDAP connection.
type LDAPConnection interface {
	// SetState sets the current state of the LDAP connection to the specified LDAPState value.
	SetState(state definitions.LDAPState)

	// GetState returns the current state of the LDAP connection as a value of type definitions.LDAPState.
	GetState() definitions.LDAPState

	// SetConn sets the LDAP connection instance to be used for subsequent operations.
	SetConn(*ldap.Conn)

	// GetConn retrieves the current LDAP connection instance, allowing interaction with the LDAP server.
	GetConn() *ldap.Conn

	// GetMutex retrieves the mutex associated with the LDAP connection for synchronization purposes.
	GetMutex() *sync.Mutex

	// Connect establishes an LDAP connection using the provided GUID and configuration, returning an error if it fails.
	Connect(guid *string, ldapConf *config.LDAPConf) error

	// Bind attempts to authenticate and establish a bound state for the LDAP connection using the provided credentials.
	Bind(guid *string, ldapConf *config.LDAPConf) error

	// Unbind gracefully disconnects the LDAP connection by sending an unbind request to the server and returns any error encountered.
	Unbind() error

	// IsClosing checks whether the LDAP connection is in the process of closing and returns true if it is.
	IsClosing() bool

	// Search executes an LDAP search request based on the specified LDAPRequest and returns the results, raw entries, or an error.
	Search(ldapRequest *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error)

	// ModifyAdd processes an LDAP ModifyAdd request by adding attributes to an entry based on the provided LDAPRequest.
	ModifyAdd(ldapRequest *bktype.LDAPRequest) error
}

// LDAPConnectionImpl represents the connection with an LDAP server.
// It encapsulates the LDAP connection state and provides a means to synchronize access to it.
type LDAPConnectionImpl struct {
	// ldapConnectionState holds the current state of the LDAP connection.
	ldapConnectionState

	// mu is a Mutex used to synchronize access to the conn field,
	// essential when multiple goroutines need to access or modify the same connection concurrently.
	mu sync.Mutex

	// conn is the active LDAP connection. It is a pointer to a ldap.Conn object.
	conn *ldap.Conn
}

// SetState updates the current state of the LDAPConnectionImpl to the provided LDAPState value.
func (l *LDAPConnectionImpl) SetState(state definitions.LDAPState) {
	l.state = state
}

// GetState returns the current state of the LDAP connection as a value of type definitions.LDAPState.
func (l *LDAPConnectionImpl) GetState() definitions.LDAPState {
	return l.state
}

// SetConn sets the internal LDAP connection instance to the provided *ldap.Conn.
func (l *LDAPConnectionImpl) SetConn(conn *ldap.Conn) {
	l.conn = conn
}

// GetConn retrieves the current LDAP connection instance managed by LDAPConnectionImpl.
func (l *LDAPConnectionImpl) GetConn() *ldap.Conn {
	return l.conn
}

func (l *LDAPConnectionImpl) GetMutex() *sync.Mutex {
	return &l.mu
}

// Connect establishes a connection to the LDAP server using the provided configuration and GUID.
// It handles TLS setup, retries, connection timeouts, and supports failover across multiple server URIs.
// Returns an error if the connection could not be established or times out.
func (l *LDAPConnectionImpl) Connect(guid *string, ldapConf *config.LDAPConf) error {
	var (
		connected    bool
		timeout      bool
		retryLimit   int
		ldapCounter  int
		err          error
		certificates []tls.Certificate
		tlsConfig    *tls.Config
	)

	connectTicker := time.NewTicker(definitions.LDAPConnectTimeout * time.Second)

	ldapConnectTimeout := make(chan bktype.Done)
	tickerEndChan := make(chan bktype.Done)

	go handleLDAPConnectTimeout(connectTicker, ldapConnectTimeout, tickerEndChan)

EndlessLoop:
	for {
		select {
		case <-ldapConnectTimeout:
			timeout = true

		default:
			if retryLimit > definitions.LDAPMaxRetries {
				return errors.ErrLDAPConnect.WithDetail(
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
			util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "Connection established")

			break EndlessLoop
		}

		if timeout {
			err = errors.ErrLDAPConnectTimeout.WithDetail("Connection timeout reached")

			break EndlessLoop
		}
	}

	connectTicker.Stop()

	tickerEndChan <- bktype.Done{}

	return err
}

// Bind establishes a connection to the LDAP server using either SASL External or simple bind based on the configuration provided.
func (l *LDAPConnectionImpl) Bind(guid *string, ldapConf *config.LDAPConf) error {
	if ldapConf.SASLExternal {
		return l.externalBind(guid)
	}

	return l.simpleBind(guid, ldapConf)
}

// Unbind closes the LDAP connection and unbinds from the server.
func (l *LDAPConnectionImpl) Unbind() (err error) {
	err = l.conn.Unbind()

	return
}

// IsClosing checks if the underlying LDAP connection is in the process of closing. Returns true if closing, false otherwise.
func (l *LDAPConnectionImpl) IsClosing() bool {
	return l.conn.IsClosing()
}

// Search performs an LDAP search based on the provided LDAPRequest and returns the corresponding results or an error.
func (l *LDAPConnectionImpl) Search(ldapRequest *bktype.LDAPRequest) (result bktype.AttributeMapping, rawResult []*ldap.Entry, err error) {
	var searchResult *ldap.SearchResult

	if ldapRequest.MacroSource != nil {
		ldapRequest.Filter = strings.ReplaceAll(ldapRequest.Filter, "%s", ldapRequest.MacroSource.Username)
		ldapRequest.Filter = ldapRequest.MacroSource.ReplaceMacros(ldapRequest.Filter)
	}

	ldapRequest.Filter = util.RemoveCRLFFromQueryOrFilter(ldapRequest.Filter, "")

	util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, ldapRequest.GUID, "filter", ldapRequest.Filter)

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

	searchResult, err = l.conn.Search(searchRequest)
	if err != nil {
		return nil, nil, err
	}

	result = make(bktype.AttributeMapping)

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

		if _, assertOk := result[definitions.DistinguishedName]; assertOk {
			result[definitions.DistinguishedName] = append(result[definitions.DistinguishedName], searchResult.Entries[entryIndex].DN)
		} else {
			result[definitions.DistinguishedName] = []any{searchResult.Entries[entryIndex].DN}
		}
	}

	return result, searchResult.Entries, nil
}

// ModifyAdd performs an LDAP modify-add operation using the provided LDAPRequest to add attributes to an entry.
// Returns an error if the operation fails or if the provided search filter yields no results.
func (l *LDAPConnectionImpl) ModifyAdd(ldapRequest *bktype.LDAPRequest) (err error) {
	var (
		assertOk           bool
		distinguishedNames any
		result             bktype.AttributeMapping
	)

	if result, _, err = l.Search(ldapRequest); err != nil {
		return
	}

	if distinguishedNames, assertOk = result[definitions.DistinguishedName]; !assertOk {
		err = errors.ErrNoLDAPSearchResult.WithDetail(
			fmt.Sprintf("No search result for filter: %v", ldapRequest.Filter))

		return
	}

	if len(distinguishedNames.([]any)) == 0 {
		err = errors.ErrNoLDAPSearchResult.WithDetail(
			fmt.Sprintf("No search result for filter: %v", ldapRequest.Filter))

		return
	}

	dn := distinguishedNames.([]any)[definitions.LDAPSingleValue].(string)

	modifyRequest := ldap.NewModifyRequest(dn, nil)

	if ldapRequest.ModifyAttributes != nil {
		for attributeName, attributeValues := range ldapRequest.ModifyAttributes {
			modifyRequest.Add(attributeName, attributeValues)
		}

		err = l.conn.Modify(modifyRequest)
	}

	return
}

var _ LDAPConnection = (*LDAPConnectionImpl)(nil)

// ldapConnectionState is a struct that helps manage LDAP connections,
// by keeping track of the connection's current state.
type ldapConnectionState struct {
	// state indicates the current LDAP connection state.
	// The value is a constant from the definitions.LDAPState set.
	state definitions.LDAPState
}

// setTLSConfig loads the CA chain and creates a TLS configuration for the LDAP connection. It takes the URL of the LDAP server, an array of certificates, and the LDAPConf configuration
func (l *LDAPConnectionImpl) setTLSConfig(u *url.URL, certificates []tls.Certificate, ldapConf *config.LDAPConf) (*tls.Config, error) {
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
func (l *LDAPConnectionImpl) dialAndStartTLS(guid *string, ldapConf *config.LDAPConf, ldapCounter int, tlsConfig *tls.Config) error {
	var err error

	l.conn, err = ldap.DialURL(ldapConf.ServerURIs[ldapCounter], ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return err
	}

	if ldapConf.StartTLS {
		err = l.conn.StartTLS(tlsConfig)

		if err != nil {
			return err
		}

		util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "STARTTLS")
	}

	return nil
}

// logURIInfo logs the URI information and connection attempt details for debugging purposes.
func (l *LDAPConnectionImpl) logURIInfo(guid *string, ldapConf *config.LDAPConf, ldapCounter int, retryLimit int) {
	util.DebugModule(
		definitions.DbgLDAP,
		definitions.LogKeyGUID, guid,
		"ldap_uri", ldapConf.ServerURIs[ldapCounter],
		"current_attempt", retryLimit+1,
		"max_attempt", definitions.LDAPMaxRetries+1,
	)
}

// handleLDAPConnectTimeout monitors the LDAP connection timeout using a ticker and signals completion through channels.
func handleLDAPConnectTimeout(connectTicker *time.Ticker, timeout chan bktype.Done, done chan bktype.Done) {
	for {
		select {
		case <-connectTicker.C:
			timeout <- bktype.Done{}
		case <-done:
			return
		}
	}
}

// externalBind performs SASL/EXTERNAL authentication using the provided GUID and logs debug information when enabled.
func (l *LDAPConnectionImpl) externalBind(guid *string) error {
	util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "SASL/EXTERNAL")

	err := l.conn.ExternalBind()
	if err != nil {
		return err
	}

	if config.GetFile().GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug {
		l.displayWhoAmI(guid)
	}

	return nil
}

// simpleBind performs a simple LDAP bind operation using the provided GUID and LDAP configuration.
// It initializes the binding process by passing the provided credentials to the LDAP connection.
// Returns an error if the binding fails.
func (l *LDAPConnectionImpl) simpleBind(guid *string, ldapConf *config.LDAPConf) error {
	util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "simple bind")
	util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, "bind_dn", ldapConf.BindDN)

	if config.GetEnvironment().GetDevMode() {
		util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, "bind_password", ldapConf.BindPW)
	}

	_, err := l.conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: ldapConf.BindDN,
		Password: ldapConf.BindPW,
	})

	if err != nil {
		return err
	}

	if config.GetFile().GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug {
		l.displayWhoAmI(guid)
	}

	return nil
}

// displayWhoAmI logs the result of the LDAP "Who Am I?" operation for debugging purposes if there is no error.
func (l *LDAPConnectionImpl) displayWhoAmI(guid *string) {
	res, err := l.conn.WhoAmI(nil) //nolint:govet // Ignore
	if err == nil {
		util.DebugModule(definitions.DbgLDAP, definitions.LogKeyGUID, guid, "whoami", fmt.Sprintf("%+v", res))
	}
}
