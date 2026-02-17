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
	"crypto/tls"
	"crypto/x509"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
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
	"github.com/croessner/nauthilus/server/stats"
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
	Connect(guid string, cfg config.File, logger *slog.Logger, ldapConf *config.LDAPConf) error

	// Bind attempts to authenticate and establish a bound state for the LDAP connection using the provided credentials.
	Bind(ctx context.Context, guid string, cfg config.File, logger *slog.Logger, ldapConf *config.LDAPConf) error

	// Unbind gracefully disconnects the LDAP connection by sending an unbind request to the server and returns any error encountered.
	Unbind() error

	// IsClosing checks whether the LDAP connection is in the process of closing and returns true if it is.
	IsClosing() bool

	// Search executes an LDAP search request based on the specified LDAPRequest and returns the results, raw entries, or an error.
	Search(ctx context.Context, cfg config.File, logger *slog.Logger, ldapRequest *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error)

	// Modify performs an LDAP modify operation based on the provided LDAP request and returns an error if the operation fails.
	Modify(ctx context.Context, cfg config.File, logger *slog.Logger, ldapRequest *bktype.LDAPRequest) error
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

	// conf keeps a reference to the last used LDAPConf for this connection (used for guardrails/settings).
	conf *config.LDAPConf
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
func (l *LDAPConnectionImpl) Connect(guid string, cfg config.File, logger *slog.Logger, ldapConf *config.LDAPConf) error {
	var (
		connected  bool
		timeout    bool
		retryCount int
		err        error
		tlsConfig  *tls.Config
	)

	// Overall connect timeout stays as before using ticker
	connectTicker := time.NewTicker(definitions.LDAPConnectTimeout * time.Second)
	ldapConnectTimeout := make(chan bktype.Done)
	tickerEndChan := make(chan bktype.Done)

	go handleLDAPConnectTimeout(connectTicker, ldapConnectTimeout, tickerEndChan)

	maxRetries := ldapConf.GetRetryMax()
	base := ldapConf.GetRetryBase()
	maxBackoff := ldapConf.GetRetryMaxBackoff()
	pool := ldapConf.GetPoolName()

EndlessLoop:
	for {
		select {
		case <-ldapConnectTimeout:
			timeout = true
		default:
			if retryCount > maxRetries {
				return errors.ErrLDAPConnect.WithDetail(
					fmt.Sprintf("Could not connect to any of the LDAP servers: %v", ldapConf.ServerURIs))
			}

			target := pickTarget(pool, ldapConf.ServerURIs, ldapConf)
			idx := indexOfTarget(ldapConf.ServerURIs, target)

			l.logURIInfo(context.Background(), cfg, logger, guid, ldapConf, idx, retryCount)

			u, _ := url.Parse(target)
			if u.Scheme == "ldaps" || ldapConf.StartTLS {
				tlsConfig, err = l.setTLSConfig(u, ldapConf)
				if err != nil {
					break EndlessLoop
				}
			}

			incInflight(pool, target)
			err = l.dialAndStartTLS(context.Background(), cfg, logger, guid, ldapConf, idx, tlsConfig)
			if err != nil {
				decInflight(pool, target)
				cbOnFailure(pool, target, ldapConf)
				setHealth(pool, target, false)

				// count retry and back off before next attempt
				stats.GetMetrics().GetLdapRetriesTotal().WithLabelValues(pool, "connect").Inc()
				// Jittered backoff before next attempt
				time.Sleep(jitterBackoff(base, retryCount, maxBackoff))

				retryCount++

				continue EndlessLoop
			}

			decInflight(pool, target)
			cbOnSuccess(pool, target)
			setHealth(pool, target, true)

			// store conf for later guardrails (search limits)
			l.conf = ldapConf

			// other operations including SASL External setup unchanged...
			connected = true
		}

		if connected {
			util.DebugModuleWithCfg(context.Background(), cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "Connection established")

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
func (l *LDAPConnectionImpl) Bind(ctx context.Context, guid string, cfg config.File, logger *slog.Logger, ldapConf *config.LDAPConf) error {
	if ldapConf.SASLExternal {
		return l.externalBind(ctx, cfg, logger, guid)
	}

	return l.simpleBind(ctx, cfg, logger, guid, ldapConf)
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
func (l *LDAPConnectionImpl) Search(ctx context.Context, cfg config.File, logger *slog.Logger, ldapRequest *bktype.LDAPRequest) (result bktype.AttributeMapping, rawResult []*ldap.Entry, err error) {
	var searchResult *ldap.SearchResult

	if ldapRequest.MacroSource != nil {
		// Escape username for safe filter embedding (RFC 4515)
		escaped := util.EscapeLDAPFilter(ldapRequest.MacroSource.Username)
		ldapRequest.Filter = strings.ReplaceAll(ldapRequest.Filter, "%s", escaped)
		ldapRequest.Filter = ldapRequest.MacroSource.ReplaceMacros(ldapRequest.Filter)
	}

	ldapRequest.Filter = util.RemoveCRLFFromQueryOrFilter(ldapRequest.Filter, "")

	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, ldapRequest.GUID, "filter", ldapRequest.Filter)

	// Apply LDAP SizeLimit/TimeLimit from connection config if available
	sizeLimit := 0
	timeLimitSec := 0

	if l.conf != nil {
		sizeLimit = l.conf.GetSearchSizeLimit()

		if tl := l.conf.GetSearchTimeLimit(); tl > 0 {
			timeLimitSec = int(tl.Seconds())
		}
	}

	searchRequest := ldap.NewSearchRequest(
		ldapRequest.BaseDN,
		ldapRequest.Scope.Get(),
		ldap.NeverDerefAliases,
		sizeLimit,
		timeLimitSec,
		false,
		ldapRequest.Filter,
		ldapRequest.SearchAttributes,
		nil,
	)

	searchResult, err = l.conn.Search(searchRequest)
	if err != nil {
		// On transport errors, mark connection as lame-duck and close
		if isTransportError(err) {
			_ = l.conn.Close()
			l.SetState(definitions.LDAPStateClosed)
		}

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

		result[definitions.DistinguishedName] = append(result[definitions.DistinguishedName], searchResult.Entries[entryIndex].DN)
	}

	return result, searchResult.Entries, nil
}

// Modify applies changes to an LDAP entry based on the given LDAP request and returns an error if any operation fails.
func (l *LDAPConnectionImpl) Modify(ctx context.Context, cfg config.File, logger *slog.Logger, ldapRequest *bktype.LDAPRequest) (err error) {
	var (
		assertOk           bool
		distinguishedNames any
		distinguishedName  string
		result             bktype.AttributeMapping
	)

	if ldapRequest.ModifyDN == "" {
		if result, _, err = l.Search(ctx, cfg, logger, ldapRequest); err != nil {
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

		distinguishedName = distinguishedNames.([]any)[definitions.LDAPSingleValue].(string)
	} else {
		distinguishedName = ldapRequest.ModifyDN
	}

	if ldapRequest.SubCommand == definitions.LDAPModifyUnknown {
		err = errors.ErrLDAPModify.WithDetail("Undefined LDAP modify operation")

		return
	}

	modifyRequest := ldap.NewModifyRequest(distinguishedName, nil)

	if ldapRequest.ModifyAttributes != nil {
		for attributeName, attributeValues := range ldapRequest.ModifyAttributes {
			switch ldapRequest.SubCommand {
			case definitions.LDAPModifyAdd:
				modifyRequest.Add(attributeName, attributeValues)
			case definitions.LDAPModifyDelete:
				modifyRequest.Delete(attributeName, attributeValues)
			case definitions.LDAPModifyReplace:
				modifyRequest.Replace(attributeName, attributeValues)
			}
		}

		err = l.conn.Modify(modifyRequest)
	}

	// If a transport error occurred, close and mark connection for replacement
	if err != nil && isTransportError(err) {
		_ = l.conn.Close()
		l.SetState(definitions.LDAPStateClosed)
	}

	return
}

var _ LDAPConnection = (*LDAPConnectionImpl)(nil)

// isTransportError returns true for network/transport level LDAP errors that warrant closing the connection.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}

	// net errors or EOF
	if ne, ok := stderrors.AsType[net.Error](err); ok {
		_ = ne

		return true
	}

	if err == io.EOF {
		return true
	}

	// ldap.Error may wrap transport issues
	if le, ok := stderrors.AsType[*ldap.Error](err); ok {
		// ResultCode 81 (server down) is typical transport failure
		if le.ResultCode == uint16(ldap.ErrorNetwork) || uint16(le.ResultCode) == 81 {
			return true
		}

		// Some transports set inner Err
		if le.Err == io.EOF {
			return true
		}
	}

	return false
}

// --- Circuit breaker (per pool+target) and retry helpers ---

type cbState int

const (
	cbClosed cbState = iota
	cbOpen
	cbHalfOpen
)

type cb struct {
	state             cbState
	failures          int
	openedAt          time.Time
	halfOpenRemaining int
}

var (
	cbMu  sync.Mutex
	cbMap = make(map[string]*cb)
)

// cbKey creates a unique key by concatenating the pool and target strings with a "|" delimiter.
func cbKey(pool, target string) string {
	return pool + "|" + target
}

// getCB retrieves a circuit breaker (cb) instance for a given pool and target, creating a new one if it doesn't exist.
func getCB(pool, target string) *cb {
	key := cbKey(pool, target)
	b, ok := cbMap[key]

	if !ok {
		b = &cb{state: cbClosed}
		cbMap[key] = b
	}

	return b
}

// setCBMetric updates the Prometheus gauge for LDAP circuit breaker state with the given pool, target, and state.
func setCBMetric(pool, target string, state cbState) {
	stats.GetMetrics().GetLdapBreakerState().WithLabelValues(pool, target).Set(float64(state))
}

// cbAllow determines if access is allowed based on circuit breaker state for a given pool and target.
func cbAllow(pool, target string, conf *config.LDAPConf) bool {
	cbMu.Lock()
	defer cbMu.Unlock()

	b := getCB(pool, target)
	switch b.state {
	case cbClosed:
		return true
	case cbOpen:
		// If cooldown passed, move to half-open
		if time.Since(b.openedAt) >= conf.GetCBCooldown() {
			b.state = cbHalfOpen
			b.halfOpenRemaining = conf.GetCBHalfOpenMax()

			setCBMetric(pool, target, b.state)

			return true
		}

		return false
	case cbHalfOpen:
		if b.halfOpenRemaining > 0 {
			b.halfOpenRemaining--

			return true
		}

		return false
	default:
		return true
	}
}

// cbOnSuccess resets the circuit breaker for the specified pool and target, setting its state to closed and clearing failures.
func cbOnSuccess(pool, target string) {
	cbMu.Lock()
	defer cbMu.Unlock()

	b := getCB(pool, target)
	b.state = cbClosed
	b.failures = 0
	b.halfOpenRemaining = 0

	setCBMetric(pool, target, b.state)
}

// cbOnFailure increments the failure count for a circuit breaker and transitions its state based on the failure threshold.
func cbOnFailure(pool, target string, conf *config.LDAPConf) {
	cbMu.Lock()
	defer cbMu.Unlock()

	b := getCB(pool, target)
	b.failures++
	threshold := conf.GetCBFailureThreshold()

	if threshold <= 0 {
		threshold = 5
	}

	if b.state == cbHalfOpen || b.failures >= threshold {
		b.state = cbOpen
		b.openedAt = time.Now()
		b.halfOpenRemaining = 0

		setCBMetric(pool, target, b.state)
	}
}

// --- Health state and target selection ---

type targetState struct {
	healthy  bool
	inflight int
}

var (
	healthMu  sync.Mutex
	healthMap = make(map[string]map[string]*targetState) // pool -> target -> state
)

func ensureTargetState(pool, target string) *targetState {
	healthMu.Lock()
	defer healthMu.Unlock()

	m, ok := healthMap[pool]
	if !ok {
		m = make(map[string]*targetState)
		healthMap[pool] = m
	}

	ts, ok := m[target]
	if !ok {
		ts = &targetState{healthy: true}
		m[target] = ts
		// default healthy=1 until proven otherwise
		stats.GetMetrics().GetLdapTargetHealth().WithLabelValues(pool, target).Set(1)
	}

	return ts
}

func setHealth(pool, target string, ok bool) {
	ts := ensureTargetState(pool, target)

	healthMu.Lock()
	defer healthMu.Unlock()

	ts.healthy = ok
	if ok {
		stats.GetMetrics().GetLdapTargetHealth().WithLabelValues(pool, target).Set(1)
	} else {
		stats.GetMetrics().GetLdapTargetHealth().WithLabelValues(pool, target).Set(0)
	}
}

func incInflight(pool, target string) {
	ts := ensureTargetState(pool, target)

	healthMu.Lock()
	defer healthMu.Unlock()

	ts.inflight++

	stats.GetMetrics().GetLdapTargetInflight().WithLabelValues(pool, target).Set(float64(ts.inflight))
}

func decInflight(pool, target string) {
	ts := ensureTargetState(pool, target)

	healthMu.Lock()
	defer healthMu.Unlock()

	if ts.inflight > 0 {
		ts.inflight--
	}

	stats.GetMetrics().GetLdapTargetInflight().WithLabelValues(pool, target).Set(float64(ts.inflight))
}

func pickTarget(pool string, targets []string, conf *config.LDAPConf) string {
	// First pass: healthy and breaker-allowed
	best := ""
	bestInflight := int(^uint(0) >> 1) // max int

	for _, t := range targets {
		ts := ensureTargetState(pool, t)
		if ts.healthy && cbAllow(pool, t, conf) {
			if ts.inflight < bestInflight {
				best = t
				bestInflight = ts.inflight
			}
		}
	}

	if best != "" {
		return best
	}

	// Second pass: breaker-allowed regardless of health (allow probing degraded)
	for _, t := range targets {
		if cbAllow(pool, t, conf) {
			return t
		}
	}

	// Fallback: first target
	if len(targets) > 0 {
		return targets[0]
	}

	return ""
}

func indexOfTarget(targets []string, target string) int {
	for i, t := range targets {
		if t == target {
			return i
		}
	}

	return 0
}

func startHealthLoop(pool string, ldapConf *config.LDAPConf) {
	if ldapConf == nil {
		return
	}

	interval := ldapConf.GetHealthCheckInterval()
	probeTO := ldapConf.GetHealthCheckTimeout()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	probe := func(target string) {
		opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: probeTO})}
		// minimal TLS config if ldaps or StartTLS indicated
		if strings.HasPrefix(strings.ToLower(target), "ldaps") || ldapConf.StartTLS {
			tlsCfg := &tls.Config{InsecureSkipVerify: ldapConf.TLSSkipVerify}
			opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
		}

		c, err := ldap.DialURL(target, opts...)
		if err == nil {
			_ = c.Close()
			setHealth(pool, target, true)

			return
		}

		setHealth(pool, target, false)
	}

	// initial probe
	for _, t := range ldapConf.ServerURIs {
		probe(t)
	}

	for range ticker.C {
		for _, t := range ldapConf.ServerURIs {
			probe(t)
		}
	}
}

// jitterBackoff applies exponential backoff with capped jitter to calculate the next retry duration.
// base specifies the initial delay duration.
// attempt is the current retry attempt count, used to calculate the exponential backoff.
// max is the maximum delay duration to cap the backoff.
func jitterBackoff(base time.Duration, attempt int, max time.Duration) time.Duration {
	if base <= 0 {
		base = 200 * time.Millisecond
	}

	if max <= 0 {
		max = 2 * time.Second
	}

	// exponential backoff
	b := base * time.Duration(1<<attempt)
	if b > max {
		b = max
	}

	if b <= 0 {
		return 0
	}

	return time.Duration(rand.Int63n(int64(b) + 1))
}

// ldapConnectionState is a struct that helps manage LDAP connections,
// by keeping track of the connection's current state.
type ldapConnectionState struct {
	// state indicates the current LDAP connection state.
	// The value is a constant from the definitions.LDAPState set.
	state definitions.LDAPState
}

// setTLSConfig loads the CA chain and creates a TLS configuration for the LDAP connection. It takes the URL of the LDAP server, an array of certificates, and the LDAPConf configuration
func (l *LDAPConnectionImpl) setTLSConfig(u *url.URL, ldapConf *config.LDAPConf) (*tls.Config, error) {
	var (
		caCert       []byte
		caCertPool   *x509.CertPool
		certificates []tls.Certificate
		cert         tls.Certificate
		err          error
	)

	// Load CA chain if specified
	if ldapConf.TLSCAFile != "" {
		caCert, err = os.ReadFile(ldapConf.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}

		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
	} else {
		caCertPool = nil // It's okay to use nil for RootCAs in tls.Config
	}

	if ldapConf.TLSClientCert != "" && ldapConf.TLSClientKey != "" {
		cert, err = tls.LoadX509KeyPair(ldapConf.TLSClientCert, ldapConf.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
		}

		certificates = append(certificates, cert)
	}

	// Determine host for ServerName
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
		VerifyPeerCertificate: func(certificates [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, certBytes := range certificates {
				certificate, err := x509.ParseCertificate(certBytes)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}

				if time.Now().After(certificate.NotAfter) {
					return fmt.Errorf("certificate expired on %v", certificate.NotAfter)
				}

				if time.Now().Before(certificate.NotBefore) {
					return fmt.Errorf("certificate not valid before %v", certificate.NotBefore)
				}
			}

			return nil
		},
	}, nil
}

// dialAndStartTLS dials the LDAP server and starts a TLS connection if configured.
func (l *LDAPConnectionImpl) dialAndStartTLS(ctx context.Context, cfg config.File, logger *slog.Logger, guid string, ldapConf *config.LDAPConf, ldapCounter int, tlsConfig *tls.Config) error {
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

		util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "STARTTLS")
	}

	return nil
}

// logURIInfo logs the URI information and connection attempt details for debugging purposes.
func (l *LDAPConnectionImpl) logURIInfo(ctx context.Context, cfg config.File, logger *slog.Logger, guid string, ldapConf *config.LDAPConf, ldapCounter int, retryLimit int) {
	util.DebugModuleWithCfg(
		ctx,
		cfg,
		logger,
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
func (l *LDAPConnectionImpl) externalBind(ctx context.Context, cfg config.File, logger *slog.Logger, guid string) error {
	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "SASL/EXTERNAL")

	err := l.conn.ExternalBind()
	if err != nil {
		return err
	}

	if cfg.GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug {
		l.displayWhoAmI(ctx, cfg, logger, guid)
	}

	return nil
}

// simpleBind performs a simple LDAP bind operation using the provided GUID and LDAP configuration.
// It initializes the binding process by passing the provided credentials to the LDAP connection.
// Returns an error if the binding fails.
func (l *LDAPConnectionImpl) simpleBind(ctx context.Context, cfg config.File, logger *slog.Logger, guid string, ldapConf *config.LDAPConf) error {
	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "simple bind")
	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, "bind_dn", ldapConf.BindDN)

	var bindPassword string
	ldapConf.BindPW.WithString(func(value string) {
		bindPassword = value
	})

	if cfg.GetServer().GetEnvironment().GetDevMode() {
		util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, "bind_password", bindPassword)
	}

	_, err := l.conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: ldapConf.BindDN,
		Password: bindPassword,
	})

	if err != nil {
		return err
	}

	if cfg.GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug {
		l.displayWhoAmI(ctx, cfg, logger, guid)
	}

	return nil
}

// displayWhoAmI logs the result of the LDAP "Who Am I?" operation for debugging purposes if there is no error.
func (l *LDAPConnectionImpl) displayWhoAmI(ctx context.Context, cfg config.File, logger *slog.Logger, guid string) {
	res, err := l.conn.WhoAmI(nil) //nolint:govet // Ignore
	if err == nil {
		util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgLDAP, definitions.LogKeyGUID, guid, "whoami", fmt.Sprintf("%+v", res))
	}
}
