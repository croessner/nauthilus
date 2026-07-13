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

package monitoring

import (
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"

	"github.com/pires/go-proxyproto"
)

// Monitor defines an interface for monitoring and checking backend server connections.
// It provides a method to verify connectivity using specified configurations.
type Monitor interface {
	// CheckBackendConnection checks the backend connection of a server based on the provided Host address, port number, whether the server runs with HAProxy V2 protocol, and whether TLS should be used. It returns an error if the connection fails.
	CheckBackendConnection(server *config.BackendServer) error

	// CheckBackendConnectionPhase checks one backend health-check phase.
	CheckBackendConnectionPhase(server *config.BackendServer, phase BackendCheckPhase) error
}

// ConnMonitor is a struct that implements monitoring of backend server connections by checking their availability.
type ConnMonitor struct {
	cfg    config.File
	logger *slog.Logger
}

// CheckBackendConnection attempts to establish a connection to a backend server to verify its availability.
// It returns an error if the connection cannot be established, using the specified configuration parameters.
func (cm *ConnMonitor) CheckBackendConnection(server *config.BackendServer) error {
	return checkBackendConnection(cm.cfg, cm.logger, server)
}

// CheckBackendConnectionPhase checks one backend health-check phase.
func (cm *ConnMonitor) CheckBackendConnectionPhase(server *config.BackendServer, phase BackendCheckPhase) error {
	return checkBackendConnectionWithDialer(cm.cfg, cm.logger, server, phase, net.DialTimeout)
}

var _ Monitor = (*ConnMonitor)(nil)

// NewMonitor returns a new instance of the Monitor interface. The returned Monitor is implemented by the ConnMonitor struct.
func NewMonitor(cfg config.File, logger *slog.Logger) Monitor {
	return &ConnMonitor{
		cfg:    cfg,
		logger: logger,
	}
}

// BackendCheckPhase identifies which part of a backend health check is being executed.
type BackendCheckPhase string

const (
	// BackendCheckPhaseConnect verifies TCP, HAProxy-v2 preface, and TLS reachability only.
	BackendCheckPhaseConnect BackendCheckPhase = "connect"

	// BackendCheckPhaseDeep verifies the protocol-level deep check when enabled for a target.
	BackendCheckPhaseDeep BackendCheckPhase = "deep"
)

const (
	backendCheckPhaseConnect = BackendCheckPhaseConnect
	backendCheckPhaseDeep    = BackendCheckPhaseDeep
)

type backendDialer func(network string, address string, timeout time.Duration) (net.Conn, error)

// checkBackendConnection attempts to establish a TCP connection to a specified backend server within a given timeout period.
// If the backend requires HAProxy v2 protocol, it sends the necessary headers. For secure connections, it performs a TLS handshake.
// Upon successful connection, it handles different protocols using the provided server settings. It returns an error if any step fails.
func checkBackendConnection(cfg config.File, logger *slog.Logger, server *config.BackendServer) error {
	return checkBackendConnectionWithDialer(cfg, logger, server, BackendCheckPhaseDeep, net.DialTimeout)
}

func checkBackendConnectionWithDialer(cfg config.File, logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, dialer backendDialer) error {
	monitoringCfg := monitoringConfig(cfg)

	conn, err := dialBackendConnection(logger, server, phase, monitoringCfg, dialer)
	if err != nil {
		return err
	}

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	preparedConn, err := prepareBackendConnection(cfg, logger, server, phase, monitoringCfg, conn)
	if err != nil {
		return err
	}

	conn = preparedConn

	return runBackendProtocolCheck(logger, server, phase, monitoringCfg, conn)
}

func dialBackendConnection(logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, monitoringCfg *config.BackendServerMonitoring, dialer backendDialer) (net.Conn, error) {
	if dialer == nil {
		dialer = net.DialTimeout
	}

	connectTimeout := monitoringCfg.GetServerConnectTimeout(server)

	conn, err := dialer("tcp", net.JoinHostPort(server.Host, fmt.Sprintf("%d", server.Port)), connectTimeout)
	if err != nil {
		_ = level.Error(logger).Log(
			definitions.LogKeyMsg, "TCP dial failed",
			"host", server.Host,
			"port", server.Port,
			"protocol", strings.ToLower(server.Protocol),
			"health_check_phase", string(phase),
			definitions.LogKeyError, err,
		)

		return nil, err
	}

	setConnectionDeadline(conn, connectTimeout)

	return conn, nil
}

func prepareBackendConnection(cfg config.File, logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, monitoringCfg *config.BackendServerMonitoring, conn net.Conn) (net.Conn, error) {
	if server.HAProxyV2 {
		if err := sendHAProxyV2Header(cfg, logger, server, phase, conn); err != nil {
			return nil, err
		}
	}

	if server.GetTLSMode() != config.BackendTLSModeImplicit {
		return conn, nil
	}

	return wrapTLSConnection(logger, server, phase, monitoringCfg, conn)
}

func sendHAProxyV2Header(cfg config.File, logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, conn net.Conn) error {
	err := checkHAproxyV2(cfg, logger, conn, server.Host, server.Port)
	if err == nil {
		return nil
	}

	_ = level.Error(logger).Log(
		definitions.LogKeyMsg, "HAProxy v2 header send failed",
		"host", server.Host,
		"port", server.Port,
		"protocol", strings.ToLower(server.Protocol),
		"health_check_phase", string(phase),
		definitions.LogKeyError, err,
	)

	return err
}

func wrapTLSConnection(logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, monitoringCfg *config.BackendServerMonitoring, conn net.Conn) (net.Conn, error) {
	handshaker := newBackendTLSHandshaker(
		logger,
		server,
		phase,
		config.BackendTLSModeImplicit,
		monitoringCfg.GetServerTLSTimeout(server),
		0,
	)

	return handshaker.Handshake(conn)
}

// backendTLSHandshaker owns shared TLS policy, deadlines, and error reporting.
type backendTLSHandshaker struct {
	logger               *slog.Logger
	server               *config.BackendServer
	phase                BackendCheckPhase
	mode                 config.BackendTLSMode
	handshakeTimeout     time.Duration
	postHandshakeTimeout time.Duration
}

// newBackendTLSHandshaker builds one backend TLS handshake boundary.
func newBackendTLSHandshaker(logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, mode config.BackendTLSMode, handshakeTimeout time.Duration, postHandshakeTimeout time.Duration) *backendTLSHandshaker {
	return &backendTLSHandshaker{
		logger:               logger,
		server:               server,
		phase:                phase,
		mode:                 mode,
		handshakeTimeout:     handshakeTimeout,
		postHandshakeTimeout: postHandshakeTimeout,
	}
}

// defaultBackendTLSHandshaker provides production defaults for direct protocol tests and adapters.
func defaultBackendTLSHandshaker(logger *slog.Logger, server *config.BackendServer) *backendTLSHandshaker {
	monitoringCfg := &config.BackendServerMonitoring{}

	return newBackendTLSHandshaker(
		logger,
		server,
		BackendCheckPhaseDeep,
		config.BackendTLSModeStartTLS,
		monitoringCfg.GetServerTLSTimeout(server),
		monitoringCfg.GetServerDeepTimeout(server),
	)
}

// Handshake applies the shared TLS client policy and restores the post-handshake deadline.
func (h *backendTLSHandshaker) Handshake(conn net.Conn) (net.Conn, error) {
	if h == nil || h.server == nil {
		return nil, fmt.Errorf("backend TLS handshaker is not configured")
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: h.server.TLSSkipVerify,
		ServerName:         h.server.Host,
		MinVersion:         tls.VersionTLS12,
	})

	setConnectionDeadline(tlsConn, h.handshakeTimeout)

	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		_ = level.Error(h.logger).Log(
			definitions.LogKeyMsg, "TLS handshake failed",
			"host", h.server.Host,
			"port", h.server.Port,
			"protocol", strings.ToLower(h.server.Protocol),
			"tls_mode", h.mode,
			"skip_verify", h.server.TLSSkipVerify,
			"health_check_phase", string(h.phase),
			definitions.LogKeyError, err,
		)

		return nil, fmt.Errorf("TLS handshake failed (host=%s port=%d protocol=%s tls_mode=%s skip_verify=%t): %w", h.server.Host, h.server.Port, strings.ToLower(h.server.Protocol), h.mode, h.server.TLSSkipVerify, err)
	}

	if h.postHandshakeTimeout > 0 {
		setConnectionDeadline(tlsConn, h.postHandshakeTimeout)
	}

	return tlsConn, nil
}

func runBackendProtocolCheck(logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, monitoringCfg *config.BackendServerMonitoring, conn net.Conn) error {
	if phase == BackendCheckPhaseConnect || !server.DeepCheck {
		return nil
	}

	setConnectionDeadline(conn, monitoringCfg.GetServerDeepTimeout(server))

	return handleProtocol(logger, server, monitoringCfg, conn)
}

func monitoringConfig(cfg config.File) *config.BackendServerMonitoring {
	if cfg == nil {
		return nil
	}

	return cfg.GetBackendServerMonitoring()
}

func setConnectionDeadline(conn net.Conn, timeout time.Duration) {
	if conn == nil {
		return
	}

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)
}

// handleProtocol runs a protocol deep check with the configured TLS transport policy.
func handleProtocol(logger *slog.Logger, server *config.BackendServer, monitoringCfg *config.BackendServerMonitoring, conn net.Conn) (err error) {
	handshaker := newBackendTLSHandshaker(
		logger,
		server,
		BackendCheckPhaseDeep,
		config.BackendTLSModeStartTLS,
		monitoringCfg.GetServerTLSTimeout(server),
		monitoringCfg.GetServerDeepTimeout(server),
	)

	switch strings.ToLower(server.Protocol) {
	case "smtp", "lmtp":
		err = checkSMTPWithTLS(logger, conn, server, handshaker)
	case "pop3":
		err = checkPOP3WithTLS(logger, conn, server, handshaker)
	case "imap":
		err = checkIMAPWithTLS(logger, conn, server, handshaker)
	case "sieve":
		err = checkSieveWithTLS(logger, conn, server, handshaker)
	case "http":
		err = checkHTTP(logger, conn, server)
	default:
		err = stderrors.New("unsupported protocol")
	}

	return err
}

// isTLSConnection determines if the provided network connection is a TLS connection.
func isTLSConnection(conn net.Conn) bool {
	_, isTLS := conn.(*tls.Conn)

	return isTLS
}

// checkHAproxyV2 sends a HAProxy protocol v2 header to the given connection with specified Host address and port.
// It returns an error if writing the header to the connection fails. The error is also logged for diagnostics.
func checkHAproxyV2(cfg config.File, logger *slog.Logger, conn net.Conn, ipAddress string, port int) error {
	header := &proxyproto.Header{
		Command: proxyproto.LOCAL,
		Version: 2,
		SourceAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 0,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(ipAddress),
			Port: port,
		},
	}

	_, err := header.WriteTo(conn)
	if err != nil {
		handleHAproxyV2Error(cfg, logger, err)
	}

	return err
}

// handleHAproxyV2Error logs an error related to HAProxy version 2 operations using the global Logger.
func handleHAproxyV2Error(cfg config.File, logger *slog.Logger, err error) {
	level.Error(logger).Log(
		definitions.LogKeyInstance, cfg.GetServer().GetInstanceName(),
		definitions.LogKeyMsg, "HAProxy v2 error",
		definitions.LogKeyError, err,
	)
}
