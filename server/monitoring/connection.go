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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"

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

	if !server.TLS || strings.ToLower(server.Protocol) == "sieve" {
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
	tlsConfig := &tls.Config{
		InsecureSkipVerify: server.TLSSkipVerify,
		ServerName:         server.Host,
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, tlsConfig)

	setConnectionDeadline(tlsConn, monitoringCfg.GetServerTLSTimeout(server))

	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		_ = level.Error(logger).Log(
			definitions.LogKeyMsg, "TLS handshake failed",
			"host", server.Host,
			"port", server.Port,
			"protocol", strings.ToLower(server.Protocol),
			"skip_verify", server.TLSSkipVerify,
			"health_check_phase", string(phase),
			definitions.LogKeyError, err,
		)

		return nil, fmt.Errorf("TLS handshake failed (host=%s port=%d protocol=%s skip_verify=%t): %w", server.Host, server.Port, strings.ToLower(server.Protocol), server.TLSSkipVerify, err)
	}

	return net.Conn(tlsConn), nil
}

func runBackendProtocolCheck(logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase, monitoringCfg *config.BackendServerMonitoring, conn net.Conn) error {
	if phase == BackendCheckPhaseConnect || !server.DeepCheck {
		return nil
	}

	setConnectionDeadline(conn, monitoringCfg.GetServerDeepTimeout(server))

	return handleProtocol(logger, server, conn)
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

// handleProtocol processes authentication for a test user over a network connection based on the specified protocol.
// Supported protocols include SMTP, POP3, IMAP, and HTTP. If an unsupported protocol is specified, a warning is logged.
// This function currently does not support plain connections requiring StartTLS.
func handleProtocol(logger *slog.Logger, server *config.BackendServer, conn net.Conn) (err error) {
	// Limited support only. Plain connections requiring StartTLS are not supported at the moment!
	switch strings.ToLower(server.Protocol) {
	case "smtp", "lmtp":
		err = checkSMTP(logger, conn, server)
	case "pop3":
		err = checkPOP3(logger, conn, server)
	case "imap":
		err = checkIMAP(logger, conn, server)
	case "sieve":
		err = checkSieve(logger, conn, server)
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
