// Copyright (C) 2026 Christian Rößner
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
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/pires/go-proxyproto"
)

func TestCheckBackendConnectionUsesConfiguredConnectTimeout(t *testing.T) {
	t.Parallel()

	wantTimeout := 150 * time.Millisecond

	var gotTimeout time.Duration

	cfg := &config.FileSettings{
		BackendServerMonitoring: &config.BackendServerMonitoring{
			ConnectTimeout: wantTimeout,
		},
	}
	server := &config.BackendServer{Protocol: "imap", Host: "127.0.0.1", Port: 993}
	dialErr := errors.New("dial stopped")

	err := checkBackendConnectionWithDialer(cfg, slog.Default(), server, backendCheckPhaseConnect, func(_ string, _ string, timeout time.Duration) (net.Conn, error) {
		gotTimeout = timeout

		return nil, dialErr
	})

	if !errors.Is(err, dialErr) {
		t.Fatalf("expected dial error %v, got %v", dialErr, err)
	}

	if gotTimeout != wantTimeout {
		t.Fatalf("expected connect timeout %s, got %s", wantTimeout, gotTimeout)
	}
}

func TestConnectProbeDoesNotRunDeepProtocolCheck(t *testing.T) {
	t.Parallel()

	cfg := &config.FileSettings{
		BackendServerMonitoring: &config.BackendServerMonitoring{},
	}
	server := &config.BackendServer{
		Protocol:     "smtp",
		Host:         "127.0.0.1",
		Port:         25,
		DeepCheck:    true,
		TestUsername: "monitor",
		TestPassword: "secret",
	}

	err := checkBackendConnectionWithDialer(cfg, slog.Default(), server, backendCheckPhaseConnect, func(_ string, _ string, _ time.Duration) (net.Conn, error) {
		return &probeOnlyConn{}, nil
	})
	if err != nil {
		t.Fatalf("connect probe should not execute SMTP deep check: %v", err)
	}
}

func TestIMAPProxyV2PrecedesSTARTTLS(t *testing.T) {
	cfg := &config.FileSettings{
		BackendServerMonitoring: &config.BackendServerMonitoring{
			ConnectTimeout: time.Second,
			TLSTimeout:     time.Second,
			DeepTimeout:    2 * time.Second,
		},
	}
	server := &config.BackendServer{
		Protocol:      "imap",
		Host:          "127.0.0.1",
		Port:          30143,
		DeepCheck:     true,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismPlain,
		TLSMode:       config.BackendTLSModeStartTLS,
		TLSSkipVerify: true,
		HAProxyV2:     true,
	}

	clientConn, waitServer := newProxyStartTLSScriptConn(t, checkProxyIMAPBeforeTLS, checkProxyIMAPAfterTLS)
	defer waitServer()

	err := checkBackendConnectionWithDialer(cfg, slog.Default(), server, backendCheckPhaseDeep, func(_ string, _ string, _ time.Duration) (net.Conn, error) {
		return clientConn, nil
	})
	if err != nil {
		t.Fatalf("PROXY-v2 IMAP STARTTLS check failed: %v", err)
	}
}

func TestPrepareBackendConnectionHonorsExplicitImplicitTLS(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "imap",
		Host:          "localhost",
		Port:          993,
		TLSMode:       config.BackendTLSModeImplicit,
		TLSSkipVerify: true,
	}
	monitoringCfg := &config.BackendServerMonitoring{TLSTimeout: time.Second}
	certificate := testTLSCertificate(t)
	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)

	go func() {
		defer closeProtocolConn(serverConn)

		tlsConn := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		errCh <- tlsConn.Handshake()
	}()

	preparedConn, err := prepareBackendConnection(nil, slog.Default(), server, backendCheckPhaseConnect, monitoringCfg, clientConn)
	if err != nil {
		t.Fatalf("prepare explicit implicit TLS connection failed: %v", err)
	}

	defer closeProtocolConn(preparedConn)

	if !isTLSConnection(preparedConn) {
		t.Fatalf("prepared connection type = %T, want *tls.Conn", preparedConn)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("scripted implicit TLS server failed: %v", err)
	}
}

// checkProxyIMAPBeforeTLS validates PROXY framing and the plaintext IMAP upgrade exchange.
func checkProxyIMAPBeforeTLS(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if err := writeTestLine(conn, "* OK imap.example.test ready"); err != nil {
		return err
	}

	if got, err := readTestLine(reader); err != nil || got != "a1 CAPABILITY" {
		return fmt.Errorf("pre-TLS CAPABILITY command = %q, err = %w", got, err)
	}

	proxyConn, ok := conn.(*proxyproto.Conn)
	if !ok {
		return fmt.Errorf("scripted connection type = %T, want *proxyproto.Conn", conn)
	}

	header := proxyConn.ProxyHeader()
	if header == nil || header.Version != 2 || !header.Command.IsLocal() {
		return fmt.Errorf("PROXY header = %#v, want v2 LOCAL", header)
	}

	if err := writeTestLines(conn, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN", "a1 OK capability completed"); err != nil {
		return err
	}

	if got, err := readTestLine(reader); err != nil || got != "a2 STARTTLS" {
		return fmt.Errorf("STARTTLS command = %q, err = %w", got, err)
	}

	return writeTestLine(conn, "a2 OK begin TLS negotiation")
}

// checkProxyIMAPAfterTLS validates protected capabilities, authentication, and logout.
func checkProxyIMAPAfterTLS(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if got, err := readTestLine(reader); err != nil || got != "a1 CAPABILITY" {
		return fmt.Errorf("post-TLS CAPABILITY command = %q, err = %w", got, err)
	}

	if err := writeTestLines(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR", "a1 OK capability completed"); err != nil {
		return err
	}

	if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, "a2 AUTHENTICATE PLAIN ") {
		return fmt.Errorf("protected AUTH command = %q, err = %w", got, err)
	}

	if err := writeTestLine(conn, "a2 OK authenticated"); err != nil {
		return err
	}

	if got, err := readTestLine(reader); err != nil || got != "a3 LOGOUT" {
		return fmt.Errorf("LOGOUT command = %q, err = %w", got, err)
	}

	return nil
}

type probeOnlyConn struct{}

func (c *probeOnlyConn) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (c *probeOnlyConn) Write(input []byte) (int, error) {
	return len(input), nil
}

func (c *probeOnlyConn) Close() error {
	return nil
}

func (c *probeOnlyConn) LocalAddr() net.Addr {
	return testAddr("local")
}

func (c *probeOnlyConn) RemoteAddr() net.Addr {
	return testAddr("remote")
}

func (c *probeOnlyConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *probeOnlyConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *probeOnlyConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type testAddr string

func (a testAddr) Network() string {
	return string(a)
}

func (a testAddr) String() string {
	return string(a)
}
