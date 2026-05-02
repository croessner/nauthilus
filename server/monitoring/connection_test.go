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
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
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
