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

package core

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
)

// transportPeerTestConn is a connection whose remote address is fixed and that must never be read.
type transportPeerTestConn struct {
	net.Conn
	remote net.Addr
}

// RemoteAddr returns the fixed TCP upstream address.
func (c transportPeerTestConn) RemoteAddr() net.Addr {
	return c.remote
}

// Read fails the test path loudly if unwrapping ever tried to consume a PROXY header.
func (c transportPeerTestConn) Read([]byte) (int, error) {
	panic("transportPeerAddress must not read from the connection")
}

// TestTransportPeerAddressIgnoresProxyProtocolSource pins that the recorded peer is the TCP upstream of
// the connection, with and without TLS, and never the source a PROXY header would claim.
func TestTransportPeerAddressIgnoresProxyProtocolSource(t *testing.T) {
	upstream := transportPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 51000}}
	proxied := proxyproto.NewConn(upstream)

	for name, conn := range map[string]net.Conn{
		"plain":           upstream,
		"proxy protocol":  proxied,
		"tls over proxy":  tls.Server(proxied, &tls.Config{}),
		"tls over direct": tls.Server(upstream, &tls.Config{}),
	} {
		t.Run(name, func(t *testing.T) {
			if got := transportPeerAddress(conn); got != "198.51.100.7" {
				t.Fatalf("transportPeerAddress() = %q, want the TCP upstream", got)
			}
		})
	}
}
