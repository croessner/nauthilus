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
	"fmt"
	"net"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/go-kit/log/level"
	"github.com/pires/go-proxyproto"
)

// Monitor represents an interface used to check the backend connection of a server.
// It provides the method CheckBackendConnection to perform the check and returns an error if the connection fails.
// The CheckBackendConnection method takes the IP address, port number, whether the server runs with HAProxy V2 protocol,
// and whether TLS should be used as parameters.
type Monitor interface {
	// CheckBackendConnection checks the backend connection of a server based on the provided IP address, port number, whether the server runs with HAProxy V2 protocol, and whether TLS should be used. It returns an error if the connection fails.
	CheckBackendConnection(ipAddress string, port int, haproxyv2 bool, useTLS bool) error
}

// ConnMonitor represents a connection monitor that can be used to check the availability of a backend server
// by establishing a TCP connection with the specified IP address and port.
// It provides a method `CheckBackendConnection` to perform the check and returns an error if the connection
// cannot be established within the timeout period. This monitor does not retry the connection and closes
// the connection before returning.
type ConnMonitor struct{}

// CheckBackendConnection checks the availability of a backend server by trying to
// establish a TCP connection with the specified IP address and port.
// It returns an error if the connection cannot be established within the timeout period.
// The function does not retry the connection and closes the connection before returning.
func (ConnMonitor) CheckBackendConnection(ipAddress string, port int, haproxyv2 bool, useTLS bool) error {
	return checkBackendConnection(ipAddress, port, haproxyv2, useTLS)
}

var _ Monitor = (*ConnMonitor)(nil)

// NewMonitor returns a new instance of the Monitor interface. The returned Monitor is implemented by the ConnMonitor struct.
func NewMonitor() Monitor {
	return &ConnMonitor{}
}

// checkBackendConnection checks the availability of a backend server by trying to establish a TCP connection with the specified IP address and port.
// It returns an error if the connection cannot be established within the timeout period.
// The function does not retry the connection and closes the connection before returning.
func checkBackendConnection(ipAddress string, port int, haproxyV2 bool, useTLS bool) error {
	timeout := 5 * time.Second

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipAddress, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return err
	}

	defer conn.Close()

	if haproxyV2 {
		if err = checkHAproxyV2(conn, ipAddress, port); err != nil {
			return err
		}
	}

	if useTLS {
		// Securing the connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		tlsConn := tls.Client(conn, tlsConfig)

		// Handshake to establish the secure connection
		err = tlsConn.Handshake()
		if err != nil {
			return err
		}

		// Replace the plain 'conn' with the tlsConn - everything written/read to/from this connection is encrypted/decrypted
		conn = net.Conn(tlsConn)
	}

	return nil
}

func checkHAproxyV2(conn net.Conn, ipAddress string, port int) error {
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
		handleHAproxyV2Error(err)
	}

	return err
}

func handleHAproxyV2Error(err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyInstance, definitions.InstanceName,
		definitions.LogKeyMsg, "HAProxy v2 error", "error", err,
	)
}
