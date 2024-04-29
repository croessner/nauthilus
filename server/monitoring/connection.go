package monitoring

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/go-kit/log/level"
	"github.com/pires/go-proxyproto"
)

// CheckBackendConnection checks the availability of a backend server by trying to establish a TCP connection with the specified IP address and port.
// It returns an error if the connection cannot be established within the timeout period.
// The function does not retry the connection and closes the connection before returning.
func CheckBackendConnection(ipAddress string, port int, haproxyV2 bool, useTLS bool) error {
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
	level.Error(logging.DefaultErrLogger).Log(
		global.LogKeyInstance, global.InstanceName,
		global.LogKeyError, "HAProxy v2 error", "error", err,
	)
}
