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
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/go-kit/log/level"
	"github.com/pires/go-proxyproto"
)

// Monitor defines an interface for monitoring and checking backend server connections.
// It provides a method to verify connectivity using specified configurations.
type Monitor interface {
	// CheckBackendConnection checks the backend connection of a server based on the provided Host address, port number, whether the server runs with HAProxy V2 protocol, and whether TLS should be used. It returns an error if the connection fails.
	CheckBackendConnection(server *config.BackendServer) error
}

// ConnMonitor is a struct that implements monitoring of backend server connections by checking their availability.
type ConnMonitor struct{}

// CheckBackendConnection attempts to establish a connection to a backend server to verify its availability.
// It returns an error if the connection cannot be established, using the specified configuration parameters.
func (ConnMonitor) CheckBackendConnection(server *config.BackendServer) error {
	return checkBackendConnection(server)
}

var _ Monitor = (*ConnMonitor)(nil)

// NewMonitor returns a new instance of the Monitor interface. The returned Monitor is implemented by the ConnMonitor struct.
func NewMonitor() Monitor {
	return &ConnMonitor{}
}

// checkBackendConnection attempts to establish a TCP connection to a specified backend server within a given timeout period.
// If the backend requires HAProxy v2 protocol, it sends the necessary headers. For secure connections, it performs a TLS handshake.
// Upon successful connection, it handles different protocols using the provided server settings. It returns an error if any step fails.
func checkBackendConnection(server *config.BackendServer) error {
	timeout := 5 * time.Second

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server.Host, fmt.Sprintf("%d", server.Port)), timeout)
	if err != nil {
		return err
	}

	defer conn.Close()

	if server.HAProxyV2 {
		if err = checkHAproxyV2(conn, server.Host, server.Port); err != nil {
			return err
		}
	}

	if server.TLS {
		// Securing the connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: server.TLSSkipVerify,
			ServerName:         server.Host,
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

	handleProtocol(server, conn)

	return nil
}

// handleProtocol processes authentication for a test user over a network connection based on the specified protocol.
// Supported protocols include SMTP, POP3, IMAP, and HTTP. If an unsupported protocol is specified, a warning is logged.
// This function currently does not support plain connections requiring StartTLS.
func handleProtocol(server *config.BackendServer, conn net.Conn) {
	// Limited support only. Plain connections requireing StartTLS are not supported at the moment!
	switch server.Protocol {
	case "smtp":
		checkSMTP(conn, server.TestUsername, server.TestPassword)
	case "pop3":
		checkPOP3(conn, server.TestUsername, server.TestPassword)
	case "imap":
		checkIMAP(conn, server.TestUsername, server.TestPassword)
	case "http":
		checkHTTP(conn, server.Host, server.RequestURI, server.TestUsername, server.TestPassword)
	default:
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unsupported protocol", "protocol", server.Protocol)
	}
}

// checkSMTP performs SMTP authentication using the provided username and password over a given network connection.
// It sends EHLO and AUTH LOGIN commands to the SMTP server, encodes credentials in base64, and logs errors if authentication fails.
func checkSMTP(conn net.Conn, username string, password string) {
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	defer fmt.Fprintf(conn, "QUIT\r\n")

	_, err := tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading SMTP initial response, error: %s", err))

		return
	}

	fmt.Fprintf(conn, "EHLO localhost\r\n")
	for {
		response, err := tp.ReadLine()
		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading SMTP EHLO response, error: %v", err))

			return
		}

		if response[:3] != "250" {
			if response[0] >= '4' {
				level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("EHLO command failed, response: %s", response))

				return
			}

			break
		}
	}

	if username == "" || password == "" {
		return
	}

	fmt.Fprintf(conn, "AUTH LOGIN\r\n")

	_, err = tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error in SMTP AUTH LOGIN, error: %v", err))

		return
	}

	usernameEnc := base64.StdEncoding.EncodeToString([]byte(username))

	fmt.Fprintf(conn, "%s\r\n", usernameEnc)

	_, err = tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error sending SMTP username, error: %v", err))

		return
	}

	passwordEnc := base64.StdEncoding.EncodeToString([]byte(password))

	fmt.Fprintf(conn, "%s\r\n", passwordEnc)

	response, err := tp.ReadLine()
	if err != nil || response[:3] != "235" {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("SMTP AUTH LOGIN failed, error: %v", err), "response", response)

		return
	}
}

// checkPOP3 performs POP3 authentication using the provided username and password over a given network connection.
// It sends USER and PASS commands to the POP3 server, validates responses, and logs errors if authentication fails.
func checkPOP3(conn net.Conn, username string, password string) {
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	defer fmt.Fprintf(conn, "QUIT\r\n")

	greeting, err := tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading POP3 greeting, error: %v", err))

		return
	}

	if !isOkResponsePOP3(greeting) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("POP3 greeting failed, error: %s", greeting))

		return
	}

	if username == "" || password == "" {
		return
	}

	fmt.Fprintf(conn, "USER %s\r\n", username)

	response, err := tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading POP3 response after USER command, error %v", err))

		return
	}

	if !isOkResponsePOP3(response) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("POP3 USER command failed, error: %s", response))

		return
	}

	fmt.Fprintf(conn, "PASS %s\r\n", password)

	response, err = tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading POP3 response after PASS command: %v\n", err))

		return
	}

	if !isOkResponsePOP3(response) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("POP3 login failed: %s\n", response))
	}
}

// isOkResponsePOP3 checks if the provided POP3 server response starts with "+OK".
func isOkResponsePOP3(response string) bool {
	return bytes.HasPrefix([]byte(response), []byte("+OK"))
}

// checkIMAP authenticates to an IMAP server using provided username and password over an existing network connection.
// It sends an IMAP LOGIN command and checks if the response indicates a successful login.
// Errors in reading responses or unsuccessful logins are logged for diagnostic purposes.
func checkIMAP(conn net.Conn, username string, password string) {
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	defer fmt.Fprintf(conn, "a2 LOGOUT\r\n")

	greeting, err := tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading IMAP greeting, error: %v", err))
		return
	}

	if !isOkResponseIMAP(greeting) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("IMAP greeting failed, response: %s", greeting))

		return
	}

	if username == "" || password == "" {
		return
	}

	fmt.Fprintf(conn, "a1 LOGIN %s %s\r\n", username, password)

	response, err := tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading IMAP response, error: %v", err))

		return
	}

	if !isOkResponseIMAP(response) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("IMAP login failed, response: %s", response))
	}
}

// isOkResponseIMAP checks if the given IMAP server response starts with "* OK" or "a1 OK".
func isOkResponseIMAP(response string) bool {
	return bytes.HasPrefix([]byte(response), []byte("* OK")) || bytes.HasPrefix([]byte(response), []byte("a1 OK"))
}

// checkHTTP performs an HTTP GET request with Basic Authentication using a given username and password.
// It encodes the credentials, sends the request over a provided connection, and checks the response for success.
// Errors related to request sending or response handling are logged and returned.
func checkHTTP(conn net.Conn, hostname, requestURI, username, password string) error {
	authHeader := ""

	if username != "" && password != "" {
		auth := username + ":" + password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		authHeader = "Authorization: Basic " + encoded + "\r\n"
	}

	if requestURI == "" {
		requestURI = "/"
	}

	_, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: Nauthilus\r\nAccept: */*\r\n\r\n", requestURI, hostname, authHeader)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error sending HTTP request, error: %v", err))

		return err
	}

	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	statusLine, err := tp.ReadLine()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading HTTP status line, error: %v", err))

		return err
	}

	if !isOkResponseHTTP(statusLine) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("HTTP request failed, response: %s", statusLine))

		return fmt.Errorf("HTTP request failed: %s", statusLine)
	}

	_, err = tp.ReadMIMEHeader()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Error reading HTTP headers, error: %v", err))

		return err
	}

	return nil
}

// isOkResponseHTTP checks if the given HTTP response starts with "HTTP/1.1 200", indicating a successful response.
func isOkResponseHTTP(response string) bool {
	return response[:12] == "HTTP/1.1 200"
}

// checkHAproxyV2 sends a HAProxy protocol v2 header to the given connection with specified Host address and port.
// It returns an error if writing the header to the connection fails. The error is also logged for diagnostics.
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

// handleHAproxyV2Error logs an error related to HAProxy version 2 operations using the global Logger.
func handleHAproxyV2Error(err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyInstance, definitions.InstanceName,
		definitions.LogKeyMsg, "HAProxy v2 error", "error", err,
	)
}
