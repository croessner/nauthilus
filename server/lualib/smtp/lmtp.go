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

package smtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
)

// LMTPClient is a client for communicating with LMTP (Local Mail Transfer Protocol) servers.
// It uses an internal SMTP client and a text protocol connection to handle LMTP-specific operations.
type LMTPClient struct {
	// internalClient represents the underlying SMTP client used to handle the communication protocol for LMTP operations.
	internalClient *smtp.Client

	// text is a field of type *textproto.Conn that represents the underlying text protocol connection for the client.
	text *textproto.Conn
}

var _ GenericClient = (*LMTPClient)(nil)

// NewLMTPClient initializes a new LMTPClient using the provided network connection and returns it or an error if failed.
func NewLMTPClient(conn net.Conn) (*LMTPClient, error) {
	textConn := textproto.NewConn(conn)
	internalClient, err := smtp.NewClient(conn, "")
	if err != nil {
		if textConn != nil {
			textConn.Close()
		}

		return nil, err
	}

	return &LMTPClient{internalClient: internalClient, text: textConn}, nil
}

// cmd sends a command to the LMTP server, expects a specific response code, and returns an error if the operation fails.
func (l *LMTPClient) cmd(expCode int, cmd string) error {
	id, err := l.text.Cmd("%s", cmd)
	if err != nil {
		return err
	}

	l.text.StartResponse(id)

	defer l.text.EndResponse(id)

	code, _, err := l.text.ReadResponse(expCode)
	if err != nil || code != expCode {
		return fmt.Errorf("failed cmd '%s': %v", cmd, err)
	}

	return nil
}

// Close terminates the connection to the LMTP server and releases associated resources.
// Returns an error if the underlying SMTP client's Close method fails.
func (l *LMTPClient) Close() error {
	return l.internalClient.Close()
}

// Hello sends the LHLO command to the LMTP server with the specified local hostname and expects a 250 response code.
// Returns an error if the command fails or if the server response is invalid.
func (l *LMTPClient) Hello(localName string) error {
	err := l.cmd(250, fmt.Sprintf("LHLO %s", localName))
	if err != nil {
		return err
	}

	return nil
}

// StartTLS initiates a TLS-secured connection to the LMTP server using the provided TLS configuration.
// Returns an error if the operation fails or if TLS is already active.
func (l *LMTPClient) StartTLS(_ *tls.Config) error {
	return nil
}

// Auth attempts to authenticate the client using the provided SMTP Auth mechanism.
// Returns an error if the authentication process fails or is not supported.
func (l *LMTPClient) Auth(_ smtp.Auth) error {
	return nil
}

// Mail sends the MAIL FROM command with the specified sender's email address to the LMTP server.
// Returns an error if the command fails or if the response code is not 250.
func (l *LMTPClient) Mail(from string) error {
	err := l.cmd(250, fmt.Sprintf("MAIL FROM:<%s>", from))
	if err != nil {
		return err
	}

	return err
}

// Rcpt sends the RCPT TO command with the specified recipient's email address to the LMTP server. Returns an error if it fails.
func (l *LMTPClient) Rcpt(to string) error {
	return l.internalClient.Rcpt(to)
}

// Data initiates the DATA command on the LMTP server and returns a writer for the message body or an error.
func (l *LMTPClient) Data() (io.WriteCloser, error) {
	return l.internalClient.Data()
}

// Quit sends the QUIT command to terminate the LMTP session, closes the text protocol connection, and returns any error.
func (l *LMTPClient) Quit() error {
	err := l.cmd(221, "QUIT")
	if err != nil {
		return err
	}

	l.text.Close()

	return err
}

// runSendLMTPMail connects to an LMTP server, sends the email using provided parameters, and handles TLS if enabled.
// Returns an error if connection, authentication, or message transmission fails.
func runSendLMTPMail(lmtpServer string, heloName string, _ smtp.Auth, from string, to []string, msg []byte, useTLS bool, _ bool) error {
	var (
		genericClient GenericClient
		tlsConfig     *tls.Config
		conn          net.Conn
		err           error
	)

	if useTLS {
		host, _, _ := net.SplitHostPort(lmtpServer)
		tlsConfig = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}

		conn, err = tls.Dial("tcp", lmtpServer, tlsConfig)
		if err != nil {
			return err
		}
	} else {
		conn, err = net.Dial("tcp", lmtpServer)
		if err != nil {
			return err
		}
	}

	genericClient, err = NewLMTPClient(conn)
	if err != nil {
		return err
	}

	defer genericClient.Quit()
	defer genericClient.Close()

	if err = genericClient.Hello(heloName); err != nil {
		return err
	}

	return sendEmailContent(genericClient, from, to, msg)
}
