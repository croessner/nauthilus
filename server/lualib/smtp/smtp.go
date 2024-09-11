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
	"net"
	"net/smtp"
)

// runSendSMTPMail sends an email using the SMTP protocol. It establishes a connection with the SMTP server,
// authenticates if provided, and sends the email content. It supports both plain and secure connections,
// with optional TLS encryption and StartTLS support.
//
// Parameters:
// - smtpServer: The SMTP server address and port in the format "host:port".
// - heloName: The domain name used in the SMTP HELO/EHLO command.
// - auth: The authentication credentials for the SMTP server. Use `nil` for no authentication.
// - from: The email address of the sender.
// - to: A slice of email addresses of the recipients.
// - msg: The byte array of the email content.
// - useTLS: A boolean indicating whether to use a secure TLS connection.
// - useStartTLS: A boolean indicating whether to use the STARTTLS extension for upgrading the connection to TLS.
//
// Returns:
// - An error if any occurs during the email sending process, or `nil` if the email is sent successfully.
func runSendSMTPMail(smtpServer string, heloName string, auth smtp.Auth, from string, to []string, msg []byte, useTLS bool, useStartTLS bool) error {
	var (
		genericClient GenericClient
		tlsConfig     *tls.Config
		conn          net.Conn
		err           error
	)

	if useTLS {
		host, _, _ := net.SplitHostPort(smtpServer)
		tlsConfig = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
	}

	// Initialize plain connection
	if !useTLS || useStartTLS {
		genericClient, err = smtp.Dial(smtpServer)
		if err != nil {
			return err
		}

		if err = genericClient.Hello(heloName); err != nil {
			return err
		}

		if useStartTLS {
			// Do SMTP/STARTTLS
			if err = genericClient.StartTLS(tlsConfig); err != nil {
				return err
			}
		}
	}

	// Initialize secure connection
	if useTLS && !useStartTLS {
		// Initialize secure connection for SMTP-only
		conn, err = tls.Dial("tcp", smtpServer, tlsConfig)
		if err != nil {
			return err
		}

		genericClient, err = smtp.NewClient(conn, smtpServer)
		if err != nil {
			return err
		}
	}

	if err = genericClient.Hello(heloName); err != nil {
		return err
	}

	defer genericClient.Quit()
	defer genericClient.Close()

	if auth != nil {
		if err = genericClient.Auth(auth); err != nil {
			return err
		}
	}

	return sendEmailContent(genericClient, from, to, msg)
}
