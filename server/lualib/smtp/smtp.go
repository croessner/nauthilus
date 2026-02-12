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

// runSendSMTPMail establishes an SMTP connection and sends an email using provided parameters with optional TLS/StartTLS.
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
		if genericClient != nil {
			defer genericClient.Quit()
			defer genericClient.Close()
		}

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
		if genericClient != nil {
			defer genericClient.Quit()
			defer genericClient.Close()
		}

		if err != nil {
			return err
		}
	}

	if err = genericClient.Hello(heloName); err != nil {
		return err
	}

	if auth != nil {
		if err = genericClient.Auth(auth); err != nil {
			return err
		}
	}

	return sendEmailContent(genericClient, from, to, msg)
}
