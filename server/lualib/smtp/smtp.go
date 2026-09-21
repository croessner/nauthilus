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
	"context"
	"crypto/tls"
	"net"
	"net/smtp"
)

// runSendSMTPMailContext keeps SMTP I/O within the originating operation lifetime.
func runSendSMTPMailContext(ctx context.Context, smtpServer string, heloName string, auth smtp.Auth, from string, to []string, msg []byte, useTLS bool, useStartTLS bool) error {
	genericClient, err := newSMTPGenericClientContext(ctx, smtpServer, heloName, useTLS, useStartTLS)
	if err != nil {
		return err
	}

	defer closeSMTPClient(genericClient)

	if auth != nil {
		if err := genericClient.Auth(auth); err != nil {
			return err
		}
	}

	return sendEmailContent(genericClient, from, to, msg)
}

// newSMTPGenericClientContext configures a bounded verified SMTP connection.
func newSMTPGenericClientContext(ctx context.Context, server, helo string, useTLS, startTLS bool) (GenericClient, error) {
	conn, err := dialMailConnection(ctx, server, useTLS && !startTLS)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(server)

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	if err = client.Hello(helo); err == nil && startTLS {
		err = client.StartTLS(smtpTLSConfig(server, true))
	}

	if err != nil {
		_ = client.Close()

		return nil, err
	}

	return client, nil
}

// smtpTLSConfig returns TLS config when TLS is enabled.
func smtpTLSConfig(smtpServer string, useTLS bool) *tls.Config {
	if !useTLS {
		return nil
	}

	host, _, _ := net.SplitHostPort(smtpServer)

	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
}

// closeSMTPClient closes the SMTP session best-effort.
func closeSMTPClient(genericClient GenericClient) {
	_ = genericClient.Close()
}
