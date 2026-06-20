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
	genericClient, err := newSMTPGenericClient(smtpServer, heloName, useTLS, useStartTLS)
	if err != nil {
		return err
	}

	defer closeSMTPClient(genericClient)

	if err := genericClient.Hello(heloName); err != nil {
		return err
	}

	if auth != nil {
		if err := genericClient.Auth(auth); err != nil {
			return err
		}
	}

	return sendEmailContent(genericClient, from, to, msg)
}

// newSMTPGenericClient creates a plain, STARTTLS, or direct TLS SMTP client.
func newSMTPGenericClient(smtpServer string, heloName string, useTLS bool, useStartTLS bool) (GenericClient, error) {
	tlsConfig := smtpTLSConfig(smtpServer, useTLS)
	if !useTLS || useStartTLS {
		return newPlainOrStartTLSClient(smtpServer, heloName, tlsConfig, useStartTLS)
	}

	return newDirectTLSClient(smtpServer, tlsConfig)
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

// newPlainOrStartTLSClient creates a plain SMTP client and optionally upgrades it.
func newPlainOrStartTLSClient(smtpServer string, heloName string, tlsConfig *tls.Config, useStartTLS bool) (GenericClient, error) {
	genericClient, err := smtp.Dial(smtpServer)
	if err != nil {
		return nil, err
	}

	if err := genericClient.Hello(heloName); err != nil {
		closeSMTPClient(genericClient)

		return nil, err
	}

	if useStartTLS {
		if err := genericClient.StartTLS(tlsConfig); err != nil {
			closeSMTPClient(genericClient)

			return nil, err
		}
	}

	return genericClient, nil
}

// newDirectTLSClient creates an SMTP client over an immediate TLS connection.
func newDirectTLSClient(smtpServer string, tlsConfig *tls.Config) (GenericClient, error) {
	conn, err := tls.Dial("tcp", smtpServer, tlsConfig)
	if err != nil {
		return nil, err
	}

	genericClient, err := smtp.NewClient(conn, smtpServer)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	return genericClient, nil
}

// closeSMTPClient closes the SMTP session best-effort.
func closeSMTPClient(genericClient GenericClient) {
	_ = genericClient.Quit()
	_ = genericClient.Close()
}
