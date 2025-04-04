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
	"io"
	"net/smtp"
)

// GenericClient represents a client interface for sending email messages via SMTP or LMTP protocols.
type GenericClient interface {
	// Close closes the connection and releases any associated resources. Returns an error if the operation fails.
	Close() error

	// Hello sends the HELO/EHLO command with the specified local hostname to the server. Returns an error if the command fails.
	Hello(localName string) error

	// StartTLS upgrades the current connection to a secure TLS connection using the provided TLS configuration. Returns an error if it fails.
	StartTLS(config *tls.Config) error

	// Auth authenticates the client using the provided SMTP Auth mechanism. Returns an error if authentication fails.
	Auth(auth smtp.Auth) error

	// Mail sends the MAIL FROM command to specify the sender's email address. Returns an error if the command fails or is rejected.
	Mail(from string) error

	// Rcpt sends the RCPT TO command to specify a recipient for the email. Returns an error if the command fails or is rejected.
	Rcpt(to string) error

	// Data initiates the DATA command, returning a writer for the email content and an error if the operation fails.
	Data() (io.WriteCloser, error)

	// Quit sends the QUIT command to terminate the session and cleanly close the connection. Returns an error if it fails.
	Quit() error
}

// MailOptions represents configuration options for sending an email, including server settings, credentials, and email content.
type MailOptions struct {
	// Server represents the SMTP server address for sending an email.
	Server string

	// Port represents the port number of the SMTP server.
	Port int

	// HeloName represents the name used in the SMTP HELO/EHLO command. It is a string field in the MailOptions struct.
	HeloName string

	// Username represents the username used for authentication when sending an email using an SMTP server.
	Username string

	// Password represents a field in the MailOptions struct.
	// It is a string type and is used for providing the password for authentication
	// when sending an email using an SMTP server.
	Password string

	// From represents the email address of the sender. It is a field in the MailOptions struct.
	From string

	// To is a field of type []string in the MailOptions struct. It represents the email addresses of the recipients.
	To []string

	// Subject is a field in the MailOptions struct that represents the subject of the email. It is a string type.
	Subject string

	// Body represents the body of an email in the MailOptions struct.
	// It contains the content of the email message to be sent.
	Body string

	// TLS is a boolean field in the MailOptions struct that indicates whether to use TLS encryption for the connection.
	TLS bool

	// StartTLS is a boolean field in the MailOptions struct that indicates whether to use STARTTLS to enable TLS encryption for the connection.
	StartTLS bool

	// LMTP indicates whether to use the Local Mail Transfer Protocol (LMTP) instead of SMTP for sending emails.
	LMTP bool
}

// SendMailFunc defines a function type for sending emails using the provided MailOptions configuration.
type SendMailFunc func(options *MailOptions) error

// Client is an interface for sending email using the SMTP protocol.
type Client interface {
	// SendMail sends an email using the provided Client implementation.
	SendMail(options *MailOptions) error
}

// EmailClient is a struct representing a real SMTP client.
type EmailClient struct{}

// InternalSendMailFunc defines a function type to send emails using SMTP or LMTP with optional authentication and TLS settings.
type InternalSendMailFunc func(smtpServer string, heloName string, auth smtp.Auth, from string, to []string, msg []byte, useTLS bool, useStartTLS bool) error
