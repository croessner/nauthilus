package smtp

import (
	"crypto/tls"
	"io"
	"net/smtp"
)

// GenericClient is an interface that defines the methods required for sending emails using an SMTP or LMTP server.
// It provides methods for establishing a connection, authenticating, setting the sender and recipients,
// writing the email content, and closing the connection.
type GenericClient interface {
	Close() error
	Hello(localName string) error
	StartTLS(config *tls.Config) error
	Auth(auth smtp.Auth) error
	Mail(from string) error
	Rcpt(to string) error
	Data() (io.WriteCloser, error)
	Quit() error
}

// MailOptions represents the options for sending an email.
// It includes the SMTP server address, port number, HELO name, username, password,
// sender email address, recipient email addresses, subject, body, and TLS/StartTLS options.
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

	// LMTP is a field in the MailOptions struct that specifies whether to use
	// the LMTP (Local Mail Transfer Protocol) protocol for sending an email.
	// If set to true, the email will be sent using LMTP. If set to false, the
	// email will be sent using the SMTP (Simple Mail Transfer Protocol) protocol.
	LMTP bool
}

// SendMailFunc is a function type that can be used to send an email using the provided MailOptions.
// It takes the mail options as a parameter and returns an error if the email sending fails.
type SendMailFunc func(options *MailOptions) error

// Client is an interface for sending email using the SMTP protocol.
type Client interface {
	// SendMail sends an email using the provided Client implementation.
	SendMail(options *MailOptions) error
}

// EmailClient is a struct representing a real SMTP client.
type EmailClient struct{}

// InternalSendMailFunc is a function type that represents the signature of a function
// used for sending emails using SMTP or LMTP server.
//
// Parameters:
// - smtpServer: The address of the SMTP server.
// - heloName: The name used in the HELO/EHLO command.
// - auth: The authentication credentials.
// - from: The email address of the sender.
// - to: A slice of email addresses of the recipients.
// - msg: The email message content as a byte array.
// - useTLS: Specifies whether to use TLS encryption for the connection.
// - useStartTLS: Specifies whether to use STARTTLS to enable TLS encryption for the connection.
//
// Returns:
// - An error if any occurs during sending the email, otherwise nil.
type InternalSendMailFunc func(smtpServer string, heloName string, auth smtp.Auth, from string, to []string, msg []byte, useTLS bool, useStartTLS bool) error
