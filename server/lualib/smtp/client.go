package smtp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"gopkg.in/gomail.v2"
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

// LMTPClient is a struct that represents a client for sending emails using the LMTP protocol.
//
// It contains an internalClient of type *smtp.Client and a text of type *textproto.Conn.
type LMTPClient struct {
	internalClient *smtp.Client
	text           *textproto.Conn
}

// NewLMTPClient creates a new instance of LMTPClient with the provided connection.
// Parameters:
// - conn: The net.Conn used for the LMTP connection.
// Returns:
// - A pointer to a new LMTPClient instance.
// - An error if an error occurs during the creation process.
func NewLMTPClient(conn net.Conn) (*LMTPClient, error) {
	textConn := textproto.NewConn(conn)
	internalClient, err := smtp.NewClient(conn, "")
	if err != nil {
		return nil, err
	}

	return &LMTPClient{internalClient: internalClient, text: textConn}, nil
}

// cmd sends a command to the LMTP server and checks the response code.
//
// Parameters:
// - code: The expected return code from the server.
// - cmd: The command to send to the LMTP server.
//
// Returns:
//   - An error if an error occurs during the execution of the command or if the response code is not 250.
//     The error message includes the failed command and any error returned by the server.
//
// This method is used internally by other methods in the LMTPClient struct to send commands to the LMTP server.
func (l *LMTPClient) cmd(expCode int, cmd string) error {
	id, err := l.text.Cmd(cmd)
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

// Close closes the LMTP client connection.
//
// Returns:
// - An error if an error occurs during the closing of the client connection.
//
// This method is used to close the client connection and should be called
// after the client finishes sending emails.
func (l *LMTPClient) Close() error {
	return l.internalClient.Close()
}

// Hello sends the LHLO command to the LMTP server.
//
// Parameters:
// - localName: The local name to use in the LHLO command.
//
// Returns:
// - An error if an error occurs during the execution of the LHLO command.
func (l *LMTPClient) Hello(localName string) error {
	err := l.cmd(250, fmt.Sprintf("LHLO %s", localName))
	if err != nil {
		return err
	}

	return nil
}

// StartTLS is a method on LMTPClient which is mentioned to implement the notion of starting a TLS connection.
// However, in this implementation, it does not initialize a secure connection. It is a simple no-operation function (nop)
// that returns nil irrespective of the input.
func (l *LMTPClient) StartTLS(_ *tls.Config) error {
	return nil
}

// Auth is a method on LMTPClient which is mentioned to handle authentication.
// However, in this implementation, it does not perform any authentication. It is a simple no-operation function (nop)
// that returns nil irrespective of the input.
func (l *LMTPClient) Auth(_ smtp.Auth) error {
	return nil
}

// Mail sends the MAIL FROM command to the LMTP server with the specified "from" address.
//
// Parameters:
// - from: The email address to use in the MAIL FROM command.
//
// Returns:
//   - An error if an error occurs during the execution of the command or if the response code is not 250.
//     The error message includes the failed command and any error returned by the server.
//
// This method is used internally by other methods in the LMTPClient struct for sending emails.
func (l *LMTPClient) Mail(from string) error {
	err := l.cmd(250, fmt.Sprintf("MAIL FROM:<%s>", from))
	if err != nil {
		return err
	}

	return err
}

// Rcpt sends the RCPT TO command with the specified "to" address to the LMTP server.
//
// Parameters:
// - to: The email address to use in the RCPT TO command.
//
// Returns:
//   - An error if an error occurs during the execution of the command or if the response code is not 250.
//     The error message includes the failed command and any error returned by the server.
//
// This method is used internally by other methods in the LMTPClient struct for sending emails.
func (l *LMTPClient) Rcpt(to string) error {
	return l.internalClient.Rcpt(to)
}

// Data returns an io.WriteCloser that can be used to write the email message content,
// and an error if an error occurs during the execution of the command or obtaining the WriteCloser.
//
// This method is used internally by other methods in the LMTPClient struct for sending emails.
func (l *LMTPClient) Data() (io.WriteCloser, error) {
	return l.internalClient.Data()
}

// Quit sends the QUIT command to the LMTP server.
//
// Returns:
// - An error if an error occurs during the execution of the command.
//
// This method is used to gracefully terminate the LMTP client connection with the server.
func (l *LMTPClient) Quit() error {
	err := l.cmd(221, "QUIT")
	if err != nil {
		return err
	}

	l.text.Close()

	return err
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

// NewMailOptions creates a new instance of MailOptions with the provided parameters.
//
// Parameters:
// - server: The SMTP server address.
// - port: The port number of the SMTP server.
// - heloName: The name used in the SMTP HELO/EHLO command.
// - username: The username for authentication (optional).
// - password: The password for authentication (optional).
// - from: The email address of the sender.
// - to: A slice of email addresses of the recipients.
// - subject: The subject of the email.
// - body: The body of the email.
// - useTLS: Whether to use TLS encryption for the connection.
// - useStartTLS: Whether to use STARTTLS to enable TLS encryption for the connection.
// - useLMTP: Wether to use LMTP or SMTP for the communication.
//
// Returns:
// - A pointer to a new MailOptions instance.
func NewMailOptions(server string, port int, heloName string, username string, password string, from string, to []string,
	subject string, body string, useTLS bool, useStartTLS bool, useLMTP bool) *MailOptions {
	return &MailOptions{
		Server:   server,
		Port:     port,
		HeloName: heloName,
		Username: username,
		Password: password,
		From:     from,
		To:       to,
		Subject:  subject,
		Body:     body,
		TLS:      useTLS,
		StartTLS: useStartTLS,
		LMTP:     useLMTP,
	}
}

// SendMailFunc is a function type that can be used to send an email using the provided MailOptions.
// It takes the mail options as a parameter and returns an error if the email sending fails.
type SendMailFunc func(options *MailOptions) error

// Client is an interface for sending email using the SMTP protocol.
type Client interface {
	// SendMail sends an email using the provided Client implementation.
	SendMail(options *MailOptions) error
}

// SendMail sends an email using the given SMTP server, authentication credentials, sender and recipients, subject,
// body, TLS encryption option, and StartTLS option. It returns an error if any occurs during sending the email.
// If TLS encryption is enabled, it uses the sendMail function to establish a TLS connection and send the email.
// Otherwise, it uses the smtp.SendMail function to send the email without encryption.
func SendMail(options *MailOptions) error {
	var (
		buf  bytes.Buffer
		auth smtp.Auth
		err  error
	)

	if options.Username != "" && options.Password != "" {
		server := options.Server
		if options.TLS && !options.StartTLS && options.Port == 465 {
			server = fmt.Sprintf("%s:%d", options.Server, options.Port)
		}

		// Set up authentication information.
		auth = smtp.PlainAuth("", options.Username, options.Password, server)
	}

	if options.HeloName == "" {
		options.HeloName = "localhost"
	}

	msgIDDomain := "localhost"
	if options.From != "" {
		address, err := mail.ParseAddress(options.From)
		if err != nil {
			return fmt.Errorf("invalid From address: %v", err)
		}

		parts := strings.Split(address.Address, "@")
		if len(parts) > 1 {
			msgIDDomain = parts[1]
		} else {
			return fmt.Errorf("invalid From address: missing domain")
		}
	}

	msg := gomail.NewMessage()

	msg.SetHeader("Date", msg.FormatDate(time.Now()))
	msg.SetHeader("Message-ID", strconv.FormatInt(time.Now().UnixNano(), 10)+"@"+msgIDDomain)
	msg.SetHeader("From", options.From)
	msg.SetHeader("To", options.To...)
	msg.SetHeader("Subject", options.Subject)
	msg.SetBody("text/plain; charset=UTF-8", options.Body)

	_, err = msg.WriteTo(&buf)
	if err != nil {
		return err
	}

	err = sendMail(options.Server+fmt.Sprintf(":%d", options.Port), options.HeloName, auth, options.From, options.To, buf.Bytes(), options.TLS, options.StartTLS, options.LMTP)

	return err
}

// sendMail establishes a TLS connection on behalf with the given SMTP server using the provided authentication,
// sender and recipients, and sends the email message. If the StartTLS option is enabled, it uses smtp.Dial
// and smtp.Client.StartTLS to establish the connection. Otherwise, it uses tls.Dial and smtp.NewClient.
// It returns an error if any occurs during the sending process.
func sendMail(smtpServer string, heloName string, auth smtp.Auth, from string, to []string, msg []byte, useTLS bool, useStartTLS bool, useLMTP bool) error {
	var (
		genericClient GenericClient
		tlsConfig     *tls.Config
		conn          net.Conn
		wc            io.WriteCloser
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
		if !useLMTP {
			genericClient, err = smtp.Dial(smtpServer)
			if err != nil {
				return err
			}
		} else {
			conn, err = net.Dial("tcp", smtpServer)
			if err != nil {
				return err
			}

			genericClient, err = NewLMTPClient(conn)
			if err != nil {
				return err
			}
		}

		if err = genericClient.Hello(heloName); err != nil {
			return err
		}
	}

	if useStartTLS && !useLMTP {
		// Do SMTP/STARTTLS
		if err = genericClient.StartTLS(tlsConfig); err != nil {
			return err
		}
	} else {
		if useTLS {
			// Initialize secure connection for SMTP-only
			conn, err = tls.Dial("tcp", smtpServer, tlsConfig)
			if err != nil {
				return err
			}

			if !useLMTP {
				genericClient, err = smtp.NewClient(conn, smtpServer)
				if err != nil {
					return err
				}
			} else {
				genericClient, err = NewLMTPClient(conn)
				if err != nil {
					return err
				}
			}
		}

		if err = genericClient.Hello(heloName); err != nil {
			return err
		}

	}

	defer genericClient.Quit()
	defer genericClient.Close()

	if !useLMTP && auth != nil {
		if err = genericClient.Auth(auth); err != nil {
			return err
		}
	}

	if err = genericClient.Mail(from); err != nil {
		return err
	}

	for _, addr := range to {
		if err = genericClient.Rcpt(addr); err != nil {
			return err
		}
	}

	wc, err = genericClient.Data()
	if err != nil {
		return err
	}

	_, err = wc.Write(msg)
	if err != nil {
		return err
	}

	err = wc.Close()
	if err != nil {
		return err
	}

	err = genericClient.Quit()
	if err != nil {
		return err
	}

	return nil
}
