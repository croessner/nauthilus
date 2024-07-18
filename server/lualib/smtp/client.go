package smtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

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
//
// Returns:
// - A pointer to a new MailOptions instance.
func NewMailOptions(server string, port int, heloName string, username string, password string, from string, to []string,
	subject string, body string, useTLS bool, useStartTLS bool) *MailOptions {
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

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	toConcatenated := strings.Join(options.To, ",")
	msg := []byte(
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"Message-ID: <" + strconv.FormatInt(time.Now().UnixNano(), 10) + "@" + msgIDDomain + ">\r\n" +
			"From: " + options.From + "\r\n" +
			"To: " + toConcatenated + "\r\n" +
			"Subject: " + options.Subject + "\r\n" +
			"\r\n" +
			options.Body +
			"\r\n")

	err = sendMail(options.Server+fmt.Sprintf(":%d", options.Port), options.HeloName, auth, options.From, options.To, msg, options.TLS, options.StartTLS)

	return err
}

// sendMail establishes a TLS connection on behalf with the given SMTP server using the provided authentication,
// sender and recipients, and sends the email message. If the StartTLS option is enabled, it uses smtp.Dial
// and smtp.Client.StartTLS to establish the connection. Otherwise, it uses tls.Dial and smtp.NewClient.
// It returns an error if any occurs during the sending process.
func sendMail(smtpServer string, heloName string, auth smtp.Auth, from string, to []string, msg []byte, useTLS bool, useStartTLS bool) error {
	var (
		smtpClient *smtp.Client
		tlsConfig  *tls.Config
		conn       net.Conn
		wc         io.WriteCloser
		err        error
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
		smtpClient, err = smtp.Dial(smtpServer)
		if err != nil {
			return err
		}

		if err = smtpClient.Hello(heloName); err != nil {
			return err
		}
	}

	if useStartTLS {
		// Do STARTTLS
		if err = smtpClient.StartTLS(tlsConfig); err != nil {
			return err
		}
	} else if useTLS {
		// Initialize secure connection
		conn, err = tls.Dial("tcp", smtpServer, tlsConfig)
		if err != nil {
			return err
		}

		smtpClient, err = smtp.NewClient(conn, smtpServer)
		if err != nil {
			return err
		}

		if err = smtpClient.Hello(heloName); err != nil {
			return err
		}
	}

	defer smtpClient.Quit()
	defer smtpClient.Close()

	if auth != nil {
		if err = smtpClient.Auth(auth); err != nil {
			return err
		}
	}

	if err = smtpClient.Mail(from); err != nil {
		return err
	}

	for _, addr := range to {
		if err = smtpClient.Rcpt(addr); err != nil {
			return err
		}
	}

	wc, err = smtpClient.Data()
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

	err = smtpClient.Quit()
	if err != nil {
		return err
	}

	return nil
}
