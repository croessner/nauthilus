package smtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
)

// LMTPClient is a struct that represents a client for sending emails using the LMTP protocol.
//
// It contains an internalClient of type *smtp.Client and a text of type *textproto.Conn.
type LMTPClient struct {
	// internalClient is a field of type *smtp.Client in the LMTPClient struct.
	// It represents the internal SMTP client used for sending emails using the LMTP protocol.
	internalClient *smtp.Client

	// text represents a field of type *textproto.Conn in the LMTPClient struct.
	// It is used internally by other methods to send commands and read responses from
	// the LMTP server.
	// The *textproto.Conn type is a low-level representation of a text protocol connection.
	// It provides methods for sending and receiving commands and responses over a network connection.
	text *textproto.Conn
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

// runSendLMTPMail sends an email using the LMTP protocol to the specified LMTP server.
//
// Parameters:
// - lmtpServer: The address of the LMTP server.
// - heloName: The name used in the HELO/EHLO command.
// - from: The email address of the sender.
// - to: A slice of email addresses of the recipients.
// - msg: The content of the email as a byte array.
// - useTLS: A boolean value indicating whether to use TLS or not.
//
// Returns:
// - An error if an error occurs during the process.
//
// This function establishes a connection with the LMTP server using the LMTP protocol.
// It creates a new instance of LMTPClient with the connection and sends the LHLO command.
// Then it calls the sendEmailContent function to send the email content.
// Finally, it closes the connection and returns any error encountered during the process.
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

	if err = genericClient.Hello(heloName); err != nil {
		return err
	}

	defer genericClient.Quit()
	defer genericClient.Close()

	return sendEmailContent(genericClient, from, to, msg)
}
