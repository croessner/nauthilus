package smtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
)

// SMTPClient is an interface for sending email using SMTP protocol.
type SMTPClient interface {
	// SendMail sends an email using the provided SMTPClient implementation.
	//
	// Parameters:
	// - server: The address of the SMTP server.
	// - port: The port number of the SMTP server.
	// - heloName: The HELO/EHLO hostname in the SMTP session
	// - username: The username to authenticate with the SMTP server.
	// - password: The password to authenticate with the SMTP server.
	// - from: The email address of the sender.
	// - to: A list of email addresses of the recipients.
	// - subject: The subject of the email.
	// - body: The body of the email.
	// - tls: Specifies whether to use TLS for the SMTP connection.
	// - startTLS: Specifies whether to use STARTTLS for the SMTP connection.
	//
	// Returns:
	// - An error if sending the email fails, otherwise nil.
	//
	// Example usage:
	// ```
	// smtpClient := &lualib.RealSMTP{}
	// err := SendMail(smtpClient, "smtp.example.com", 587, "mua.example.com",  "user@example.com", "password",
	//     "sender@example.com", []string{"recipient@example.com"}, "Hello, World!",
	//     "This is the body of the email.", true, true)
	// if err != nil {
	//     fmt.Println("Failed to send email:", err)
	// }
	// ```
	SendMail(server string, port int, heloName string, username string, password string,
		from string, to []string, subject string, body string, tls bool, startTLS bool) error
}

// SendMail sends an email using the given SMTP server, authentication credentials, sender and recipients, subject,
// body, TLS encryption option, and StartTLS option. It returns an error if any occurs during sending the email.
// If TLS encryption is enabled, it uses the sendMail function to establish a TLS connection and send the email.
// Otherwise, it uses the smtp.SendMail function to send the email without encryption.
func SendMail(smtpServer string, smtpPort int, heloName string, username, password, from string, to []string, subject, body string, useTLS bool, useStartTLS bool) error {
	var (
		auth smtp.Auth
		err  error
	)

	if username != "" && password != "" {
		// Set up authentication information.
		auth = smtp.PlainAuth("", username, password, smtpServer)
	}

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	toConcatenated := strings.Join(to, ",")
	msg := []byte("To: " + toConcatenated + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	if heloName == "" {
		heloName = "localhost"
	}

	err = sendMail(smtpServer+fmt.Sprintf(":%d", smtpPort), heloName, auth, from, to, msg, useTLS, useStartTLS)

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
