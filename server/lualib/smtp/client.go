package smtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
)

// SendMail sends an email using the given SMTP server, authentication credentials, sender and recipients, subject,
// body, TLS encryption option, and StartTLS option. It returns an error if any occurs during sending the email.
// If TLS encryption is enabled, it uses the sendMailUsingTLS function to establish a TLS connection and send the email.
// Otherwise, it uses the smtp.SendMail function to send the email without encryption.
func SendMail(smtpServer string, smtpPort int, username, password, from string, to []string, subject, body string, tls bool, startTLS bool) error {
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

	if tls {
		err = sendMailUsingTLS(smtpServer+fmt.Sprintf(":%d", smtpPort), auth, from, to, msg, startTLS)
	} else {
		err = smtp.SendMail(smtpServer+fmt.Sprintf(":%d", smtpPort), auth, from, to, msg)
	}

	return err
}

// sendMailUsingTLS establishes a TLS connection with the given SMTP server using the provided authentication,
// sender and recipients, and sends the email message. If the StartTLS option is enabled, it uses smtp.Dial
// and smtp.Client.StartTLS to establish the connection. Otherwise, it uses tls.Dial and smtp.NewClient.
// It returns an error if any occurs during the sending process.
func sendMailUsingTLS(smtpServer string, auth smtp.Auth, from string, to []string, msg []byte, startTLS bool) error {
	var (
		smtpClient *smtp.Client
		conn       net.Conn
		wc         io.WriteCloser
		err        error
	)

	host, _, _ := net.SplitHostPort(smtpServer)
	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	if startTLS {
		smtpClient, err = smtp.Dial(smtpServer)
		if err != nil {
			return err
		}

		if err = smtpClient.StartTLS(tlsConfig); err != nil {

			return err
		}
	} else {
		conn, err = tls.Dial("tcp", smtpServer, tlsConfig)
		if err != nil {
			return err
		}

		smtpClient, err = smtp.NewClient(conn, smtpServer)
		if err != nil {
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
