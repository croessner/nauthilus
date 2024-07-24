package smtp

import (
	"bytes"
	"fmt"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/gomail.v2"
)

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

// SendMail utilizes the EmailClient struct to invoke the SendMail method from the smtp package.
// This method will return an error if an attempting to send email with nil options.
// Otherwise, it will pass the non-nil options to smtp.SendMail method and return its result.
//
// Parameters:
// - options: The MailOptions pointer containing the email sending configuration.
//
// Returns:
// - An error if options is nil.
// - Otherwise, it returns the result of executing the SendMail method from the smtp package.
//
// This method is used to send emails using the EmailClient struct and the SendMail method from the smtp package.
func (s *EmailClient) SendMail(options *MailOptions) error {
	if options == nil {
		return fmt.Errorf("options is nil")
	}

	if options.LMTP {
		return SendMail(options, runSendLMTPMail)
	}

	return SendMail(options, runSendSMTPMail)
}

// SendMail sends an email using the given SMTP server, authentication credentials, sender and recipients, subject,
// body, TLS encryption option, and StartTLS option. It returns an error if any occurs during sending the email.
// If TLS encryption is enabled, it uses the runSendSMTPMail function to establish a TLS connection and send the email.
// Otherwise, it uses the smtp.SendMail function to send the email without encryption.
func SendMail(options *MailOptions, sendMail InternalSendMailFunc) error {
	var (
		fromAddress *mail.Address
		buf         bytes.Buffer
		auth        smtp.Auth
		err         error
	)

	toAddresses := make([]string, 0)

	if !options.LMTP {
		if options.Username != "" && options.Password != "" {
			server := options.Server
			if options.TLS && !options.StartTLS && options.Port == 465 {
				server = fmt.Sprintf("%s:%d", options.Server, options.Port)
			}

			// Set up authentication information.
			auth = smtp.PlainAuth("", options.Username, options.Password, server)
		}
	}

	if options.HeloName == "" {
		options.HeloName = "localhost"
	}

	if fromAddress, err = mail.ParseAddress(options.From); err != nil {
		return fmt.Errorf("invalid From address: %v", err)
	}

	for _, toAddressWithCN := range options.To {
		var toAddress *mail.Address

		if toAddress, err = mail.ParseAddress(toAddressWithCN); err != nil {
			return fmt.Errorf("invalid To address: %v", err)
		}

		toAddresses = append(toAddresses, toAddress.Address)
	}

	msgIDDomain := "localhost"
	if parts := strings.Split(fromAddress.Address, "@"); len(parts) > 1 {
		msgIDDomain = parts[1]
	}

	msg := gomail.NewMessage()

	msg.SetHeader("Date", msg.FormatDate(time.Now()))
	msg.SetHeader("Message-ID", strconv.FormatInt(time.Now().UnixNano(), 10)+"@"+msgIDDomain)
	msg.SetHeader("From", options.From)
	msg.SetHeader("To", options.To...)
	msg.SetHeader("Subject", options.Subject)
	msg.SetBody("text/plain", options.Body)

	_, err = msg.WriteTo(&buf)
	if err != nil {
		return err
	}

	err = sendMail(options.Server+fmt.Sprintf(":%d", options.Port), options.HeloName, auth, fromAddress.Address, toAddresses, buf.Bytes(), options.TLS, options.StartTLS)

	return err
}
