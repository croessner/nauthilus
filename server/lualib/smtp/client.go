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
	"bytes"
	"fmt"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/gomail.v2"
)

// NewMailOptions creates and returns a new MailOptions instance configured with the provided parameters.
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

// SendMail sends an email based on the provided MailOptions. It supports both LMTP and SMTP protocols.
// Returns an error if MailOptions is nil or sending the email fails.
func (s *EmailClient) SendMail(options *MailOptions) error {
	if options == nil {
		return fmt.Errorf("options is nil")
	}

	if options.LMTP {
		return SendMail(options, runSendLMTPMail)
	}

	return SendMail(options, runSendSMTPMail)
}

// SendMail sends an email using the provided MailOptions and InternalSendMailFunc.
// It supports both SMTP and LMTP protocols, including optional authentication and TLS settings.
// Returns an error if email sending fails or if any input is invalid.
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
