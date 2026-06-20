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

// Package smtp provides smtp functionality.
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
	if options.HeloName == "" {
		options.HeloName = smtpDefaultHeloName
	}

	fromAddress, toAddresses, err := parseMailAddresses(options)
	if err != nil {
		return err
	}

	buf, err := buildMailMessage(options, fromAddress)
	if err != nil {
		return err
	}

	auth := smtpAuth(options)
	smtpServer := options.Server + fmt.Sprintf(":%d", options.Port)

	return sendMail(smtpServer, options.HeloName, auth, fromAddress.Address, toAddresses, buf.Bytes(), options.TLS, options.StartTLS)
}

// parseMailAddresses parses sender and recipient addresses.
func parseMailAddresses(options *MailOptions) (*mail.Address, []string, error) {
	fromAddress, err := mail.ParseAddress(options.From)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid From address: %v", err)
	}

	toAddresses := make([]string, 0, len(options.To))
	for _, toAddressWithCN := range options.To {
		toAddress, err := mail.ParseAddress(toAddressWithCN)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid To address: %v", err)
		}

		toAddresses = append(toAddresses, toAddress.Address)
	}

	return fromAddress, toAddresses, nil
}

// buildMailMessage renders headers and body into a message buffer.
func buildMailMessage(options *MailOptions, fromAddress *mail.Address) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	msg := gomail.NewMessage()

	msg.SetHeader("Date", msg.FormatDate(time.Now()))
	msg.SetHeader("Message-ID", strconv.FormatInt(time.Now().UnixNano(), 10)+"@"+messageIDDomain(fromAddress))
	msg.SetHeader("From", options.From)
	msg.SetHeader("To", options.To...)
	msg.SetHeader("Subject", options.Subject)
	msg.SetBody("text/plain", options.Body)

	if _, err := msg.WriteTo(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// messageIDDomain returns the domain part used for generated Message-ID values.
func messageIDDomain(fromAddress *mail.Address) string {
	if parts := strings.Split(fromAddress.Address, "@"); len(parts) > 1 {
		return parts[1]
	}

	return "localhost"
}

// smtpAuth returns SMTP auth when credentials apply to an SMTP send.
func smtpAuth(options *MailOptions) smtp.Auth {
	if options.LMTP || options.Username == "" || options.Password == "" {
		return nil
	}

	server := options.Server
	if options.TLS && !options.StartTLS && options.Port == 465 {
		server = fmt.Sprintf("%s:%d", options.Server, options.Port)
	}

	return smtp.PlainAuth("", options.Username, options.Password, server)
}
