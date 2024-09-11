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

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/pires/go-proxyproto"
)

const contactSupport = "Please contact your support"

var (
	smtpErr = &smtp.SMTPError{
		Code:         554,
		EnhancedCode: smtp.EnhancedCode{5, 0, 0},
		Message:      contactSupport,
	}
)

// The Backend implements SMTP server methods.
type Backend struct{}

func (bkd *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	log.Println("Connect from", conn.Conn().RemoteAddr().String())

	return &Session{}, nil
}

// A Session is returned after EHLO.
type Session struct {
	auth bool
}

func (s *Session) AuthMechanisms() []string {
	return []string{"PLAIN"}
}

func (s *Session) Auth(mech string) (sasl.Server, error) {
	if mech != "PLAIN" {
		return nil, smtp.ErrAuthUnsupported
	}

	server := sasl.NewPlainServer(func(identity, username, password string) error {
		s.auth = true
		log.Println(fmt.Sprintf("AUTH username=<%s>", username))

		return nil
	})

	return server, nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	log.Println("MAIL FROM:", from, fmt.Sprintf("opts: %v", opts))

	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Println("RCPT TO:", to, fmt.Sprintf("opts: %v", opts))

	return nil
}

func (s *Session) Data(r io.Reader) error {
	_ = r

	time.Sleep(1 * time.Second)

	return smtpErr
}

func (s *Session) Reset() {}

func (s *Session) Logout() error {
	return nil
}

func main() {
	be := &Backend{}

	s := smtp.NewServer(be)

	address := os.Getenv("FAKE_SMTP_SERVER_ADDRESS")
	serverName := os.Getenv("FAKE_SMTP_SERVER_NAME")
	tlsCert := os.Getenv("FAKE_SMTP_SERVER_TLSCERT")
	tlsKey := os.Getenv("FAKE_SMTP_SERVER_TLSKEY")

	if tlsCert != "" && tlsKey != "" {
		cer, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Println(err)

			return
		}

		s.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cer},
		}
	}

	if address == "" {
		address = "127.0.0.1:10025"
	}

	if serverName == "" {
		serverName = "mail.test"
	}

	s.Addr = address
	s.Domain = serverName

	s.ReadTimeout = 10 * time.Second
	s.WriteTimeout = 10 * time.Second

	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50

	s.AllowInsecureAuth = true
	s.EnableBINARYMIME = true
	s.EnableSMTPUTF8 = true
	s.EnableDSN = true

	log.Println("Starting fake server at", s.Addr)

	// Set up listener
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		log.Fatal(err)
	}

	// Wrap listener in proxyproto
	proxyListener := &proxyproto.Listener{Listener: listener}

	// Start server
	if err := s.Serve(proxyListener); err != nil {
		log.Fatal(err)
	}
}
