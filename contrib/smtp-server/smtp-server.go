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
	"sync"
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

var _ smtp.Backend = (*Backend)(nil)

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

	saslServer := sasl.NewPlainServer(func(identity, username, password string) error {
		s.auth = true

		log.Printf("AUTH username=<%s>", username)

		return nil
	})

	return saslServer, nil
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

var _ smtp.Session = (*Session)(nil)

type ProxyAndTLSListener struct {
	ProxyListener *proxyproto.Listener
	TLSConfig     *tls.Config
}

func (p *ProxyAndTLSListener) Accept() (net.Conn, error) {
	rawConn, err := p.ProxyListener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}

	tlsConn := tls.Server(rawConn, p.TLSConfig)

	return tlsConn, nil
}

func (p *ProxyAndTLSListener) Close() error {
	return p.ProxyListener.Close()
}

func (p *ProxyAndTLSListener) Addr() net.Addr {
	return p.ProxyListener.Addr()
}

var _ net.Listener = (*ProxyAndTLSListener)(nil)

func NewProxyAndTLSListener(rawListener net.Listener, tlsConfig *tls.Config) net.Listener {
	proxyListener := &proxyproto.Listener{
		Listener: rawListener,
		ConnPolicy: func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}

	return &ProxyAndTLSListener{
		ProxyListener: proxyListener,
		TLSConfig:     tlsConfig,
	}
}

type ServerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

type SMTPType uint

const (
	SMTP SMTPType = iota
	SMTPS
)

type SMTPServer struct {
	serverDescription string
	serverType        SMTPType
	config            *ServerConfig
	server            *smtp.Server
	serverName        string
}

func NewSMTPServer(serverType SMTPType, serverDescription string, address string, backend *Backend) *SMTPServer {
	serverName := os.Getenv("FAKE_SMTP_SERVER_NAME")
	if serverName == "" {
		serverName = "mail.test"
	}

	return &SMTPServer{
		serverDescription: serverDescription,
		serverType:        serverType,
		config: &ServerConfig{
			Address:   address,
			TLSConfig: configureTLS(serverName),
		},
		server:     smtp.NewServer(backend),
		serverName: serverName,
	}
}

func (s *SMTPServer) configureServer() {
	s.server.Domain = s.serverName
	s.server.ReadTimeout = 10 * time.Second
	s.server.WriteTimeout = 10 * time.Second
	s.server.MaxMessageBytes = 1024 * 1024
	s.server.MaxRecipients = 50
	s.server.AllowInsecureAuth = true
	s.server.EnableBINARYMIME = true
	s.server.EnableSMTPUTF8 = true
	s.server.EnableDSN = true
}

func (s *SMTPServer) Start(wg *sync.WaitGroup) {
	var listener net.Listener

	defer wg.Done()

	log.Printf("Starting %s server at %s", s.serverDescription, s.config.Address)

	rawListener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		log.Fatalf("Failed to start %s server: %v", s.serverDescription, err)
	}

	s.configureServer()

	if s.serverType == SMTPS {
		listener = NewProxyAndTLSListener(rawListener, s.config.TLSConfig)
	} else {
		listener = &proxyproto.Listener{
			Listener: rawListener,
			ConnPolicy: func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}

		s.server.TLSConfig = s.config.TLSConfig
	}

	if err := s.server.Serve(listener); err != nil {
		log.Fatalf("%s server stopped unexpectedly: %v", s.serverDescription, err)
	}
}

type ServerManager struct {
	wg    *sync.WaitGroup
	smtp  *SMTPServer
	smtps *SMTPServer
}

func NewServerManager(backend *Backend) *ServerManager {
	imapServer := NewSMTPServer(
		SMTP,
		"SMTP Submission (StartTLS)",
		getEnvWithDefault("FAKE_SMTP_SERVER_ADDRESS", "127.0.0.1:10587"),
		backend,
	)
	imapsServer := NewSMTPServer(
		SMTPS,
		"SMTPS",
		getEnvWithDefault("FAKE_SMTPS_SERVER_ADDRESS", "127.0.0.1:10465"),
		backend,
	)

	return &ServerManager{
		wg:    &sync.WaitGroup{},
		smtp:  imapServer,
		smtps: imapsServer,
	}
}

func (m *ServerManager) StartAll() {
	m.wg.Add(2)

	go m.smtp.Start(m.wg)
	go m.smtps.Start(m.wg)

	m.wg.Wait()
}

func configureTLS(serverName string) *tls.Config {
	tlsCert := os.Getenv("FAKE_SMTP_SERVER_TLSCERT")
	tlsKey := os.Getenv("FAKE_SMTP_SERVER_TLSKEY")

	if tlsCert == "" || tlsKey == "" {
		log.Fatal("TLS certificate and key must be provided for SMTPS")
	}

	tlsCertificate, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCertificate},
		ServerName:   serverName,
	}
}

func getEnvWithDefault(envVar, defaultValue string) string {
	if value := os.Getenv(envVar); value != "" {
		return value
	}

	return defaultValue
}

func main() {
	manager := NewServerManager(&Backend{})

	manager.StartAll()
}
