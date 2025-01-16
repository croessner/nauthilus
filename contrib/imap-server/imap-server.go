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
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/server"
	"github.com/pires/go-proxyproto"
)

const contactSupport = "Please contact your support"

//goland:noinspection ALL
var errContactSupport = errors.New(contactSupport)

type User struct {
	name string
}

func (u *User) Username() string {
	return u.name
}

func (u *User) ListMailboxes(subscribed bool) (mboxes []backend.Mailbox, err error) {
	log.Println("List mailboxes, subscribed:", subscribed)

	return nil, errContactSupport
}

func (u *User) GetMailbox(name string) (mbox backend.Mailbox, err error) {
	log.Println("Get mailbox, name:", name)

	return nil, errContactSupport
}

func (u *User) CreateMailbox(name string) error {
	log.Println("Create mailbox, name:", name)

	return errContactSupport
}

func (u *User) DeleteMailbox(name string) error {
	log.Println("Delete mailbox, name:", name)

	return errContactSupport
}

func (u *User) RenameMailbox(oldname, newname string) error {
	log.Println("Rename mailbox, oldname:", oldname, ", newname:", newname)

	return errContactSupport
}

func (u *User) Logout() error {
	log.Println("Logout")

	return nil
}

type Backend struct{}

func (b *Backend) Login(connInfo *imap.ConnInfo, username string, password string) (user backend.User, err error) {
	_ = password

	log.Println("Connect from", connInfo.RemoteAddr.String(), "username", username)

	user = &User{name: username}

	time.Sleep(1 * time.Second)

	return user, errContactSupport
}

type proxyAndTLSListener struct {
	proxyListener *proxyproto.Listener
	tlsConfig     *tls.Config
}

func (p *proxyAndTLSListener) Accept() (net.Conn, error) {
	rawConn, err := p.proxyListener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}

	tlsConn := tls.Server(rawConn, p.tlsConfig)

	return tlsConn, nil
}

func (p *proxyAndTLSListener) Close() error {
	return p.proxyListener.Close()
}

func (p *proxyAndTLSListener) Addr() net.Addr {
	return p.proxyListener.Addr()
}

func NewProxyAndTLSListener(rawListener net.Listener, tlsConfig *tls.Config) net.Listener {
	proxyListener := &proxyproto.Listener{
		Listener: rawListener,
		ConnPolicy: func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}

	return &proxyAndTLSListener{
		proxyListener: proxyListener,
		tlsConfig:     tlsConfig,
	}
}

type ServerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

type IMAPType uint

const (
	IMAP IMAPType = iota
	IMAPS
)

type IMAPServer struct {
	serverDescription string
	serverType        IMAPType
	config            *ServerConfig
	server            *server.Server
}

func NewIMAPServer(serverType IMAPType, serverDescription string, address string, backend backend.Backend) *IMAPServer {
	return &IMAPServer{
		serverDescription: serverDescription,
		serverType:        serverType,
		config: &ServerConfig{
			Address:   address,
			TLSConfig: configureTLS(),
		},
		server: server.New(backend),
	}
}

func (s *IMAPServer) Start(wg *sync.WaitGroup) {
	var listener net.Listener

	defer wg.Done()

	log.Printf("Starting %s server at %s", s.serverDescription, s.config.Address)

	rawListener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		log.Fatalf("Failed to start %s server: %v", s.serverDescription, err)
	}

	if s.serverType == IMAPS {
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
	imap  *IMAPServer
	imaps *IMAPServer
}

func NewServerManager(backend *Backend) *ServerManager {
	imapServer := NewIMAPServer(
		IMAP,
		"IMAP (StartTLS)",
		getEnvWithDefault("FAKE_IMAP_SERVER_ADDRESS", "127.0.0.1:10143"),
		backend,
	)
	imapsServer := NewIMAPServer(
		IMAPS,
		"IMAPS",
		getEnvWithDefault("FAKE_IMAPS_SERVER_ADDRESS", "127.0.0.1:10993"),
		backend,
	)

	return &ServerManager{
		wg:    &sync.WaitGroup{},
		imap:  imapServer,
		imaps: imapsServer,
	}
}

func (m *ServerManager) StartAll() {
	m.wg.Add(2)

	go m.imap.Start(m.wg)
	go m.imaps.Start(m.wg)

	m.wg.Wait()
}

func configureTLS() *tls.Config {
	serverName := os.Getenv("FAKE_IMAP_SERVER_NAME")
	tlsCert := os.Getenv("FAKE_IMAP_SERVER_TLSCERT")
	tlsKey := os.Getenv("FAKE_IMAP_SERVER_TLSKEY")

	if tlsCert == "" || tlsKey == "" {
		log.Fatal("TLS certificate and key must be provided for IMAPS")
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
