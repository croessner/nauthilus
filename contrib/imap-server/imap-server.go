package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"os"
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

	time.Sleep(5 * time.Second)

	return user, errContactSupport
}

func main() {
	be := &Backend{}

	// Create a new server
	s := server.New(be)

	address := os.Getenv("FAKE_IMAP_SERVER_ADDRESS")
	tlsCert := os.Getenv("FAKE_IMAP_SERVER_TLSCERT")
	tlsKey := os.Getenv("FAKE_IMAP_SERVER_TLSKEY")

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
		address = "127.0.0.1:10143"
	}

	s.Addr = address
	s.AllowInsecureAuth = true

	log.Println("Starting IMAP server at", s.Addr)

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
