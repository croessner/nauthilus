package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/emersion/go-smtp"
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

func (bkd *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

// A Session is returned after EHLO.
type Session struct {
	auth bool
}

func (s *Session) AuthPlain(username, password string) error {
	_ = password
	s.auth = true

	log.Println(fmt.Sprintf("AUTH username=<%s>", username))

	return nil
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

	time.Sleep(5 * time.Second)

	return smtpErr
}

func (s *Session) Reset() {}

func (s *Session) Logout() error {
	return nil
}

func main() {
	be := &Backend{}

	s := smtp.NewServer(be)

	cer, err := tls.LoadX509KeyPair(os.Getenv("FAKE_SMTP_SERVER_TLSCERT"), os.Getenv("FAKE_SMTP_SERVER_TLSKEY"))
	if err != nil {
		log.Println(err)

		return
	}

	s.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cer},
	}

	s.Addr = os.Getenv("FAKE_SMTP_SERVER_ADDRESS")
	s.Domain = os.Getenv("FAKE_SMTP_SERVER_NAME")
	s.ReadTimeout = 10 * time.Second
	s.WriteTimeout = 10 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true
	s.EnableBINARYMIME = true
	s.EnableSMTPUTF8 = true

	log.Println("Starting fake server at", s.Addr)

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
