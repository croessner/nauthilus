// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/lualib/smtp"
)

const (
	mailTestScope         = "haveibeenpwnd"
	mailTestServer        = "mail.example.test"
	mailTestHeloName      = "mx.example.test"
	mailTestUsername      = "smtp-user"
	mailTestPassword      = "smtp-secret"
	mailTestFrom          = "Postmaster <postmaster@example.test>"
	mailTestRecipient     = "Alice <alice@example.test>"
	mailTestSubject       = "Secret leak warning"
	mailTestBody          = "Secret mail body"
	mailTestTransportLeak = "raw transport leak alice@example.test smtp-secret Secret mail body"
)

func TestHostMailFacadeAdaptsSMTPMessage(t *testing.T) {
	sender := &recordingMailSender{}
	host := NewHost(WithMailSender(sender))
	message := newMailTestMessage()
	message.TLS = true
	message.StartTLS = true

	if err := host.Mail(mailTestScope).Send(context.Background(), message); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	options := sender.singleCall(t)
	assertMailOptionsMatchMessage(t, options, message)

	if options.LMTP {
		t.Fatal("LMTP = true, want SMTP options")
	}
}

func TestHostMailFacadeAdaptsLMTPMessage(t *testing.T) {
	sender := &recordingMailSender{}
	host := NewHost(WithMailSender(sender))
	message := newMailTestMessage()
	message.LMTP = true
	message.TLS = true
	message.StartTLS = false

	if err := host.Mail(mailTestScope).Send(context.Background(), message); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	options := sender.singleCall(t)
	assertMailOptionsMatchMessage(t, options, message)

	if !options.LMTP {
		t.Fatal("LMTP = false, want LMTP options")
	}
}

func TestHostMailFacadeRejectsInvalidScope(t *testing.T) {
	sender := &recordingMailSender{}
	host := NewHost(WithMailSender(sender))

	err := host.Mail("bad-scope").Send(context.Background(), newMailTestMessage())
	if !errors.Is(err, pluginapi.ErrInvalidName) {
		t.Fatalf("Send() error = %v, want ErrInvalidName", err)
	}

	if sender.calls != 0 {
		t.Fatalf("sender calls = %d, want none", sender.calls)
	}
}

func TestHostMailFacadeRejectsInvalidMessageBeforeSending(t *testing.T) {
	tests := []struct {
		mutate func(*pluginapi.MailMessage)
		name   string
	}{
		{
			name: "server",
			mutate: func(message *pluginapi.MailMessage) {
				message.Server = ""
			},
		},
		{
			name: "port",
			mutate: func(message *pluginapi.MailMessage) {
				message.Port = 0
			},
		},
		{
			name: "from",
			mutate: func(message *pluginapi.MailMessage) {
				message.From = ""
			},
		},
		{
			name: "to",
			mutate: func(message *pluginapi.MailMessage) {
				message.To = nil
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			sender := &recordingMailSender{}
			host := NewHost(WithMailSender(sender))
			message := newMailTestMessage()
			testCase.mutate(&message)

			err := host.Mail(mailTestScope).Send(context.Background(), message)
			if !errors.Is(err, errInvalidMailRequest) {
				t.Fatalf("Send() error = %v, want errInvalidMailRequest", err)
			}

			if sender.calls != 0 {
				t.Fatalf("sender calls = %d, want none", sender.calls)
			}
		})
	}
}

func TestHostMailFacadeRedactsReturnedErrorsAndLogs(t *testing.T) {
	var logs bytes.Buffer

	sender := &recordingMailSender{err: errors.New(mailTestTransportLeak)}
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	host := NewHost(
		WithLogger(logger),
		WithMailSender(sender),
	)

	err := host.Mail(mailTestScope).Send(context.Background(), newMailTestMessage())
	if !errors.Is(err, errMailSendFailed) {
		t.Fatalf("Send() error = %v, want errMailSendFailed", err)
	}

	assertMailRedacted(t, err.Error())
	assertMailRedacted(t, logs.String())

	if !strings.Contains(logs.String(), mailLogMessageFailure) {
		t.Fatalf("mail failure log missing message: %s", logs.String())
	}

	for _, want := range []string{"mail_protocol", "smtp", "mail_result", "error"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("mail failure log missing %q: %s", want, logs.String())
		}
	}
}

type recordingMailSender struct {
	last  *smtp.MailOptions
	err   error
	calls int
}

// SendMail records a cloned options value before returning the configured error.
func (s *recordingMailSender) SendMail(options *smtp.MailOptions) error {
	s.calls++
	s.last = cloneMailOptions(options)

	return s.err
}

// singleCall returns the only recorded mail options or fails the test.
func (s *recordingMailSender) singleCall(t *testing.T) *smtp.MailOptions {
	t.Helper()

	if s.calls != 1 {
		t.Fatalf("sender calls = %d, want one", s.calls)
	}

	if s.last == nil {
		t.Fatal("sender options were not recorded")
	}

	return s.last
}

// newMailTestMessage returns a complete value-only mail request for facade tests.
func newMailTestMessage() pluginapi.MailMessage {
	return pluginapi.MailMessage{
		Server:   mailTestServer,
		HeloName: mailTestHeloName,
		Username: mailTestUsername,
		Password: mailTestPassword,
		From:     mailTestFrom,
		To:       []string{mailTestRecipient},
		Subject:  mailTestSubject,
		Body:     mailTestBody,
		Port:     2525,
	}
}

// assertMailOptionsMatchMessage verifies the runtime adapter preserves public message fields.
func assertMailOptionsMatchMessage(t *testing.T, options *smtp.MailOptions, message pluginapi.MailMessage) {
	t.Helper()

	want := smtp.NewMailOptions(
		message.Server,
		message.Port,
		message.HeloName,
		message.Username,
		message.Password,
		message.From,
		append([]string(nil), message.To...),
		message.Subject,
		message.Body,
		message.TLS,
		message.StartTLS,
		message.LMTP,
	)

	if !reflect.DeepEqual(options, want) {
		t.Fatalf("mail options = %#v, want %#v", options, want)
	}
}

// cloneMailOptions copies mutable SMTP option slices for stable assertions.
func cloneMailOptions(options *smtp.MailOptions) *smtp.MailOptions {
	if options == nil {
		return nil
	}

	cloned := *options
	cloned.To = append([]string(nil), options.To...)

	return &cloned
}

// assertMailRedacted verifies that secret-bearing mail values are absent from text.
func assertMailRedacted(t *testing.T, text string) {
	t.Helper()

	for _, secret := range []string{
		mailTestServer,
		mailTestUsername,
		mailTestPassword,
		mailTestFrom,
		mailTestRecipient,
		mailTestSubject,
		mailTestBody,
		mailTestTransportLeak,
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("mail text leaked %q: %s", secret, text)
		}
	}
}
