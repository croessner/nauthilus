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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/lualib/smtp"
)

const (
	mailLogMessageCompleted = "plugin mail send completed"
	mailLogMessageFailure   = "plugin mail send failed"
	mailOperationSend       = "mail_send"
	mailProtocolSMTP        = "smtp"
	mailProtocolLMTP        = "lmtp"
	mailResultOK            = "ok"
	mailResultError         = "error"
	mailResultCanceled      = "canceled"
	mailResultTimeout       = "timeout"
)

var (
	errInvalidMailRequest = errors.New("invalid plugin mail request")
	errMailSendFailed     = errors.New("plugin mail send failed")
)

var _ pluginapi.Mailer = (*MailFacade)(nil)

// MailFacade sends plugin mail through the host-owned SMTP/LMTP implementation.
type MailFacade struct {
	sender smtp.Client
	logger pluginapi.Logger
	scope  string
}

// MailFacadeOption customizes a host-managed mail facade.
type MailFacadeOption func(*MailFacade)

// NewMailFacade returns a scoped host mail facade.
func NewMailFacade(scope string, options ...MailFacadeOption) *MailFacade {
	facade := &MailFacade{
		sender: &smtp.EmailClient{},
		scope:  scope,
	}
	for _, option := range options {
		option(facade)
	}

	return facade
}

// MailFacadeSender configures the SMTP/LMTP sender used by the facade.
func MailFacadeSender(sender smtp.Client) MailFacadeOption {
	return func(facade *MailFacade) {
		if sender != nil {
			facade.sender = sender
		}
	}
}

// MailFacadeLogger configures the logger used by the facade.
func MailFacadeLogger(logger pluginapi.Logger) MailFacadeOption {
	return func(facade *MailFacade) {
		if logger != nil {
			facade.logger = logger
		}
	}
}

// Send adapts an API-level mail message and sends it synchronously.
func (f *MailFacade) Send(ctx context.Context, message pluginapi.MailMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if f == nil {
		f = NewMailFacade("")
	}

	prepared, err := f.prepareMessage(message)
	if err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		f.logFailure(ctx, prepared, mailErrorResult(err), 0)

		return err
	}

	started := time.Now()
	sender := f.sender

	if sender == nil {
		sender = &smtp.EmailClient{}
	}

	if err := sender.SendMail(prepared.options); err != nil {
		result := mailErrorResult(err)
		f.logFailure(ctx, prepared, result, time.Since(started))

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		return fmt.Errorf("%w: %s", errMailSendFailed, result)
	}

	f.logSuccess(ctx, prepared, mailResultOK, time.Since(started))

	return nil
}

// prepareMessage validates scoped labels and builds internal SMTP options.
func (f *MailFacade) prepareMessage(message pluginapi.MailMessage) (preparedMailMessage, error) {
	if err := pluginapi.ValidateComponentName(f.scope); err != nil {
		return preparedMailMessage{}, err
	}

	options, err := mailOptionsFromMessage(message)
	if err != nil {
		return preparedMailMessage{}, err
	}

	return preparedMailMessage{
		options:  options,
		protocol: mailProtocol(message),
	}, nil
}

// logSuccess writes a bounded success record without message or server data.
func (f *MailFacade) logSuccess(ctx context.Context, message preparedMailMessage, result string, duration time.Duration) {
	if f.logger == nil {
		return
	}

	f.logger.Debug(ctx, mailLogMessageCompleted, mailLogFields(message, result, duration)...)
}

// logFailure writes a bounded failure record without raw transport error text.
func (f *MailFacade) logFailure(ctx context.Context, message preparedMailMessage, result string, duration time.Duration) {
	if f.logger == nil {
		return
	}

	fields := append(mailLogFields(message, result, duration), pluginapi.LogField{Key: pluginLogFieldErrorClass, Value: result})
	f.logger.Error(ctx, mailLogMessageFailure, fields...)
}

type preparedMailMessage struct {
	options  *smtp.MailOptions
	protocol string
}

// mailOptionsFromMessage converts the public request value into SMTP mail options.
func mailOptionsFromMessage(message pluginapi.MailMessage) (*smtp.MailOptions, error) {
	if strings.TrimSpace(message.Server) == "" {
		return nil, fmt.Errorf("%w: server is required", errInvalidMailRequest)
	}

	if message.Port <= 0 || message.Port > 65535 {
		return nil, fmt.Errorf("%w: port is invalid", errInvalidMailRequest)
	}

	if strings.TrimSpace(message.From) == "" {
		return nil, fmt.Errorf("%w: from is required", errInvalidMailRequest)
	}

	recipients, err := cloneMailRecipients(message.To)
	if err != nil {
		return nil, err
	}

	return smtp.NewMailOptions(
		message.Server,
		message.Port,
		message.HeloName,
		message.Username,
		message.Password,
		message.From,
		recipients,
		message.Subject,
		message.Body,
		message.TLS,
		message.StartTLS,
		message.LMTP,
	), nil
}

// cloneMailRecipients copies recipients after rejecting empty recipient lists.
func cloneMailRecipients(recipients []string) ([]string, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: recipient is required", errInvalidMailRequest)
	}

	cloned := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		if strings.TrimSpace(recipient) == "" {
			return nil, fmt.Errorf("%w: recipient is required", errInvalidMailRequest)
		}

		cloned = append(cloned, recipient)
	}

	return cloned, nil
}

// mailProtocol returns the bounded protocol label for a mail request.
func mailProtocol(message pluginapi.MailMessage) string {
	if message.LMTP {
		return mailProtocolLMTP
	}

	return mailProtocolSMTP
}

// mailErrorResult maps transport errors into bounded result labels.
func mailErrorResult(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return mailResultCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return mailResultTimeout
	default:
		return mailResultError
	}
}

// mailLogFields returns bounded structured fields for one mail facade call.
func mailLogFields(message preparedMailMessage, result string, duration time.Duration) []pluginapi.LogField {
	return []pluginapi.LogField{
		{Key: "operation", Value: mailOperationSend},
		{Key: "mail_protocol", Value: message.protocol},
		{Key: "mail_result", Value: result},
		{Key: httpLogFieldDurationMS, Value: durationMilliseconds(duration)},
	}
}
