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

package main

import (
	"context"
	"fmt"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const redisHashFieldSendMail = "send_mail"

// mailTemplateData is the bounded data model exposed to mail templates.
type mailTemplateData struct {
	Account    string
	HashPrefix string
	Website    string
	Timestamp  time.Time
	Count      int
}

// notifyPositiveMail sends a duplicate-gated mail notification for one fresh positive HIBP lookup.
func notifyPositiveMail(
	ctx context.Context,
	state pluginState,
	snapshot pluginapi.RequestSnapshot,
	redisKey string,
	prefix string,
	count int,
) (string, error) {
	if !state.config.Mail.Enabled {
		state.metrics.recordMailResult(ctx, resultMailDisabled)

		return resultMailDisabled, nil
	}

	ctx, span := startHIBPSpan(ctx, state.tracer, operationMail)
	defer span.End()

	result, err := sendPositiveMail(ctx, state, snapshot, redisKey, prefix, count)
	state.metrics.recordMailResult(ctx, result)
	span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: result})
	logMailOutcome(ctx, state, result)

	if err != nil {
		span.RecordError(err)
	}

	return result, err
}

// sendPositiveMail claims the Redis mail gate, renders templates, sends mail, and extends hash expiry.
func sendPositiveMail(
	ctx context.Context,
	state pluginState,
	snapshot pluginapi.RequestSnapshot,
	redisKey string,
	prefix string,
	count int,
) (string, error) {
	if state.mailer == nil {
		return resultMailSendError, fmt.Errorf("haveibeenpwnd mail facade unavailable")
	}

	allowed, err := claimMailGate(ctx, state.redis, redisKey)
	if err != nil {
		return resultMailSendError, err
	}

	if !allowed {
		return resultMailGateSkipped, nil
	}

	message, err := renderPositiveMailMessage(state.config.Mail, snapshot.Account, prefix, count)
	if err != nil {
		return resultMailTemplateError, fmt.Errorf("haveibeenpwnd mail template render failed: %w", err)
	}

	if err := state.mailer.Send(ctx, message); err != nil {
		return resultMailSendError, fmt.Errorf("haveibeenpwnd mail send failed: %w", err)
	}

	if err := expireRedisHash(ctx, state.redis, redisKey, state.config.RedisNegativeTTL); err != nil {
		return resultMailSendError, err
	}

	return resultMailSent, nil
}

// claimMailGate claims the Redis hash field used to suppress duplicate notifications.
func claimMailGate(ctx context.Context, redisFacade pluginapi.Redis, redisKey string) (bool, error) {
	if redisFacade == nil || redisFacade.Write() == nil {
		return false, fmt.Errorf("haveibeenpwnd Redis facade unavailable")
	}

	return redisFacade.Write().HSetNX(ctx, redisKey, redisHashFieldSendMail, "1").Result()
}

// expireRedisHash updates the HIBP hash TTL after a successful notification.
func expireRedisHash(ctx context.Context, redisFacade pluginapi.Redis, redisKey string, ttl time.Duration) error {
	if redisFacade == nil || redisFacade.Write() == nil {
		return fmt.Errorf("haveibeenpwnd Redis facade unavailable")
	}

	return redisFacade.Write().Expire(ctx, redisKey, ttl).Err()
}

// renderPositiveMailMessage builds the host mail facade request for a positive HIBP lookup.
func renderPositiveMailMessage(config mailConfig, account string, prefix string, count int) (pluginapi.MailMessage, error) {
	return renderMailMessage(config, mailTemplateData{
		Account:    account,
		HashPrefix: prefix,
		Count:      count,
		Website:    config.Website,
		Timestamp:  time.Now().UTC(),
	}, account)
}

// renderMailMessage executes parsed subject and body templates into a value-only mail request.
func renderMailMessage(config mailConfig, data mailTemplateData, recipient string) (pluginapi.MailMessage, error) {
	subject, err := executeMailTemplate(config.SubjectTemplate, data)
	if err != nil {
		return pluginapi.MailMessage{}, err
	}

	body, err := executeMailTemplate(config.BodyTemplate, data)
	if err != nil {
		return pluginapi.MailMessage{}, err
	}

	return pluginapi.MailMessage{
		Server:   config.Server,
		HeloName: config.HeloName,
		Username: config.Username,
		Password: config.Password,
		From:     config.MailFrom,
		Subject:  subject,
		Body:     body,
		To:       []string{recipient},
		Port:     config.Port,
		TLS:      config.TLS,
		StartTLS: config.StartTLS,
		LMTP:     config.UseLMTP,
	}, nil
}

// logMailOutcome records one bounded mail result without message or recipient data.
func logMailOutcome(ctx context.Context, state pluginState, result string) {
	if state.logger == nil {
		return
	}

	state.logger.Debug(ctx, "haveibeenpwnd mail completed", pluginapi.LogField{Key: logFieldMailResult, Value: result})
}
