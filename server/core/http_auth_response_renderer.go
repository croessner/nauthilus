// Copyright (C) 2026 Christian Rößner
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

package core

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/encoding/cborcodec"
	servererrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/log/level"

	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
)

const (
	authMediaTypeCBOR = "application/cbor"
	authMediaTypeForm = "application/x-www-form-urlencoded"
	authMediaTypeJSON = "application/json"
	authMediaTypeText = "text/plain"
)

// HTTPAuthResponseRenderer projects transport-neutral application outcomes onto established HTTP surfaces.
type HTTPAuthResponseRenderer struct {
	deps ResponseDeps
}

// NewHTTPAuthResponseRenderer constructs the shared HTTP response adapter.
func NewHTTPAuthResponseRenderer(deps ResponseDeps) *HTTPAuthResponseRenderer {
	return &HTTPAuthResponseRenderer{deps: deps}
}

// RenderAuth writes one terminal authentication outcome without replaying domain side effects.
func (r *HTTPAuthResponseRenderer) RenderAuth(ctx *gin.Context, input AuthInput, outcome *AuthOutcome) {
	if r == nil || ctx == nil || outcome == nil {
		return
	}

	applyCapturedResponseMutations(ctx, outcome.ResponseHeaders, outcome.ResponseHeaderDeletes)

	switch outcome.Decision {
	case AuthDecisionOK:
		r.renderSuccess(ctx, input, outcome)
	case AuthDecisionFail:
		r.renderFailure(ctx, input, outcome)
	case AuthDecisionTempFail:
		r.renderTempFail(ctx, input, outcome)
	default:
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}
}

// RenderListAccounts writes the established negotiated account-provider surface.
func (r *HTTPAuthResponseRenderer) RenderListAccounts(
	ctx *gin.Context,
	input AuthInput,
	outcome *ListAccountsOutcome,
) {
	if r == nil || ctx == nil || outcome == nil {
		return
	}

	if outcome.Decision != "" && outcome.Decision != AuthDecisionOK {
		r.RenderAuth(ctx, input, authOutcomeFromListAccountsOutcome(outcome))

		return
	}

	applyCapturedResponseMutations(ctx, outcome.ResponseHeaders, outcome.ResponseHeaderDeletes)

	status := outcome.HTTPStatus
	if status == 0 {
		status = http.StatusOK
	}

	chosen := listAccountsNegotiator.BestMatch(ctx.GetHeader("Accept"))
	switch chosen {
	case authMediaTypeJSON:
		ctx.JSON(status, outcome.Accounts)
	case authMediaTypeCBOR:
		writeCBORList(ctx, outcome.Accounts)
	case authMediaTypeText:
		writeLineSeparated(ctx, outcome.Accounts, authMediaTypeText)
	case authMediaTypeForm:
		writeLineSeparated(ctx, outcome.Accounts, authMediaTypeForm)
	default:
		_ = ctx.Error(servererrors.ErrUnsupportedMediaType).SetType(gin.ErrorTypeBind)
		ctx.AbortWithStatus(http.StatusUnsupportedMediaType)
	}
}

// writeCBORList encodes the account list as a single CBOR array body.
func writeCBORList(ctx *gin.Context, accounts AccountList) {
	body, err := cborcodec.Marshal(accounts)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	ctx.Data(http.StatusOK, authMediaTypeCBOR, body)
}

// writeLineSeparated streams accounts as CRLF-separated entries.
func writeLineSeparated(ctx *gin.Context, accounts AccountList, contentType string) {
	for _, account := range accounts {
		ctx.Data(http.StatusOK, contentType, []byte(account+"\r\n"))
	}
}

// renderSuccess writes common success headers and the selected surface payload.
func (r *HTTPAuthResponseRenderer) renderSuccess(ctx *gin.Context, input AuthInput, outcome *AuthOutcome) {
	ctx.Header("Auth-Status", authStatusMessageOK)
	ctx.Header("X-Nauthilus-Session", outcome.Session)

	if input.Service != definitions.ServBasic && outcome.Account != "" {
		ctx.Header("Auth-User", outcome.Account)
	}

	cacheState := "Miss"
	if outcome.MemoryCacheHit {
		cacheState = "Hit"
	}

	ctx.Header("X-Nauthilus-Memory-Cache", cacheState)

	switch input.Service {
	case definitions.ServNginx:
		r.renderNginxBackend(ctx, input, outcome)
		ctx.Status(authOutcomeStatus(outcome, http.StatusOK))
	case definitions.ServHeader:
		r.renderAttributeHeaders(ctx, outcome)
		ctx.Status(authOutcomeStatus(outcome, http.StatusOK))
	case definitions.ServJSON, definitions.ServCBOR:
		r.renderStructuredSuccess(ctx, input, outcome)
	default:
		ctx.Status(authOutcomeStatus(outcome, http.StatusOK))
	}
}

// renderFailure writes the legacy null-body failure surface and bounded wait header.
func (r *HTTPAuthResponseRenderer) renderFailure(ctx *gin.Context, input AuthInput, outcome *AuthOutcome) {
	statusMessage := r.renderStatusMessage(ctx, outcome)
	if statusMessage == "" {
		statusMessage = definitions.PasswordFail
	}

	ctx.Header("Auth-Status", statusMessage)
	ctx.Header("X-Nauthilus-Session", outcome.Session)
	r.renderWaitHeader(ctx, outcome.ResponseSettings, outcome.LoginAttempts)

	status := authOutcomeStatus(outcome, http.StatusForbidden)

	switch input.Service {
	case definitions.ServHeader, definitions.ServNginx, definitions.ServJSON:
		ctx.JSON(status, nil)
	case definitions.ServCBOR:
		sendCBOR(ctx, status, nil)
	default:
		ctx.String(status, statusMessage)
	}
}

// renderTempFail writes the established temporary-failure surface.
func (r *HTTPAuthResponseRenderer) renderTempFail(ctx *gin.Context, input AuthInput, outcome *AuthOutcome) {
	statusMessage := r.renderStatusMessage(ctx, outcome)
	if statusMessage == "" {
		statusMessage = outcome.Error
	}

	if statusMessage == "" {
		statusMessage = definitions.TempFailDefault
	}

	ctx.Header("Auth-Status", statusMessage)
	ctx.Header("X-Nauthilus-Session", outcome.Session)

	protocol := outcome.Protocol
	if protocol == "" {
		protocol = input.Context.Protocol
	}

	if input.Service == definitions.ServNginx && protocol == definitions.ProtoSMTP {
		ctx.Header("Auth-Error-Code", definitions.TempFailCode)
	}

	status := authOutcomeStatus(outcome, http.StatusInternalServerError)

	switch input.Service {
	case definitions.ServJSON:
		ctx.JSON(status, gin.H{responseBodyFieldError: statusMessage})
	case definitions.ServCBOR:
		sendCBOR(ctx, status, gin.H{responseBodyFieldError: statusMessage})
	default:
		ctx.String(status, statusMessage)
	}
}

// renderStructuredSuccess writes the stable JSON or CBOR success envelope.
func (r *HTTPAuthResponseRenderer) renderStructuredSuccess(
	ctx *gin.Context,
	input AuthInput,
	outcome *AuthOutcome,
) {
	response := authResponse{
		OK:           true,
		AccountField: outcome.AccountField,
		TOTPSecret:   "",
		Backend:      int(outcome.Backend),
		Attributes: FilterSensitiveOutputAttributes(
			outcome.Attributes,
			outcome.TOTPSecretField,
			outcome.TOTPRecoveryField,
		),
	}

	status := authOutcomeStatus(outcome, http.StatusOK)
	if input.Service == definitions.ServCBOR {
		sendCBOR(ctx, status, response)

		return
	}

	payload, err := jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(response)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	ctx.Data(status, authMediaTypeJSON+"; charset=utf-8", payload)
}

// renderAttributeHeaders projects non-sensitive backend attributes onto the header surface.
func (r *HTTPAuthResponseRenderer) renderAttributeHeaders(ctx *gin.Context, outcome *AuthOutcome) {
	for name, values := range outcome.Attributes {
		if IsSensitiveOutputAttribute(name, outcome.TOTPSecretField, outcome.TOTPRecoveryField) {
			continue
		}

		handleAttributeValue(ctx, name, values)
	}
}

// renderNginxBackend preserves selected backend affinity or configured protocol fallback.
func (r *HTTPAuthResponseRenderer) renderNginxBackend(
	ctx *gin.Context,
	input AuthInput,
	outcome *AuthOutcome,
) {
	settings := r.responseSettings(outcome.ResponseSettings)

	if settings.BackendHealthChecks {
		if BackendServers.GetTotalServers() == 0 {
			ctx.Header("Auth-Status", "Internal failure")

			logger := r.deps.Logger
			if logger == nil {
				logger = slog.Default()
			}

			_ = level.Error(logger).Log(
				definitions.LogKeyGUID, outcome.Session,
				definitions.LogKeyMsg, "No backend servers found for backend_health_checks service",
				definitions.LogKeyError, "No backend servers found for backend_health_checks service",
				definitions.LogKeyInstance, settings.InstanceName,
			)

			return
		}

		if outcome.UsedBackendIP != "" && outcome.UsedBackendPort > 0 {
			ctx.Header("Auth-Server", outcome.UsedBackendIP)
			ctx.Header("Auth-Port", fmt.Sprintf("%d", outcome.UsedBackendPort))
		}

		return
	}

	protocol := outcome.Protocol
	if protocol == "" {
		protocol = input.Context.Protocol
	}

	switch protocol {
	case definitions.ProtoSMTP:
		ctx.Header("Auth-Server", settings.SMTPBackendAddress)
		ctx.Header("Auth-Port", fmt.Sprintf("%d", settings.SMTPBackendPort))
	case definitions.ProtoIMAP:
		ctx.Header("Auth-Server", settings.IMAPBackendAddress)
		ctx.Header("Auth-Port", fmt.Sprintf("%d", settings.IMAPBackendPort))
	case definitions.ProtoPOP3:
		ctx.Header("Auth-Server", settings.POP3BackendAddress)
		ctx.Header("Auth-Port", fmt.Sprintf("%d", settings.POP3BackendPort))
	}
}

// renderWaitHeader calculates the same bounded brute-force delay as the legacy writer.
func (r *HTTPAuthResponseRenderer) renderWaitHeader(
	ctx *gin.Context,
	settings AuthResponseSettings,
	loginAttempts uint,
) {
	maximum := r.responseSettings(settings).NginxWaitDelay
	if maximum == 0 {
		return
	}

	if r.deps.WaitDelay == nil {
		return
	}

	ctx.Header("Auth-Wait", fmt.Sprintf("%d", r.deps.WaitDelay(maximum, loginAttempts)))
}

// renderStatusMessage resolves policy-selected localization at the HTTP boundary.
func (r *HTTPAuthResponseRenderer) renderStatusMessage(ctx *gin.Context, outcome *AuthOutcome) string {
	fallback := outcome.StatusMessage
	key := strings.TrimSpace(outcome.StatusMessageI18NKey)

	resolver := outcome.MessageResolver
	if resolver == nil {
		resolver = r.deps.Resolver
	}

	if key == "" || resolver == nil {
		return fallback
	}

	resolved := resolver.ResolveStatusMessage(
		statusMessageContext(ctx),
		localization.StatusMessage{Text: fallback, I18NKey: key},
		localization.LanguagePreference{
			Policy:  outcome.ResponseLanguage,
			Header:  acceptLanguageHeader(ctx),
			Default: r.responseSettings(outcome.ResponseSettings).DefaultLanguage,
		},
	)
	if strings.TrimSpace(resolved.Language) != "" {
		ctx.Header("Content-Language", resolved.Language)
	}

	if resolved.Text == "" {
		return fallback
	}

	return resolved.Text
}

// responseSettings returns the captured generation or a compatibility snapshot for direct callers.
func (r *HTTPAuthResponseRenderer) responseSettings(captured AuthResponseSettings) AuthResponseSettings {
	if captured.Captured {
		return captured
	}

	return newAuthResponseSettings(r.deps.Cfg)
}

// applyCapturedResponseMutations restores bounded response mutations selected before terminal rendering.
func applyCapturedResponseMutations(ctx *gin.Context, headers http.Header, deletes []string) {
	for _, name := range deletes {
		ctx.Writer.Header().Del(name)
	}

	for name, values := range headers {
		ctx.Writer.Header().Del(name)

		for _, value := range values {
			ctx.Writer.Header().Add(name, value)
		}
	}
}

// authOutcomeFromListAccountsOutcome retains the complete terminal list projection for shared rendering.
func authOutcomeFromListAccountsOutcome(outcome *ListAccountsOutcome) *AuthOutcome {
	if outcome == nil {
		return nil
	}

	return &AuthOutcome{
		ResponseHeaders:         outcome.ResponseHeaders.Clone(),
		MessageResolver:         outcome.MessageResolver,
		ResponseHeaderDeletes:   append([]string(nil), outcome.ResponseHeaderDeletes...),
		FSMEventPath:            append([]string(nil), outcome.FSMEventPath...),
		ResponseSettings:        outcome.ResponseSettings,
		Decision:                outcome.Decision,
		TerminalState:           outcome.TerminalState,
		Session:                 outcome.Session,
		StatusMessage:           outcome.StatusMessage,
		StatusMessageI18NKey:    outcome.StatusMessageI18NKey,
		ResponseLanguage:        outcome.ResponseLanguage,
		Error:                   outcome.Error,
		Protocol:                outcome.Protocol,
		HTTPStatus:              outcome.HTTPStatus,
		LoginAttempts:           outcome.LoginAttempts,
		MemoryCacheHit:          outcome.MemoryCacheHit,
		DelayedResponseEligible: outcome.DelayedResponseEligible,
	}
}

// authOutcomeStatus selects a non-zero status while preserving service-specific compatibility codes.
func authOutcomeStatus(outcome *AuthOutcome, fallback int) int {
	if outcome != nil && outcome.HTTPStatus > 0 {
		return outcome.HTTPStatus
	}

	return fallback
}
