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

package idp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp/dcr"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/gin-gonic/gin"
)

const oidcRegistrationEndpointPath = "/oidc/register"

const registrationUnknownSource = "unknown"

const (
	registrationAuditOutcomeKey  = "oidc_registration_audit_outcome"
	registrationAuditReasonKey   = "oidc_registration_audit_reason"
	registrationAuditClientIDKey = "oidc_registration_audit_client_id"
)

// dynamicRegistrationService is the narrow HTTP-to-domain registration boundary.
type dynamicRegistrationService interface {
	ReserveAttempt(ctx context.Context, source string) error
	Register(ctx context.Context, metadata dcr.EffectiveMetadata, source string) (dcr.RegistrationResponse, error)
}

// registrationNoStoreMiddleware applies cache prohibitions to every method on the registration path.
func registrationNoStoreMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ctx.Request.URL.Path == oidcRegistrationEndpointPath {
			setRegistrationNoStoreHeaders(ctx)
		}

		ctx.Next()
	}
}

// RegisterDynamicClient handles the restricted anonymous public-native registration profile.
func (h *OIDCHandler) RegisterDynamicClient(ctx *gin.Context) { //nolint:funlen
	startedAt := time.Now()
	defer h.finishDynamicRegistrationAudit(ctx, startedAt)

	setRegistrationNoStoreHeaders(ctx)

	source := registrationSource(ctx)
	if err := h.registrationService.ReserveAttempt(ctx.Request.Context(), source); err != nil {
		if errors.Is(err, dcr.ErrRateLimited) {
			writeRegistrationHTTPError(ctx, http.StatusTooManyRequests)
		} else {
			writeRegistrationHTTPError(ctx, http.StatusServiceUnavailable)
		}

		return
	}

	if !registrationContentTypeIsJSON(ctx.GetHeader("Content-Type")) {
		writeRegistrationHTTPError(ctx, http.StatusUnsupportedMediaType)

		return
	}

	policy := h.deps.Cfg.GetIDP().OIDC.DynamicClientRegistration
	maximumBodyBytes := int64(policy.GetLimits().GetRequestBodyBytes())

	if ctx.Request.ContentLength > maximumBodyBytes {
		writeRegistrationHTTPError(ctx, http.StatusRequestEntityTooLarge)

		return
	}

	body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, maximumBodyBytes+1))
	if err != nil {
		writeRegistrationProtocolError(ctx, &dcr.ProtocolError{
			Code:        "invalid_client_metadata",
			Description: "request body must be readable JSON",
		})

		return
	}

	if int64(len(body)) > maximumBodyBytes {
		writeRegistrationHTTPError(ctx, http.StatusRequestEntityTooLarge)

		return
	}

	request, protocolErr := dcr.DecodeMetadata(bytes.NewReader(body))
	if protocolErr != nil {
		writeRegistrationProtocolError(ctx, protocolErr)

		return
	}

	effective, protocolErr := dcr.BuildEffectiveMetadata(request, policy)
	if protocolErr != nil {
		writeRegistrationProtocolError(ctx, protocolErr)

		return
	}

	response, err := h.registrationService.Register(ctx.Request.Context(), effective, source)
	if err != nil {
		switch {
		case errors.Is(err, dcr.ErrRateLimited), errors.Is(err, dcr.ErrQuota):
			writeRegistrationHTTPError(ctx, http.StatusTooManyRequests)
		default:
			writeRegistrationHTTPError(ctx, http.StatusServiceUnavailable)
		}

		return
	}

	ctx.JSON(http.StatusCreated, response)
	setRegistrationAuditResult(ctx, "accepted", "created", response.ClientID)
	observeRegistration("success", "created")
}

// finishDynamicRegistrationAudit records latency and bounded structured outcome fields.
func (h *OIDCHandler) finishDynamicRegistrationAudit(ctx *gin.Context, startedAt time.Time) {
	duration := time.Since(startedAt)
	stats.GetMetrics().GetIdpDynamicClientRegistrationDurationSeconds().Observe(duration.Seconds())

	if h.deps.Logger == nil {
		return
	}

	outcome := ctx.GetString(registrationAuditOutcomeKey)
	if outcome == "" {
		outcome = dcr.AuditOutcomeFailed
	}

	h.deps.Logger.InfoContext(
		ctx.Request.Context(),
		"OIDC dynamic client registration completed",
		"event", "oidc_dynamic_client_registration",
		"outcome", outcome,
		"reason", ctx.GetString(registrationAuditReasonKey),
		"origin", "dynamic",
		"profile", dcr.ProfileMailClientV1,
		"profile_version", h.deps.Cfg.GetIDP().OIDC.DynamicClientRegistration.GetProfileVersion(),
		definitions.LogKeyClientID, ctx.GetString(registrationAuditClientIDKey),
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		"http_status", ctx.Writer.Status(),
		"duration_ms", duration.Milliseconds(),
	)
}

// registrationContentTypeIsJSON validates the RFC 7591 JSON media type.
func registrationContentTypeIsJSON(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)

	return err == nil && mediaType == "application/json"
}

// registrationSource returns the canonical source address after trusted-proxy handling.
func registrationSource(ctx *gin.Context) string {
	if clientIP := net.ParseIP(ctx.ClientIP()); clientIP != nil {
		return clientIP.String()
	}

	host, _, err := net.SplitHostPort(ctx.Request.RemoteAddr)
	if err == nil {
		if remoteIP := net.ParseIP(host); remoteIP != nil {
			return remoteIP.String()
		}
	}

	return registrationUnknownSource
}

// setRegistrationNoStoreHeaders prevents caching of all registration responses.
func setRegistrationNoStoreHeaders(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
}

// writeRegistrationProtocolError writes a stable RFC 7591 error object.
func writeRegistrationProtocolError(ctx *gin.Context, protocolErr *dcr.ProtocolError) {
	setRegistrationAuditResult(ctx, "rejected", protocolErr.Code, "")
	ctx.JSON(http.StatusBadRequest, gin.H{
		definitions.LogKeyError: protocolErr.Code,
		"error_description":     protocolErr.Description,
	})
	observeRegistration("rejected", protocolErr.Code)
}

// writeRegistrationHTTPError writes a generic non-protocol HTTP failure.
func writeRegistrationHTTPError(ctx *gin.Context, status int) {
	setRegistrationAuditResult(ctx, "failed", http.StatusText(status), "")
	ctx.JSON(status, gin.H{definitions.LogKeyError: http.StatusText(status)})
	observeRegistration("failed", http.StatusText(status))
}

// setRegistrationAuditResult stores only bounded fields for deferred structured logging.
func setRegistrationAuditResult(ctx *gin.Context, outcome string, reason string, clientID string) {
	ctx.Set(registrationAuditOutcomeKey, outcome)
	ctx.Set(registrationAuditReasonKey, reason)
	ctx.Set(registrationAuditClientIDKey, clientID)
}

// observeRegistration records only bounded result and reason labels.
func observeRegistration(outcome string, code string) {
	stats.GetMetrics().GetIdpDynamicClientRegistrationsTotal().WithLabelValues(outcome, code).Inc()
}
