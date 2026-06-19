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

// Package idp contains frontend handlers for IDP browser flows.
package idp

import (
	"context"
	stderrors "errors"
	"strings"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	idpservice "github.com/croessner/nauthilus/v3/server/idp"
	"github.com/gin-gonic/gin"
)

const idpGenericInvalidLoginMessage = "Invalid login or password"

type idpAuthStatusBridge struct {
	StatusMessage    string
	I18NKey          string
	ResponseLanguage string
}

func renderIDPAuthFailureMessage(ctx *gin.Context, d *deps.Deps, err error, genericMessage string) string {
	status, ok := idpAuthStatusBridgeFromError(err)
	if !ok {
		return localizedIDPGenericMessage(ctx, d, genericMessage)
	}

	return renderIDPAuthStatusBridgeMessage(ctx, d, status, genericMessage)
}

func idpAuthFailurePolicyTerminal(err error) bool {
	failure, ok := stderrors.AsType[*idpservice.AuthFailureError](err)
	if !ok || failure == nil {
		return false
	}

	return failure.Status.PolicyTerminal
}

func idpAuthFailureAllowsDelayedResponse(err error) bool {
	failure, ok := stderrors.AsType[*idpservice.AuthFailureError](err)
	if !ok || failure == nil {
		return true
	}

	if !failure.Status.PolicyTerminal {
		return true
	}

	return failure.Status.DelayedResponseEligible
}

func storeIDPAuthStatusBridgeFromError(mgr cookie.Manager, err error) bool {
	status, ok := idpAuthStatusBridgeFromError(err)
	if !ok {
		clearIDPAuthStatusBridge(mgr)

		return false
	}

	storeIDPAuthStatusBridge(mgr, status)

	return true
}

func idpAuthStatusBridgeFromError(err error) (idpAuthStatusBridge, bool) {
	failure, ok := stderrors.AsType[*idpservice.AuthFailureError](err)
	if !ok || failure == nil || !failure.Status.HasI18NStatus() {
		return idpAuthStatusBridge{}, false
	}

	return idpAuthStatusBridge{
		StatusMessage:    failure.Status.StatusMessage,
		I18NKey:          failure.Status.I18NKey,
		ResponseLanguage: failure.Status.ResponseLanguage,
	}, true
}

func renderIDPAuthStatusBridgeMessage(
	ctx *gin.Context,
	d *deps.Deps,
	status idpAuthStatusBridge,
	genericMessage string,
) string {
	if strings.TrimSpace(status.I18NKey) == "" {
		return localizedIDPGenericMessage(ctx, d, genericMessage)
	}

	fallback := strings.TrimSpace(status.StatusMessage)
	if d == nil || d.MessageResolver == nil {
		return idpFallbackStatusMessage(ctx, d, fallback, genericMessage)
	}

	resolved := d.MessageResolver.ResolveStatusMessage(
		idpStatusMessageContext(ctx),
		localization.StatusMessage{
			Text:    fallback,
			I18NKey: status.I18NKey,
		},
		localization.LanguagePreference{
			Explicit: explicitIDPUILanguage(ctx),
			Policy:   status.ResponseLanguage,
			Header:   idpAcceptLanguage(ctx),
			Default:  defaultIDPLanguage(d),
		},
	)
	if text := strings.TrimSpace(resolved.Text); text != "" {
		return text
	}

	return idpFallbackStatusMessage(ctx, d, fallback, genericMessage)
}

func storeIDPAuthStatusBridge(mgr cookie.Manager, status idpAuthStatusBridge) {
	if mgr == nil || strings.TrimSpace(status.I18NKey) == "" {
		return
	}

	mgr.Set(definitions.SessionKeyIDPAuthStatusMessage, status.StatusMessage)
	mgr.Set(definitions.SessionKeyIDPAuthStatusI18NKey, status.I18NKey)
	mgr.Set(definitions.SessionKeyIDPAuthStatusLanguage, status.ResponseLanguage)
}

func loadIDPAuthStatusBridge(mgr cookie.Manager) (idpAuthStatusBridge, bool) {
	if mgr == nil {
		return idpAuthStatusBridge{}, false
	}

	status := idpAuthStatusBridge{
		StatusMessage:    mgr.GetString(definitions.SessionKeyIDPAuthStatusMessage, ""),
		I18NKey:          mgr.GetString(definitions.SessionKeyIDPAuthStatusI18NKey, ""),
		ResponseLanguage: mgr.GetString(definitions.SessionKeyIDPAuthStatusLanguage, ""),
	}
	if strings.TrimSpace(status.I18NKey) == "" {
		return idpAuthStatusBridge{}, false
	}

	return status, true
}

func clearIDPAuthStatusBridge(mgr cookie.Manager) {
	if mgr == nil {
		return
	}

	mgr.Delete(definitions.SessionKeyIDPAuthStatusMessage)
	mgr.Delete(definitions.SessionKeyIDPAuthStatusI18NKey)
	mgr.Delete(definitions.SessionKeyIDPAuthStatusLanguage)
}

func renderStoredIDPAuthStatusBridgeMessage(
	ctx *gin.Context,
	d *deps.Deps,
	mgr cookie.Manager,
	genericMessage string,
) string {
	status, ok := loadIDPAuthStatusBridge(mgr)
	clearIDPAuthStatusBridge(mgr)

	if !ok {
		return localizedIDPGenericMessage(ctx, d, genericMessage)
	}

	return renderIDPAuthStatusBridgeMessage(ctx, d, status, genericMessage)
}

func idpFallbackStatusMessage(ctx *gin.Context, d *deps.Deps, fallback string, genericMessage string) string {
	if fallback != "" {
		return fallback
	}

	return localizedIDPGenericMessage(ctx, d, genericMessage)
}

func localizedIDPGenericMessage(ctx *gin.Context, d *deps.Deps, message string) string {
	if d == nil {
		return message
	}

	return frontend.GetLocalized(ctx, d.Cfg, d.Logger, message)
}

func explicitIDPUILanguage(ctx *gin.Context) string {
	if ctx == nil {
		return ""
	}

	if tag := strings.TrimSpace(ctx.Param("languageTag")); tag != "" {
		return tag
	}

	if tag, err := ctx.Cookie(definitions.LanguageCookieName); err == nil {
		return strings.TrimSpace(tag)
	}

	return ""
}

func idpAcceptLanguage(ctx *gin.Context) string {
	if ctx == nil {
		return ""
	}

	return ctx.GetHeader("Accept-Language")
}

func defaultIDPLanguage(d *deps.Deps) string {
	if d == nil || d.Cfg == nil || d.Cfg.GetServer() == nil {
		return ""
	}

	return d.Cfg.GetServer().Frontend.GetDefaultLanguage()
}

func idpStatusMessageContext(ctx *gin.Context) context.Context {
	if ctx == nil || ctx.Request == nil || ctx.Request.Context() == nil {
		return context.Background()
	}

	return ctx.Request.Context()
}
