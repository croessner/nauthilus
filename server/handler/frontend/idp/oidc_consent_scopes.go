// Copyright (C) 2025 Christian Rößner
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
	"log/slog"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/gin-gonic/gin"
)

const (
	consentMsgScopeProfile = "Access your basic profile information"
	consentMsgScopeEmail   = "Access your email address"
	consentMsgScopeGroups  = "Access your group memberships"
	consentMsgScopeOffline = "Maintain access when you are offline"
	consentMsgNoAdditional = "No additional permissions requested."
)

func consentScopeDescriptions(ctx *gin.Context, cfg config.File, logger *slog.Logger, scopes []string) []string {
	descriptions := make([]string, 0, len(scopes))
	customScopes := cfg.GetIdP().OIDC.CustomScopes
	lang := consentLanguage(ctx)

	for _, scope := range scopes {
		if desc, ok := consentScopeDescription(ctx, cfg, logger, customScopes, lang, scope); ok {
			descriptions = append(descriptions, desc)
		}
	}

	return descriptions
}

func consentScopeDescription(
	ctx *gin.Context,
	cfg config.File,
	logger *slog.Logger,
	customScopes []config.Oauth2CustomScope,
	lang string,
	scope string,
) (string, bool) {
	if scope == "" {
		return "", false
	}

	// openid is technically mandatory and not user-actionable; do not show it.
	if scope == definitions.ScopeOpenId {
		return "", false
	}

	if desc, ok := localizedStandardScopeDescription(ctx, cfg, logger, scope); ok {
		return desc, true
	}

	if desc := localizedCustomScopeDescription(customScopes, scope, lang); desc != "" {
		return desc, true
	}

	// Last fallback: show raw scope name.
	return scope, true
}

func localizedStandardScopeDescription(ctx *gin.Context, cfg config.File, logger *slog.Logger, scope string) (string, bool) {
	switch scope {
	case definitions.ScopeProfile:
		return frontend.GetLocalized(ctx, cfg, logger, consentMsgScopeProfile), true
	case definitions.ScopeEmail:
		return frontend.GetLocalized(ctx, cfg, logger, consentMsgScopeEmail), true
	case definitions.ScopeGroups:
		return frontend.GetLocalized(ctx, cfg, logger, consentMsgScopeGroups), true
	case definitions.ScopeOfflineAccess:
		return frontend.GetLocalized(ctx, cfg, logger, consentMsgScopeOffline), true
	default:
		return "", false
	}
}

func localizedCustomScopeDescription(scopes []config.Oauth2CustomScope, requestedScope, lang string) string {
	for _, scope := range scopes {
		if scope.Name != requestedScope {
			continue
		}

		if localized := localizedScopeDescriptionFromOther(scope.Other, lang); localized != "" {
			return localized
		}

		return scope.Description
	}

	return ""
}

func localizedScopeDescriptionFromOther(other map[string]any, lang string) string {
	if len(other) == 0 {
		return ""
	}

	normalized := strings.ToLower(strings.ReplaceAll(lang, "-", "_"))
	base := normalized
	if idx := strings.IndexByte(base, '_'); idx > 0 {
		base = base[:idx]
	}

	candidates := []string{
		"description_" + normalized,
		"description_" + base,
	}

	for _, key := range candidates {
		if v, ok := other[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}

	return ""
}

func consentLanguage(ctx *gin.Context) string {
	if tag := strings.TrimSpace(ctx.Param("languageTag")); tag != "" {
		return tag
	}

	if tag, err := ctx.Cookie(definitions.LanguageCookieName); err == nil {
		if tag = strings.TrimSpace(tag); tag != "" {
			return tag
		}
	}

	return "en"
}
