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

// Package i18n provides i18n functionality.
package i18n

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	corelang "github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

const languageCookieMaxAgeSeconds = 365 * 24 * 60 * 60

type languageSources struct {
	guid         string
	url          string
	cookie       string
	browser      string
	accept       string
	baseName     string
	lang         string
	needCookie   bool
	needRedirect bool
}

// WithLanguage is a middleware function that handles the language setup for the application.
func WithLanguage(cfg config.File, logger *slog.Logger, langManager corelang.Manager) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		sources := newLanguageSources(ctx, cfg, langManager)
		if !validateResolvedLanguage(ctx, sources) {
			return
		}

		localizer := i18n.NewLocalizer(langManager.GetBundle(), sources.lang, sources.accept)
		saveLanguageCookie(ctx, logger, sources)
		ctx.Set(definitions.CtxLocalizedKey, localizer)

		if redirectLanguageRequest(ctx, sources) {
			return
		}

		ctx.Next()
	}
}

// newLanguageSources collects language sources and resolves the final language.
func newLanguageSources(ctx *gin.Context, cfg config.File, langManager corelang.Manager) languageSources {
	sources := languageSources{
		guid:   ctx.GetString(definitions.CtxGUIDKey),
		url:    ctx.Param("languageTag"),
		accept: ctx.GetHeader("Accept-Language"),
	}

	if cookieLang, err := ctx.Cookie(definitions.LanguageCookieName); err == nil {
		sources.cookie = strings.TrimSpace(cookieLang)
	}

	sources.browser = browserLanguage(sources, langManager)
	sources.lang, sources.needCookie, sources.needRedirect = setLanguageDetails(cfg, sources.url, sources.cookie, sources.browser)
	sources.baseName = matchedLanguageBaseName(langManager, sources.lang, sources.accept)

	return sources
}

// browserLanguage resolves the best browser language when no stronger source exists.
func browserLanguage(sources languageSources, langManager corelang.Manager) string {
	if sources.url != "" || sources.cookie != "" || sources.accept == "" {
		return ""
	}

	tag, _ := language.MatchStrings(langManager.GetMatcher(), sources.accept)
	baseName, _ := tag.Base()

	return baseName.String()
}

// matchedLanguageBaseName resolves the supported base language name for a candidate language.
func matchedLanguageBaseName(langManager corelang.Manager, lang string, accept string) string {
	tag, _ := language.MatchStrings(langManager.GetMatcher(), lang, accept)
	baseName, _ := tag.Base()

	return baseName.String()
}

// validateResolvedLanguage aborts the request when the resolved language is unsupported.
func validateResolvedLanguage(ctx *gin.Context, sources languageSources) bool {
	if sources.lang == "" || sources.lang == sources.baseName {
		return true
	}

	_ = ctx.AbortWithError(http.StatusNotFound, errors.ErrLanguageNotFound)

	return false
}

// saveLanguageCookie persists the resolved language when cookie state changed.
func saveLanguageCookie(ctx *gin.Context, logger *slog.Logger, sources languageSources) {
	if !sources.needCookie {
		return
	}

	ctx.SetCookie(
		definitions.LanguageCookieName,
		sources.baseName,
		languageCookieMaxAgeSeconds,
		"/",
		"",
		util.ShouldSetSecureCookie(),
		true,
	)

	level.Debug(logger).Log(
		definitions.LogKeyGUID, sources.guid,
		definitions.LogKeyMsg, "Language preference saved to language cookie",
		"lang", sources.baseName,
	)
}

// redirectLanguageRequest redirects GET requests to the language-specific path.
func redirectLanguageRequest(ctx *gin.Context, sources languageSources) bool {
	if !sources.needRedirect || ctx.Request.Method != http.MethodGet {
		return false
	}

	ctx.Redirect(http.StatusFound, languageRedirectURL(ctx, sources.baseName))
	ctx.Abort()

	return true
}

// languageRedirectURL returns the current request path with the resolved language suffix.
func languageRedirectURL(ctx *gin.Context, baseName string) string {
	var sb strings.Builder

	path := strings.TrimSuffix(ctx.Request.URL.Path, "/")

	sb.WriteString(path)
	sb.WriteByte('/')
	sb.WriteString(baseName)

	if ctx.Request.URL.RawQuery != "" {
		sb.WriteByte('?')
		sb.WriteString(ctx.Request.URL.RawQuery)
	}

	return sb.String()
}

func setLanguageDetails(cfg config.File, langFromURL string, langFromCookie string, langFromBrowser string) (lang string, needCookie bool, needRedirect bool) {
	if langFromURL != "" {
		return languageDetailsFromURL(langFromURL, langFromCookie)
	}

	if langFromCookie != "" {
		return langFromCookie, false, true
	}

	if langFromBrowser != "" {
		return langFromBrowser, true, true
	}

	return cfg.GetServer().Frontend.GetDefaultLanguage(), true, true
}

// languageDetailsFromURL resolves cookie update needs for URL-bound language tags.
func languageDetailsFromURL(langFromURL string, langFromCookie string) (string, bool, bool) {
	return langFromURL, langFromCookie == "" || langFromURL != langFromCookie, false
}
