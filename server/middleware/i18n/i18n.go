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

package i18n

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/cookie"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// WithLanguage is a middleware function that handles the language setup for the application.
func WithLanguage(cfg config.File, logger *slog.Logger, langManager corelang.Manager) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			langFromURL     string
			langFromCookie  string
			langFromBrowser string
		)

		guid := ctx.GetString(definitions.CtxGUIDKey)

		// Try to get language tag from URL
		langFromURL = ctx.Param("languageTag")

		// Try to get language tag from secure cookie
		mgr := cookie.GetManager(ctx)
		if mgr != nil {
			langFromCookie = mgr.GetString(definitions.SessionKeyLang, "")
		}

		// Get Accept-Language header for browser language detection
		accept := ctx.GetHeader("Accept-Language")

		// If no URL or cookie language is set, detect language from browser
		if langFromURL == "" && langFromCookie == "" && accept != "" {
			tag, _ := language.MatchStrings(langManager.GetMatcher(), accept)
			baseName, _ := tag.Base()
			langFromBrowser = baseName.String()
		}

		// Determine language with all available sources
		lang, needCookie, needRedirect := setLanguageDetails(cfg, langFromURL, langFromCookie, langFromBrowser)

		tag, _ := language.MatchStrings(langManager.GetMatcher(), lang, accept)
		baseName, _ := tag.Base()

		// Language not found in catalog
		if lang != "" && lang != baseName.String() {
			ctx.AbortWithError(http.StatusNotFound, errors.ErrLanguageNotFound)

			return
		}

		localizer := i18n.NewLocalizer(langManager.GetBundle(), lang, accept)

		if needCookie && mgr != nil {
			mgr.Set(definitions.SessionKeyLang, baseName.String())
			// Cookie is automatically saved by the cookie.Middleware after the handler chain.
			level.Debug(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Language preference saved to secure cookie",
				"lang", baseName.String(),
			)
		}

		ctx.Set(definitions.CtxLocalizedKey, localizer)

		if needRedirect && ctx.Request.Method == http.MethodGet {
			var sb strings.Builder

			path := strings.TrimSuffix(ctx.Request.URL.Path, "/")

			sb.WriteString(path)
			sb.WriteByte('/')
			sb.WriteString(baseName.String())

			if ctx.Request.URL.RawQuery != "" {
				sb.WriteByte('?')
				sb.WriteString(ctx.Request.URL.RawQuery)
			}

			ctx.Redirect(http.StatusFound, sb.String())
			ctx.Abort()

			return
		}

		ctx.Next()
	}
}

func setLanguageDetails(cfg config.File, langFromURL string, langFromCookie string, langFromBrowser string) (lang string, needCookie bool, needRedirect bool) {
	switch {
	case langFromURL == "" && langFromCookie == "" && langFromBrowser == "":
		// 1. No language from URL, no cookie and no browser language
		lang = ""
	case langFromURL == "" && langFromCookie == "" && langFromBrowser != "":
		// 2. No language from URL and no cookie, but browser language is set
		lang = langFromBrowser
		needCookie = true
		needRedirect = true
	case langFromURL == "" && langFromCookie != "":
		// 3. No language from URL, but a cookie is set
		lang = langFromCookie
		needRedirect = true
	case langFromURL != "" && langFromCookie == "":
		// 4. Language from URL and no cookie
		lang = langFromURL
		needCookie = true
	case langFromURL != "" && langFromCookie != "":
		// 5. Language given from URL and cookie, but both differ
		if langFromURL != langFromCookie {
			needCookie = true
		}

		lang = langFromURL
	}

	if lang == "" && langFromURL == "" && langFromCookie == "" && langFromBrowser == "" {
		lang = cfg.GetServer().Frontend.GetDefaultLanguage()
		needCookie = true
		needRedirect = true
	}

	return lang, needCookie, needRedirect
}
