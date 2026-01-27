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
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// WithLanguage is a middleware function that handles the language setup for the application.
func WithLanguage(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			langFromURL    string
			langFromCookie string
		)

		guid := ctx.GetString(definitions.CtxGUIDKey)

		// Try to get language tag from URL
		langFromURL = ctx.Param("languageTag")

		// Try to get language tag from cookie
		session := sessions.Default(ctx)

		if cookieValue, err := util.GetSessionValue[string](session, definitions.CookieLang); err == nil {
			langFromCookie = cookieValue
		}

		lang, needCookie, needRedirect := setLanguageDetails(cfg, langFromURL, langFromCookie, "")
		accept := ctx.GetHeader("Accept-Language")

		if lang == "" {
			tag, _ := language.MatchStrings(config.Matcher, accept)
			baseName, _ := tag.Base()
			langFromBrowser := baseName.String()
			lang, needCookie, needRedirect = setLanguageDetails(cfg, langFromURL, langFromCookie, langFromBrowser)
		}

		tag, _ := language.MatchStrings(config.Matcher, lang, accept)
		baseName, _ := tag.Base()

		// Language not found in catalog
		if lang != "" && lang != baseName.String() {
			ctx.AbortWithError(http.StatusNotFound, errors.ErrLanguageNotFound)

			return
		}

		localizer := i18n.NewLocalizer(core.LangBundle, lang, accept)

		if needCookie {
			session.Set(definitions.CookieLang, baseName.String())
			err := session.Save()
			if err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "Failed to save session",
					definitions.LogKeyError, err,
				)
			}
		}

		ctx.Set(definitions.CtxLocalizedKey, localizer)

		if needRedirect && ctx.Request.Method == http.MethodGet {
			var sb strings.Builder

			path := ctx.Request.URL.Path
			if strings.HasSuffix(path, "/") {
				path = strings.TrimSuffix(path, "/")
			}

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
