// Copyright (C) 2024 Christian Rößner
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

package frontend

import (
	"log/slog"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Language represents a language used in various page data structs.
type Language struct {
	// LanguageLink represents the link associated with the language
	LanguageLink string

	// LanguageName represents the name of the language
	LanguageName string
}

// GetLocalized is a function that returns the localized message based on the message ID and the context provided.
func GetLocalized(ctx *gin.Context, cfg config.File, logger *slog.Logger, messageID string) string {
	localizer := ctx.MustGet(definitions.CtxLocalizedKey).(*i18n.Localizer)

	localizeConfig := i18n.LocalizeConfig{
		MessageID: messageID,
	}

	localization, err := localizer.Localize(&localizeConfig)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgAuth,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			"message_id", messageID,
			definitions.LogKeyMsg, "Failed to get localized message",
			definitions.LogKeyError, err,
		)

		return messageID
	}

	return localization
}

// CreateLanguagePassive creates a slice of Language structs for non-current languages.
func CreateLanguagePassive(ctx *gin.Context, destPage string, languageTags []language.Tag, currentName string) []Language {
	var languagePassive []Language

	for _, languageTag := range languageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))

		if languageName != currentName {
			baseName, _ := languageTag.Base()

			var sb strings.Builder

			sb.WriteString(destPage)
			sb.WriteByte('/')
			sb.WriteString(baseName.String())
			sb.WriteByte('?')
			sb.WriteString(ctx.Request.URL.RawQuery)

			languagePassive = append(
				languagePassive,
				Language{
					LanguageLink: sb.String(),
					LanguageName: languageName,
				},
			)
		}
	}

	return languagePassive
}
