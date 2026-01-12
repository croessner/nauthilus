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

package core

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// NotifyGETHandler Page '/notify'
func (h *HydraHandlers) NotifyGETHandler(ctx *gin.Context) {
	NotifyGETHandlerWithDeps(ctx, AuthDeps{
		Cfg:    h.deps.Cfg,
		Logger: h.deps.Logger,
		Env:    h.deps.Env,
		Redis:  h.deps.Redis,
	})
}

// NotifyGETHandlerWithDeps is a handler function that handles the GET request for the notify page.
func NotifyGETHandlerWithDeps(ctx *gin.Context, deps AuthDeps) {
	var (
		found          bool
		msg            string
		value          any
		httpStatusCode = http.StatusOK
	)

	statusTitle := frontend.GetLocalized(ctx, "Information")

	if value, found = ctx.Get(definitions.CtxFailureKey); found {
		if value.(bool) {
			httpStatusCode = http.StatusBadRequest
			statusTitle = frontend.GetLocalized(ctx, "Bad Request")
		}
	}

	if value, found = ctx.Get(definitions.CtxMessageKey); found {
		switch what := value.(type) {
		case error:
			msg = frontend.GetLocalized(ctx, "An error occurred:") + " " + what.Error()
		case string:
			msg = frontend.GetLocalized(ctx, what)
		}
	} else {
		msg = frontend.GetLocalized(ctx, ctx.Query("message"))
	}

	// Fallback for non-localized messages
	if msg == "" {
		msg = ctx.Query("message")
	}

	session := sessions.Default(ctx)
	cookieValue := session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, deps.Cfg, deps.Cfg.GetServer().Frontend.GetNotifyPage(), config.DefaultLanguageTags, languageCurrentName)

	notifyData := frontend.NotifyPageData{
		Title: statusTitle,
		WantWelcome: func() bool {
			if deps.Cfg.GetServer().Frontend.GetNotifyPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             deps.Cfg.GetServer().Frontend.GetNotifyPageWelcome(),
		LogoImage:           deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(),
		NotifyMessage:       msg,
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
	}

	ctx.HTML(httpStatusCode, "notify.html", notifyData)
}
