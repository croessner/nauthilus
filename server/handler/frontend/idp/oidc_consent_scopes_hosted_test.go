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
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// shippedLocaleDirectory is the directory of the localization resources shipped with Nauthilus.
const shippedLocaleDirectory = "../../../resources"

// TestConsentScopeDescription_LocalizesHostedSupportScopes requires a translated consent text for every hosted
// support scope in every shipped language, so the consent page never shows a raw scope name for them.
func TestConsentScopeDescription_LocalizesHostedSupportScopes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	files, err := filepath.Glob(filepath.Join(shippedLocaleDirectory, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no shipped localization resources found: %v", err)
	}

	for _, file := range files {
		lang := strings.TrimSuffix(filepath.Base(file), ".json")

		t.Run(lang, func(t *testing.T) {
			ctx := consentTestContextForLocale(t, file, lang)

			for _, scope := range definitions.HostedResourceScopes {
				messageID, ok := consentStandardScopeMessages[scope]
				if !ok {
					t.Fatalf("scope %q has no consent message", scope)
				}

				desc, ok := consentScopeDescription(ctx, nil, nil, nil, lang, scope)
				if !ok || desc == scope || desc == messageID {
					t.Fatalf("scope %q is not translated in %s: %q", scope, lang, desc)
				}
			}
		})
	}
}

// consentTestContextForLocale returns a Gin context whose localizer reads exactly one shipped resource file.
func consentTestContextForLocale(t *testing.T, file, lang string) *gin.Context {
	t.Helper()

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}

	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	if _, err = bundle.ParseMessageFileBytes(content, file); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer(bundle, lang))

	return ctx
}
