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

package devui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

type mockLangManager struct {
	corelang.Manager
}

func (m *mockLangManager) GetTags() []language.Tag {
	return []language.Tag{language.English}
}

func (m *mockLangManager) GetMatcher() language.Matcher {
	return language.NewMatcher(m.GetTags())
}

func (m *mockLangManager) GetBundle() *i18n.Bundle {
	return i18n.NewBundle(language.English)
}

func TestDevUIHandler_GetVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	r := gin.New()

	env := config.NewTestEnvironmentConfig()
	h := &DevUIHandler{
		deps: &deps.Deps{
			Cfg:         &config.FileSettings{},
			Env:         env,
			LangManager: &mockLangManager{},
		},
		version: 12345,
	}

	h.Register(r)

	req := httptest.NewRequest(http.MethodGet, "/dev/ui/version", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]int64

	err := json.Unmarshal(w.Body.Bytes(), &resp)

	assert.NoError(t, err)
	assert.Equal(t, int64(12345), resp["version"])
}

func TestDevUIHandler_Index(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	r := gin.New()

	env := config.NewTestEnvironmentConfig()
	h := &DevUIHandler{
		deps: &deps.Deps{
			Cfg:         &config.FileSettings{},
			Env:         env,
			LangManager: &mockLangManager{},
		},
		version: 12345,
	}

	h.Register(r)

	req := httptest.NewRequest(http.MethodGet, "/dev/ui", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Nauthilus Dev UI")
	assert.Contains(t, w.Body.String(), "admin_login.html")
	assert.Contains(t, w.Body.String(), "admin_layout.html")
	assert.Contains(t, w.Body.String(), "admin_dashboard.html")
	assert.Contains(t, w.Body.String(), "partials_bruteforce.html")
	assert.Contains(t, w.Body.String(), "partials_clickhouse.html")
	assert.Contains(t, w.Body.String(), "partials_hooktester.html")
	assert.Contains(t, w.Body.String(), "idp_login.html")
	assert.Contains(t, w.Body.String(), "idp_saml_post.html")
	assert.Contains(t, w.Body.String(), "12345")
}

func TestDevUIHandler_RenderTemplate_AdminPartialWrapped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	templatePath, err := testTemplatePath()
	assert.NoError(t, err)

	r := gin.New()

	env := config.NewTestEnvironmentConfig()
	h := &DevUIHandler{
		deps: &deps.Deps{
			Cfg: &config.FileSettings{
				Server: &config.ServerSection{
					Frontend: config.Frontend{
						HTMLStaticContentPath: templatePath,
					},
				},
			},
			Env:         env,
			LangManager: &mockLangManager{},
		},
		version: 12345,
	}

	h.Register(r)

	req := httptest.NewRequest(http.MethodGet, "/dev/ui/render/partials_bruteforce.html/en", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/static/css/daisyui.min.css")
	assert.Contains(t, w.Body.String(), "/static/js/admin_ui.js")
}

func testTemplatePath() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	return filepath.Clean(filepath.Join(wd, "../../../static/templates")), nil
}
