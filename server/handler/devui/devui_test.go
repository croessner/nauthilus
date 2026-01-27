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
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/handler/deps"
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

	r := gin.New()

	h := &DevUIHandler{
		deps: &deps.Deps{
			Cfg:         &config.FileSettings{},
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

	r := gin.New()

	h := &DevUIHandler{
		deps: &deps.Deps{
			Cfg:         &config.FileSettings{},
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
	assert.Contains(t, w.Body.String(), "idp_login.html")
	assert.Contains(t, w.Body.String(), "12345")
}
