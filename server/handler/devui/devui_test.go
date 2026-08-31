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

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	corelang "github.com/croessner/nauthilus/v4/server/core/language"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/util"
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
	h := &Handler{
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
	h := &Handler{
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
	assert.Contains(t, w.Body.String(), "idp_login.html")
	assert.Contains(t, w.Body.String(), "idp_saml_post.html")
	assert.Contains(t, w.Body.String(), "12345")
}

func TestDevUIHandler_RenderTemplateUsesSealedTemplateAfterLiveMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	directory := t.TempDir()
	templatePath := filepath.Join(directory, "preview.html")
	writeDevUITemplateArtifact(t, templatePath, []byte(`{{ define "preview.html" }}sealed-preview{{ end }}`))

	cfg := &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		Enabled: true, HTMLStaticContentPath: directory,
	}}}

	snapshot, err := config.CaptureArtifactSnapshot(config.ProductionArtifactSnapshotSpec(cfg))
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	artifacts, err := core.PrepareRouteArtifacts(cfg, snapshot)
	if err != nil {
		t.Fatalf("PrepareRouteArtifacts() error = %v", err)
	}

	writeDevUITemplateArtifact(t, templatePath, []byte(`{{ define "preview.html" }}mutated-preview{{ end }}`))

	env := config.NewTestEnvironmentConfig()
	handler := &Handler{deps: &deps.Deps{
		Cfg: cfg, Env: env, LangManager: &mockLangManager{}, RouteArtifacts: artifacts,
	}}
	router := gin.New()
	router.GET("/render/:template", handler.RenderTemplate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/render/preview.html", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("GET preview status = %d, want %d", response.Code, http.StatusOK)
	}

	if got := response.Body.String(); got != "sealed-preview" {
		t.Fatalf("GET preview body = %q, want sealed template", got)
	}
}

// writeDevUITemplateArtifact replaces one test-owned preview template.
func writeDevUITemplateArtifact(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write DevUI template %q: %v", path, err)
	}
}
