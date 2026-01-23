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
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

type mockI18nConfig struct {
	config.File
	defaultLang string
}

func (m *mockI18nConfig) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Frontend: config.Frontend{
			DefaultLanguage: m.defaultLang,
		},
	}
}

func TestSetLanguageDetails(t *testing.T) {
	cfg := &mockI18nConfig{defaultLang: "en"}

	tests := []struct {
		name         string
		urlLang      string
		cookieLang   string
		wantLang     string
		wantCookie   bool
		wantRedirect bool
	}{
		{"NoUrlNoCookie", "", "", "en", true, true},
		{"NoUrlWithCookie", "", "de", "de", false, true},
		{"WithUrlNoCookie", "fr", "", "fr", true, false},
		{"WithUrlWithSameCookie", "de", "de", "de", false, false},
		{"WithUrlWithDifferentCookie", "de", "en", "de", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang, needCookie, needRedirect := setLanguageDetails(cfg, tt.urlLang, tt.cookieLang)
			assert.Equal(t, tt.wantLang, lang)
			assert.Equal(t, tt.wantCookie, needCookie)
			assert.Equal(t, tt.wantRedirect, needRedirect)
		})
	}
}
