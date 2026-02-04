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

package language

import (
	"fmt"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	jsoniter "github.com/json-iterator/go"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

var json = jsoniter.ConfigFastest

// Manager defines the interface for managing language bundles and matching.
type Manager interface {
	GetBundle() *i18n.Bundle
	GetMatcher() language.Matcher
	GetTags() []language.Tag
}

type manager struct {
	bundle  *i18n.Bundle
	matcher language.Matcher
	tags    []language.Tag
}

// NewManager creates a new Manager instance and loads the language bundles.
func NewManager(cfg config.File, _ *slog.Logger) (Manager, error) {
	m := &manager{
		bundle: i18n.NewBundle(language.English),
	}

	m.bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	langs := cfg.GetServer().Frontend.GetLanguages()
	if len(langs) == 0 {
		for _, tag := range config.DefaultLanguageTags {
			langs = append(langs, tag.String())
		}
	}

	m.tags = make([]language.Tag, 0, len(langs))

	for _, lang := range langs {
		tag := language.Make(lang)
		m.tags = append(m.tags, tag)

		if err := m.loadLanguageBundle(cfg, lang); err != nil {
			return nil, fmt.Errorf("failed to load language bundle for %s: %w", lang, err)
		}
	}

	m.matcher = language.NewMatcher(m.tags)

	return m, nil
}

func (m *manager) loadLanguageBundle(cfg config.File, lang string) error {
	resourcePath := cfg.GetServer().Frontend.GetLanguageResources()
	if _, err := m.bundle.LoadMessageFile(resourcePath + "/" + lang + ".json"); err != nil {
		return err
	}

	return nil
}

// GetBundle returns the i18n bundle.
func (m *manager) GetBundle() *i18n.Bundle {
	return m.bundle
}

// GetMatcher returns the language matcher.
func (m *manager) GetMatcher() language.Matcher {
	return m.matcher
}

// GetTags returns the supported language tags.
func (m *manager) GetTags() []language.Tag {
	return m.tags
}
