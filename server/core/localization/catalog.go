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

// Package localization contains transport-neutral policy message localization.
package localization

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	corelang "github.com/croessner/nauthilus/server/core/language"
	goi18n "github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

var (
	// ErrNilCatalog is returned when a required catalog dependency is missing.
	ErrNilCatalog = errors.New("localization catalog is nil")

	// ErrNilEffectiveCatalog is returned when activation receives no effective catalog.
	ErrNilEffectiveCatalog = errors.New("effective localization catalog is nil")
)

// Catalog resolves localized messages for one immutable catalog view.
type Catalog interface {
	Lookup(tag language.Tag, key string) (string, bool)
	Tags() []language.Tag
}

// CatalogOverlay contains deployment-owned translation entries.
type CatalogOverlay struct {
	Entries   map[string]map[string]string
	Namespace string
}

// CatalogOverride reports an entry replaced by a deployment overlay.
type CatalogOverride struct {
	Language          string
	Key               string
	Namespace         string
	PreviousNamespace string
}

type catalogEntry struct {
	text      string
	namespace string
}

// MapCatalog is an immutable in-memory catalog for tests and deployment overlays.
type MapCatalog struct {
	entries map[string]map[string]string
	tags    []language.Tag
}

// NewMapCatalog returns a detached in-memory catalog from language-key entries.
func NewMapCatalog(entries map[string]map[string]string) *MapCatalog {
	cloned, tags := cloneStringCatalog(entries)

	return &MapCatalog{
		entries: cloned,
		tags:    tags,
	}
}

// Lookup returns a message for an exact catalog language tag and key.
func (c *MapCatalog) Lookup(tag language.Tag, key string) (string, bool) {
	if c == nil {
		return "", false
	}

	messages := c.entries[tag.String()]
	if messages == nil {
		return "", false
	}

	message, ok := messages[key]

	return message, ok
}

// Tags returns the supported language tags.
func (c *MapCatalog) Tags() []language.Tag {
	if c == nil {
		return nil
	}

	return append([]language.Tag(nil), c.tags...)
}

// ManagerCatalog adapts the existing language manager as a system catalog.
type ManagerCatalog struct {
	manager corelang.Manager
}

// NewManagerCatalog returns a catalog backed by the existing language manager.
func NewManagerCatalog(manager corelang.Manager) *ManagerCatalog {
	return &ManagerCatalog{manager: manager}
}

// Lookup resolves a message only when it exists in the selected language.
func (c *ManagerCatalog) Lookup(tag language.Tag, key string) (string, bool) {
	if c == nil || c.manager == nil || c.manager.GetBundle() == nil {
		return "", false
	}

	localizer := goi18n.NewLocalizer(c.manager.GetBundle(), tag.String())
	message, resolvedTag, err := localizer.LocalizeWithTag(&goi18n.LocalizeConfig{MessageID: key})
	if err != nil || resolvedTag != tag {
		return "", false
	}

	return message, true
}

// Tags returns the language manager's supported language tags.
func (c *ManagerCatalog) Tags() []language.Tag {
	if c == nil || c.manager == nil {
		return nil
	}

	return append([]language.Tag(nil), c.manager.GetTags()...)
}

// EffectiveCatalog is the frozen request-time catalog view.
type EffectiveCatalog struct {
	system  Catalog
	entries map[string]map[string]catalogEntry
	tags    []language.Tag
}

// NewEffectiveCatalog merges the system catalog with deployment overlays.
func NewEffectiveCatalog(system Catalog, overlays ...CatalogOverlay) (*EffectiveCatalog, []CatalogOverride, error) {
	if system == nil {
		return nil, nil, ErrNilCatalog
	}

	builder := effectiveCatalogBuilder{
		system:  system,
		entries: make(map[string]map[string]catalogEntry),
		tagSet:  make(map[string]language.Tag),
	}
	builder.addTags(system.Tags())

	overrides, err := builder.applyOverlays(overlays)
	if err != nil {
		return nil, nil, err
	}

	return &EffectiveCatalog{
		system:  system,
		entries: builder.entries,
		tags:    sortedTags(builder.tagSet),
	}, overrides, nil
}

// Lookup returns the effective message for the selected language and key.
func (c *EffectiveCatalog) Lookup(tag language.Tag, key string) (string, bool) {
	if c == nil {
		return "", false
	}

	if messages := c.entries[tag.String()]; messages != nil {
		if entry, ok := messages[key]; ok {
			return entry.text, true
		}
	}

	return c.system.Lookup(tag, key)
}

// Tags returns the effective supported language tags.
func (c *EffectiveCatalog) Tags() []language.Tag {
	if c == nil {
		return nil
	}

	return append([]language.Tag(nil), c.tags...)
}

type effectiveCatalogBuilder struct {
	system  Catalog
	entries map[string]map[string]catalogEntry
	tagSet  map[string]language.Tag
}

func (b *effectiveCatalogBuilder) applyOverlays(overlays []CatalogOverlay) ([]CatalogOverride, error) {
	var overrides []CatalogOverride

	for _, overlay := range overlays {
		applied, err := b.applyOverlay(overlay)
		if err != nil {
			return nil, err
		}

		overrides = append(overrides, applied...)
	}

	return overrides, nil
}

func (b *effectiveCatalogBuilder) applyOverlay(overlay CatalogOverlay) ([]CatalogOverride, error) {
	var overrides []CatalogOverride

	namespace := strings.TrimSpace(overlay.Namespace)
	for _, languageName := range sortedKeys(overlay.Entries) {
		tag, err := parseCatalogLanguage(languageName)
		if err != nil {
			return nil, err
		}

		languageKey := tag.String()
		b.tagSet[languageKey] = tag
		if b.entries[languageKey] == nil {
			b.entries[languageKey] = make(map[string]catalogEntry)
		}

		for _, key := range sortedKeys(overlay.Entries[languageName]) {
			catalogKey := strings.TrimSpace(key)
			if catalogKey == "" {
				return nil, fmt.Errorf("catalog overlay %q has an empty key for language %q", namespace, languageKey)
			}

			if previousNamespace, ok := b.previousNamespace(tag, catalogKey); ok {
				overrides = append(overrides, CatalogOverride{
					Language:          languageKey,
					Key:               catalogKey,
					Namespace:         namespace,
					PreviousNamespace: previousNamespace,
				})
			}

			b.entries[languageKey][catalogKey] = catalogEntry{
				text:      overlay.Entries[languageName][key],
				namespace: namespace,
			}
		}
	}

	return overrides, nil
}

func (b *effectiveCatalogBuilder) previousNamespace(tag language.Tag, key string) (string, bool) {
	if messages := b.entries[tag.String()]; messages != nil {
		if previous, ok := messages[key]; ok {
			return previous.namespace, true
		}
	}

	if _, ok := b.system.Lookup(tag, key); ok {
		return "system", true
	}

	return "", false
}

func (b *effectiveCatalogBuilder) addTags(tags []language.Tag) {
	for _, tag := range tags {
		b.tagSet[tag.String()] = tag
	}
}

func parseCatalogLanguage(value string) (language.Tag, error) {
	tag, err := language.Parse(strings.TrimSpace(value))
	if err != nil {
		return language.Und, fmt.Errorf("catalog language %q is invalid: %w", value, err)
	}

	return tag, nil
}

func cloneStringCatalog(entries map[string]map[string]string) (map[string]map[string]string, []language.Tag) {
	cloned := make(map[string]map[string]string, len(entries))
	tagSet := make(map[string]language.Tag, len(entries))

	for _, languageName := range sortedKeys(entries) {
		tag := language.Make(languageName)
		languageKey := tag.String()
		tagSet[languageKey] = tag
		cloned[languageKey] = make(map[string]string, len(entries[languageName]))

		maps.Copy(cloned[languageKey], entries[languageName])
	}

	return cloned, sortedTags(tagSet)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func sortedTags(tags map[string]language.Tag) []language.Tag {
	keys := sortedKeys(tags)
	output := make([]language.Tag, 0, len(keys))
	for _, key := range keys {
		output = append(output, tags[key])
	}

	return output
}
