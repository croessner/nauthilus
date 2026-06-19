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

package localization

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"golang.org/x/text/language"
)

// MessageResolver resolves policy-selected status messages at response boundaries.
type MessageResolver interface {
	ResolveStatusMessage(ctx context.Context, selection StatusMessage, preference LanguagePreference) ResolvedStatusMessage
}

// StatusMessage carries the policy-selected fallback text and optional catalog key.
type StatusMessage struct {
	Text      string
	I18NKey   string
	MaxLength int
}

// LanguagePreference describes the transport-neutral language preference chain.
type LanguagePreference struct {
	Explicit string
	Policy   string
	Header   string
	Tags     []string
	Default  string
}

// ResolvedStatusMessage contains the rendered response-boundary message.
type ResolvedStatusMessage struct {
	Text         string
	Language     string
	Key          string
	Localized    bool
	FallbackUsed bool
}

// Resolver resolves status messages through one immutable catalog view.
type Resolver struct {
	catalog         Catalog
	matcher         language.Matcher
	supported       []language.Tag
	defaultLanguage string
}

// RegistryResolver resolves against the currently active immutable catalog.
type RegistryResolver struct {
	registry        *CatalogRegistry
	defaultLanguage string
}

// NewResolver returns a resolver backed by the supplied effective catalog.
func NewResolver(catalog Catalog, defaultLanguage string) *Resolver {
	if strings.TrimSpace(defaultLanguage) == "" {
		defaultLanguage = definitions.DefaultLanguage
	}

	supported := catalogTags(catalog)

	return &Resolver{
		catalog:         catalog,
		matcher:         language.NewMatcher(supported),
		supported:       supported,
		defaultLanguage: strings.TrimSpace(defaultLanguage),
	}
}

// NewRegistryResolver returns a resolver that reads the active catalog per call.
func NewRegistryResolver(registry *CatalogRegistry, defaultLanguage string) *RegistryResolver {
	return &RegistryResolver{
		registry:        registry,
		defaultLanguage: strings.TrimSpace(defaultLanguage),
	}
}

// ResolveStatusMessage resolves through the registry's currently active catalog.
func (r *RegistryResolver) ResolveStatusMessage(
	ctx context.Context,
	selection StatusMessage,
	preference LanguagePreference,
) ResolvedStatusMessage {
	defaultLanguage := ""
	if r != nil {
		defaultLanguage = r.defaultLanguage
	}

	if r == nil || r.registry == nil {
		return NewResolver(nil, defaultLanguage).ResolveStatusMessage(ctx, selection, preference)
	}

	return NewResolver(r.registry.Active(), defaultLanguage).ResolveStatusMessage(ctx, selection, preference)
}

// ResolveStatusMessage resolves an i18n key or returns the bounded fallback text.
func (r *Resolver) ResolveStatusMessage(_ context.Context, selection StatusMessage, preference LanguagePreference) ResolvedStatusMessage {
	key := strings.TrimSpace(selection.I18NKey)
	if key == "" || r == nil || r.catalog == nil {
		return ResolvedStatusMessage{
			Text:         limitString(selection.Text, selection.MaxLength),
			Key:          key,
			FallbackUsed: true,
		}
	}

	selectedTag := r.selectLanguage(preference)

	languageName := selectedTag.String()
	if message, ok := r.catalog.Lookup(selectedTag, key); ok {
		return ResolvedStatusMessage{
			Text:      limitString(message, selection.MaxLength),
			Language:  languageName,
			Key:       key,
			Localized: true,
		}
	}

	return ResolvedStatusMessage{
		Text:         limitString(selection.Text, selection.MaxLength),
		Language:     languageName,
		Key:          key,
		FallbackUsed: true,
	}
}

func (r *Resolver) selectLanguage(preference LanguagePreference) language.Tag {
	if tag, ok := r.matchLanguage(preference.Explicit); ok {
		return tag
	}

	if tag, ok := r.matchLanguage(preference.Policy); ok {
		return tag
	}

	for _, preferred := range preference.Tags {
		if tag, ok := r.matchLanguage(preferred); ok {
			return tag
		}
	}

	if tag, ok := r.matchAcceptLanguage(preference.Header); ok {
		return tag
	}

	if tag, ok := r.matchLanguage(preference.Default); ok {
		return tag
	}

	if tag, ok := r.matchLanguage(r.defaultLanguage); ok {
		return tag
	}

	return language.Make(r.defaultLanguage)
}

func (r *Resolver) matchLanguage(value string) (language.Tag, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return language.Und, false
	}

	tag, err := language.Parse(value)
	if err != nil {
		return language.Und, false
	}

	return r.matchTag(tag)
}

func (r *Resolver) matchAcceptLanguage(value string) (language.Tag, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return language.Und, false
	}

	tags, _, err := language.ParseAcceptLanguage(value)
	if err != nil || len(tags) == 0 {
		return language.Und, false
	}

	matched, _, confidence := r.matcher.Match(tags...)
	if confidence == language.No {
		return language.Und, false
	}

	return matched, true
}

func (r *Resolver) matchTag(tag language.Tag) (language.Tag, bool) {
	if len(r.supported) == 0 {
		return tag, true
	}

	matched, _, confidence := r.matcher.Match(tag)
	if confidence == language.No {
		return language.Und, false
	}

	return matched, true
}

func catalogTags(catalog Catalog) []language.Tag {
	if catalog == nil {
		return nil
	}

	return catalog.Tags()
}

func limitString(value string, maxLength int) string {
	if maxLength <= 0 || utf8.RuneCountInString(value) <= maxLength {
		return value
	}

	var builder strings.Builder

	count := 0

	for _, r := range value {
		if count >= maxLength {
			break
		}

		builder.WriteRune(r)

		count++
	}

	return builder.String()
}
