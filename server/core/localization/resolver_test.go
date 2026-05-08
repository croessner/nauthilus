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
	"errors"
	"testing"

	"golang.org/x/text/language"
)

const (
	testResponseKey      = "auth.policy.company.account_blocked"
	testFallbackMessage  = "Login failed because the account is locked."
	testLocalizedGerman  = "Anmeldung abgelehnt."
	testLocalizedEnglish = "Login denied."
	testSystemEnglish    = "system english"
)

func TestResolverUsesLanguagePreferenceChain(t *testing.T) {
	catalog := testEffectiveCatalog(t)
	resolver := NewResolver(catalog, "en")

	tests := []struct {
		preference LanguagePreference
		name       string
		wantText   string
		wantLang   string
	}{
		{
			name: "explicit language overrides policy and header",
			preference: LanguagePreference{
				Explicit: "de",
				Policy:   "en",
				Header:   "en;q=1.0,de;q=0.2",
			},
			wantText: testLocalizedGerman,
			wantLang: "de",
		},
		{
			name: "policy language overrides header",
			preference: LanguagePreference{
				Policy: "de",
				Header: "en;q=1.0,de;q=0.2",
			},
			wantText: testLocalizedGerman,
			wantLang: "de",
		},
		{
			name: "weighted header resolves preferred supported language",
			preference: LanguagePreference{
				Header: "de;q=0.2,en;q=0.9",
			},
			wantText: testLocalizedEnglish,
			wantLang: "en",
		},
		{
			name: "invalid and unsupported preferences fall back to default",
			preference: LanguagePreference{
				Explicit: "not a language",
				Policy:   "fr",
				Header:   "zz;q=1.0",
			},
			wantText: testLocalizedEnglish,
			wantLang: "en",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertResolvedPreference(t, resolver, tt.preference, tt.wantText, tt.wantLang)
		})
	}
}

func TestResolverUsesFallbackForMissingKeyAndLimitsLocalizedText(t *testing.T) {
	catalog := mustBuildCatalog(
		t,
		NewMapCatalog(map[string]map[string]string{
			"en": {
				testResponseKey: "localized text that must be truncated",
			},
		}),
	)
	resolver := NewResolver(catalog, "en")

	resolved := resolver.ResolveStatusMessage(
		context.Background(),
		StatusMessage{
			Text:      testFallbackMessage,
			I18NKey:   "auth.policy.company.unknown",
			MaxLength: 11,
		},
		LanguagePreference{Default: "en"},
	)

	if resolved.Text != "Login faile" {
		t.Fatalf("fallback text = %q, want truncated fallback", resolved.Text)
	}

	if resolved.Localized {
		t.Fatal("missing key was marked localized")
	}

	if !resolved.FallbackUsed {
		t.Fatal("missing key did not report fallback usage")
	}

	resolved = resolver.ResolveStatusMessage(
		context.Background(),
		StatusMessage{
			Text:      testFallbackMessage,
			I18NKey:   testResponseKey,
			MaxLength: 14,
		},
		LanguagePreference{Default: "en"},
	)

	if resolved.Text != "localized text" {
		t.Fatalf("localized text = %q, want truncated localized text", resolved.Text)
	}

	if !resolved.Localized {
		t.Fatal("existing key was not marked localized")
	}
}

func TestEffectiveCatalogAppliesDeploymentOverlaysDeterministically(t *testing.T) {
	system := NewMapCatalog(map[string]map[string]string{
		"en": {
			testResponseKey: testSystemEnglish,
		},
		"de": {
			testResponseKey: "system german",
		},
	})

	first := CatalogOverlay{
		Namespace: "company-base",
		Entries: map[string]map[string]string{
			"de": {
				testResponseKey: "deployment german",
			},
		},
	}
	second := CatalogOverlay{
		Namespace: "company-final",
		Entries: map[string]map[string]string{
			"de": {
				testResponseKey: "final german",
			},
		},
	}

	catalog, overrides, err := NewEffectiveCatalog(system, first, second)
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}

	got, ok := catalog.Lookup(mustLanguageTag(t, "de"), testResponseKey)
	if !ok {
		t.Fatal("merged catalog did not resolve deployment key")
	}

	if got != "final german" {
		t.Fatalf("german text = %q, want final overlay", got)
	}

	got, ok = catalog.Lookup(mustLanguageTag(t, "en"), testResponseKey)
	if !ok {
		t.Fatal("merged catalog did not resolve system key")
	}

	if got != testSystemEnglish {
		t.Fatalf("english text = %q, want system catalog", got)
	}

	if len(overrides) != 2 {
		t.Fatalf("overrides = %#v, want two override records", overrides)
	}

	if overrides[0].Namespace != "company-base" || overrides[1].Namespace != "company-final" {
		t.Fatalf("override order = %#v, want overlay order", overrides)
	}
}

func TestEffectiveCatalogIsFrozenForRequestTime(t *testing.T) {
	systemEntries := map[string]map[string]string{
		"en": {
			testResponseKey: testSystemEnglish,
		},
	}
	overlayEntries := map[string]map[string]string{
		"en": {
			testResponseKey: "deployment english",
		},
	}

	catalog := mustBuildCatalog(
		t,
		NewMapCatalog(systemEntries),
		CatalogOverlay{
			Namespace: "company",
			Entries:   overlayEntries,
		},
	)

	systemEntries["en"][testResponseKey] = "mutated system"
	overlayEntries["en"][testResponseKey] = "mutated overlay"

	got, ok := catalog.Lookup(mustLanguageTag(t, "en"), testResponseKey)
	if !ok {
		t.Fatal("frozen catalog did not resolve key")
	}

	if got != "deployment english" {
		t.Fatalf("frozen text = %q, want original deployment value", got)
	}
}

func TestCatalogStoreKeepsPreviousCatalogOnFailedReload(t *testing.T) {
	initial := testEffectiveCatalog(t)
	store := NewCatalogStore(initial)

	err := store.Reload(func() (*EffectiveCatalog, error) {
		return nil, errors.New("reload failed")
	})
	if err == nil {
		t.Fatal("failed reload succeeded")
	}

	resolved, ok := store.Active().Lookup(mustLanguageTag(t, "de"), testResponseKey)
	if !ok {
		t.Fatal("active catalog lost previous key after failed reload")
	}

	if resolved != testLocalizedGerman {
		t.Fatalf("active catalog text = %q, want previous catalog", resolved)
	}

	next := mustBuildCatalog(
		t,
		NewMapCatalog(map[string]map[string]string{
			"en": {
				testResponseKey: "new english",
			},
		}),
	)

	if err := store.Reload(func() (*EffectiveCatalog, error) {
		return next, nil
	}); err != nil {
		t.Fatalf("successful reload failed: %v", err)
	}

	resolved, ok = store.Active().Lookup(mustLanguageTag(t, "en"), testResponseKey)
	if !ok {
		t.Fatal("active catalog did not expose reloaded key")
	}

	if resolved != "new english" {
		t.Fatalf("active catalog text = %q, want reloaded catalog", resolved)
	}
}

func testEffectiveCatalog(t *testing.T) *EffectiveCatalog {
	t.Helper()

	return mustBuildCatalog(
		t,
		NewMapCatalog(map[string]map[string]string{
			"en": {
				testResponseKey: testLocalizedEnglish,
			},
			"de": {
				testResponseKey: testLocalizedGerman,
			},
		}),
	)
}

func mustBuildCatalog(t *testing.T, system Catalog, overlays ...CatalogOverlay) *EffectiveCatalog {
	t.Helper()

	catalog, _, err := NewEffectiveCatalog(system, overlays...)
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}

	return catalog
}

func assertResolvedPreference(
	t *testing.T,
	resolver *Resolver,
	preference LanguagePreference,
	wantText string,
	wantLanguage string,
) {
	t.Helper()

	resolved := resolver.ResolveStatusMessage(
		context.Background(),
		StatusMessage{
			Text:    testFallbackMessage,
			I18NKey: testResponseKey,
		},
		preference,
	)

	if resolved.Text != wantText {
		t.Fatalf("text = %q, want %q", resolved.Text, wantText)
	}

	if resolved.Language != wantLanguage {
		t.Fatalf("language = %q, want %q", resolved.Language, wantLanguage)
	}

	if !resolved.Localized {
		t.Fatal("message was not marked localized")
	}
}

func mustLanguageTag(t *testing.T, value string) language.Tag {
	t.Helper()

	tag, err := language.Parse(value)
	if err != nil {
		t.Fatalf("parse language tag: %v", err)
	}

	return tag
}
