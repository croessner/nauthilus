// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package localization

import (
	"testing"

	"golang.org/x/text/language"
)

const layeredCatalogKey = "auth.policy.rns.account_disabled"

func TestCatalogRegistryOperatorReloadPreservesStartupOverlays(t *testing.T) {
	registry, err := NewCatalogRegistry(NewMapCatalog(map[string]map[string]string{
		"en": {layeredCatalogKey: "system"},
	}))
	if err != nil {
		t.Fatalf("NewCatalogRegistry() error = %v", err)
	}

	_, err = registry.RegisterOverlay(CatalogOverlay{
		Namespace: "legacy-lua",
		Entries: map[string]map[string]string{
			"de": {layeredCatalogKey: "lua"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterOverlay() error = %v", err)
	}

	operator := CatalogOverlay{
		Namespace: "rns-auth",
		Entries: map[string]map[string]string{
			"de": {layeredCatalogKey: "operator"},
		},
	}

	if _, err = registry.ReloadOperatorOverlays(operator); err != nil {
		t.Fatalf("ReloadOperatorOverlays() error = %v", err)
	}

	operator.Entries["de"][layeredCatalogKey] = "mutated input"

	assertCatalogText(t, registry, "de", "operator")

	if _, err = registry.ReloadOperatorOverlays(); err != nil {
		t.Fatalf("clear operator overlays: %v", err)
	}

	assertCatalogText(t, registry, "de", "lua")
}

func TestCatalogRegistryFailedOperatorReloadKeepsCompleteCatalog(t *testing.T) {
	registry, err := NewCatalogRegistry(NewMapCatalog(nil))
	if err != nil {
		t.Fatalf("NewCatalogRegistry() error = %v", err)
	}

	if _, err = registry.RegisterOverlay(CatalogOverlay{
		Namespace: "legacy-lua",
		Entries: map[string]map[string]string{
			"de": {layeredCatalogKey: "lua"},
		},
	}); err != nil {
		t.Fatalf("RegisterOverlay() error = %v", err)
	}

	if _, err = registry.ReloadOperatorOverlays(CatalogOverlay{
		Namespace: "rns-auth",
		Entries: map[string]map[string]string{
			"de": {layeredCatalogKey: "operator"},
		},
	}); err != nil {
		t.Fatalf("initial operator reload: %v", err)
	}

	_, err = registry.ReloadOperatorOverlays(CatalogOverlay{
		Namespace: "invalid",
		Entries: map[string]map[string]string{
			"not a language": {layeredCatalogKey: "invalid"},
		},
	})
	if err == nil {
		t.Fatal("invalid operator reload succeeded")
	}

	assertCatalogText(t, registry, "de", "operator")
}

// assertCatalogText verifies one exact active catalog entry.
func assertCatalogText(t *testing.T, registry *CatalogRegistry, languageName string, want string) {
	t.Helper()

	got, ok := registry.Active().Lookup(language.Make(languageName), layeredCatalogKey)
	if !ok {
		t.Fatalf("active catalog missing %q for %q", layeredCatalogKey, languageName)
	}

	if got != want {
		t.Fatalf("active catalog text = %q, want %q", got, want)
	}
}
