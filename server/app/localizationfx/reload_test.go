// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package localizationfx

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"

	"golang.org/x/text/language"
)

const reloadCatalogKey = "auth.policy.rns.account_disabled"

func TestReloaderAppliesCurrentOperatorCatalogWithoutReplacingStartupLayer(t *testing.T) {
	registry, err := localization.NewCatalogRegistry(localization.NewMapCatalog(nil))
	if err != nil {
		t.Fatalf("NewCatalogRegistry() error = %v", err)
	}

	if _, err = registry.RegisterOverlay(localization.CatalogOverlay{
		Namespace: "legacy-lua",
		Entries: map[string]map[string]string{
			"de": {reloadCatalogKey: "lua"},
		},
	}); err != nil {
		t.Fatalf("RegisterOverlay() error = %v", err)
	}

	reloader := NewReloader(func() *localization.CatalogRegistry { return registry })

	snapshot := configfx.Snapshot{File: localizationConfig("operator"), Version: 2}

	if err = reloader.ApplyConfig(context.Background(), snapshot); err != nil {
		t.Fatalf("ApplyConfig() error = %v", err)
	}

	assertReloadCatalogText(t, registry, "operator")

	if err = reloader.ApplyConfig(context.Background(), configfx.Snapshot{File: localizationConfig(""), Version: 3}); err != nil {
		t.Fatalf("clear operator config: %v", err)
	}

	assertReloadCatalogText(t, registry, "lua")
}

// localizationConfig builds one config snapshot with an optional operator message.
func localizationConfig(message string) *config.FileSettings {
	catalogs := []config.PolicyTranslationCatalogConfig(nil)
	if message != "" {
		catalogs = []config.PolicyTranslationCatalogConfig{
			{
				Entries:   map[string]string{reloadCatalogKey: message},
				Namespace: "rns-auth",
				Language:  "de",
			},
		}
	}

	return &config.FileSettings{
		Auth: &config.AuthSection{
			Policy: config.AuthPolicySection{
				Localization: config.PolicyLocalizationConfig{Catalogs: catalogs},
			},
		},
	}
}

// assertReloadCatalogText verifies one active German message.
func assertReloadCatalogText(t *testing.T, registry *localization.CatalogRegistry, want string) {
	t.Helper()

	got, ok := registry.Active().Lookup(language.German, reloadCatalogKey)
	if !ok || got != want {
		t.Fatalf("active catalog text = %q, found = %t, want %q", got, ok, want)
	}
}
