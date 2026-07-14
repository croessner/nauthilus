// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package localizationfx

import (
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
)

type policyLocalizationCatalogProvider interface {
	GetPolicyLocalizationCatalogs() []config.PolicyTranslationCatalogConfig
}

// CatalogOverlays converts operator configuration into detached runtime overlays.
func CatalogOverlays(cfg config.File) []localization.CatalogOverlay {
	provider, ok := cfg.(policyLocalizationCatalogProvider)
	if !ok {
		return nil
	}

	catalogs := provider.GetPolicyLocalizationCatalogs()

	overlays := make([]localization.CatalogOverlay, 0, len(catalogs))

	for _, catalog := range catalogs {
		overlays = append(overlays, localization.CatalogOverlay{
			Namespace: catalog.Namespace,
			Entries: map[string]map[string]string{
				catalog.Language: catalog.Entries,
			},
		})
	}

	return localization.CloneCatalogOverlays(overlays)
}
