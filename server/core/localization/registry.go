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
	"maps"
	"sync"
)

// CatalogRegistry owns deployment overlays and publishes effective catalogs.
type CatalogRegistry struct {
	system           Catalog
	store            *CatalogStore
	startupOverlays  []CatalogOverlay
	operatorOverlays []CatalogOverlay
	mu               sync.Mutex
}

// NewCatalogRegistry creates a registry with an atomically published initial catalog.
func NewCatalogRegistry(system Catalog, overlays ...CatalogOverlay) (*CatalogRegistry, error) {
	detached := cloneCatalogOverlays(overlays)

	effective, _, err := NewEffectiveCatalog(system, detached...)
	if err != nil {
		return nil, err
	}

	return &CatalogRegistry{
		system:          system,
		store:           NewCatalogStore(effective),
		startupOverlays: detached,
	}, nil
}

// Active returns the currently published immutable catalog.
func (r *CatalogRegistry) Active() *EffectiveCatalog {
	if r == nil || r.store == nil {
		return nil
	}

	return r.store.Active()
}

// RegisterOverlay adds one deployment overlay and activates the resulting catalog atomically.
func (r *CatalogRegistry) RegisterOverlay(overlay CatalogOverlay) ([]CatalogOverride, error) {
	return r.RegisterOverlays(overlay)
}

// RegisterOverlays adds deployment overlays and activates the resulting catalog atomically.
func (r *CatalogRegistry) RegisterOverlays(overlays ...CatalogOverlay) ([]CatalogOverride, error) {
	if r == nil {
		return nil, ErrNilCatalog
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	next, effective, overrides, err := r.candidateWithLocked(overlays)
	if err != nil {
		return nil, err
	}

	if err := r.store.Activate(effective); err != nil {
		return nil, err
	}

	r.startupOverlays = next

	return overrides, nil
}

// ValidateAdditionalOverlays builds a candidate catalog without activating it.
func (r *CatalogRegistry) ValidateAdditionalOverlays(overlays ...CatalogOverlay) ([]CatalogOverride, error) {
	if r == nil {
		return nil, ErrNilCatalog
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_, _, overrides, err := r.candidateWithLocked(overlays)

	return overrides, err
}

// Reload replaces all startup overlays only after the complete catalog builds successfully.
func (r *CatalogRegistry) Reload(overlays ...CatalogOverlay) ([]CatalogOverride, error) {
	if r == nil {
		return nil, ErrNilCatalog
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	next := cloneCatalogOverlays(overlays)

	effective, overrides, err := r.buildEffectiveLocked(next, r.operatorOverlays)
	if err != nil {
		return nil, err
	}

	if err := r.store.Activate(effective); err != nil {
		return nil, err
	}

	r.startupOverlays = next

	return overrides, nil
}

// ReloadOperatorOverlays atomically replaces only operator-configured overlays.
func (r *CatalogRegistry) ReloadOperatorOverlays(overlays ...CatalogOverlay) ([]CatalogOverride, error) {
	if r == nil {
		return nil, ErrNilCatalog
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	next := cloneCatalogOverlays(overlays)

	effective, overrides, err := r.buildEffectiveLocked(r.startupOverlays, next)
	if err != nil {
		return nil, err
	}

	if err := r.store.Activate(effective); err != nil {
		return nil, err
	}

	r.operatorOverlays = next

	return overrides, nil
}

// candidateWithLocked builds a detached startup-layer candidate while the registry lock is held.
func (r *CatalogRegistry) candidateWithLocked(overlays []CatalogOverlay) ([]CatalogOverlay, *EffectiveCatalog, []CatalogOverride, error) {
	next := append(cloneCatalogOverlays(r.startupOverlays), cloneCatalogOverlays(overlays)...)

	effective, overrides, err := r.buildEffectiveLocked(next, r.operatorOverlays)
	if err != nil {
		return nil, nil, nil, err
	}

	return next, effective, overrides, nil
}

// buildEffectiveLocked builds the fixed system, startup, then operator precedence chain.
func (r *CatalogRegistry) buildEffectiveLocked(
	startupOverlays []CatalogOverlay,
	operatorOverlays []CatalogOverlay,
) (*EffectiveCatalog, []CatalogOverride, error) {
	overlays := append(cloneCatalogOverlays(startupOverlays), cloneCatalogOverlays(operatorOverlays)...)

	return NewEffectiveCatalog(r.system, overlays...)
}

func cloneCatalogOverlays(overlays []CatalogOverlay) []CatalogOverlay {
	return CloneCatalogOverlays(overlays)
}

// CloneCatalogOverlays returns detached catalog overlay copies.
func CloneCatalogOverlays(overlays []CatalogOverlay) []CatalogOverlay {
	if len(overlays) == 0 {
		return nil
	}

	cloned := make([]CatalogOverlay, 0, len(overlays))
	for _, overlay := range overlays {
		cloned = append(cloned, CloneCatalogOverlay(overlay))
	}

	return cloned
}

// CloneCatalogOverlay returns a detached catalog overlay copy.
func CloneCatalogOverlay(overlay CatalogOverlay) CatalogOverlay {
	return CatalogOverlay{
		Entries:   cloneCatalogEntries(overlay.Entries),
		Namespace: overlay.Namespace,
	}
}

func cloneCatalogEntries(entries map[string]map[string]string) map[string]map[string]string {
	if len(entries) == 0 {
		return nil
	}

	cloned := make(map[string]map[string]string, len(entries))
	for languageName, messages := range entries {
		cloned[languageName] = make(map[string]string, len(messages))
		maps.Copy(cloned[languageName], messages)
	}

	return cloned
}
