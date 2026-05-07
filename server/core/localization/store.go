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

import "sync/atomic"

// CatalogBuilder builds a complete effective catalog candidate for reload.
type CatalogBuilder func() (*EffectiveCatalog, error)

// CatalogStore publishes complete effective catalogs atomically.
type CatalogStore struct {
	active atomic.Pointer[EffectiveCatalog]
}

// NewCatalogStore returns a store initialized with the provided catalog.
func NewCatalogStore(initial *EffectiveCatalog) *CatalogStore {
	store := &CatalogStore{}
	if initial != nil {
		store.active.Store(initial)
	}

	return store
}

// Active returns the immutable request-time catalog.
func (s *CatalogStore) Active() *EffectiveCatalog {
	if s == nil {
		return nil
	}

	return s.active.Load()
}

// Activate publishes a fully built effective catalog.
func (s *CatalogStore) Activate(candidate *EffectiveCatalog) error {
	if candidate == nil {
		return ErrNilEffectiveCatalog
	}

	s.active.Store(candidate)

	return nil
}

// Reload builds a new catalog and activates it only after the build succeeds.
func (s *CatalogStore) Reload(build CatalogBuilder) error {
	candidate, err := build()
	if err != nil {
		return err
	}

	return s.Activate(candidate)
}
