// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package localizationfx

import (
	"context"
	"errors"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/lualib"
)

var errCatalogRegistryUnavailable = errors.New("localization catalog registry is unavailable")

// Reloader atomically replaces the operator-owned localization layer.
type Reloader struct {
	registry func() *localization.CatalogRegistry
}

// NewReloader creates a localization reload component over a registry source.
func NewReloader(registry func() *localization.CatalogRegistry) *Reloader {
	return &Reloader{registry: registry}
}

// NewDefaultReloader creates the reload component for the process-wide Lua localization runtime.
func NewDefaultReloader() *Reloader {
	return NewReloader(func() *localization.CatalogRegistry {
		return lualib.DefaultI18NRuntime().Registry
	})
}

// Name returns the stable reload component name.
func (r *Reloader) Name() string {
	return "policy_localization"
}

// Order applies translations before policy snapshots are compiled.
func (r *Reloader) Order() int {
	return 15
}

// ApplyConfig builds and activates the operator catalog layer for a config snapshot.
func (r *Reloader) ApplyConfig(_ context.Context, snap configfx.Snapshot) error {
	if r == nil || r.registry == nil {
		return errCatalogRegistryUnavailable
	}

	registry := r.registry()
	if registry == nil {
		return errCatalogRegistryUnavailable
	}

	_, err := registry.ReloadOperatorOverlays(CatalogOverlays(snap.File)...)

	return err
}

var _ reloadfx.Reloadable = (*Reloader)(nil)
