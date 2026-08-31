// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"fmt"
	"slices"
	"sync"

	"github.com/croessner/nauthilus/v4/server/app/bootfx"
	"github.com/croessner/nauthilus/v4/server/config"
	corelanguage "github.com/croessner/nauthilus/v4/server/core/language"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// StartupCatalog owns the immutable startup-Lua localization layer and script baseline.
type StartupCatalog struct {
	overlays []localization.CatalogOverlay
	scripts  []bootfx.LuaInitScriptFingerprint
	system   corelanguage.SystemLocalizationFingerprint
	mu       sync.RWMutex
	pinned   bool
	captured bool
}

// NewStartupCatalog returns an initially unpublished startup catalog authority.
func NewStartupCatalog() *StartupCatalog {
	return &StartupCatalog{}
}

// provideStartupCatalog pins the exact source bytes loaded by the production language manager.
func provideStartupCatalog(manager corelanguage.Manager) (*StartupCatalog, error) {
	if manager == nil {
		return nil, fmt.Errorf("%w: system localization manager is nil", policyruntime.ErrInvalidGeneration)
	}

	provider, ok := manager.(corelanguage.SystemLocalizationFingerprintProvider)
	if !ok {
		return nil, fmt.Errorf(
			"%w: system localization manager does not expose its source fingerprint",
			policyruntime.ErrInvalidGeneration,
		)
	}

	return &StartupCatalog{
		system: provider.GetSystemLocalizationFingerprint().Clone(),
		pinned: true,
	}, nil
}

// Capture freezes successful startup overlays and the exact executed script baseline once.
func (c *StartupCatalog) Capture(
	configured config.File,
	preparation bootfx.LuaInitCatalogPreparation,
) error {
	if c == nil || configured == nil {
		return fmt.Errorf("%w: startup catalog dependencies are incomplete", policyruntime.ErrInvalidGeneration)
	}

	scripts := preparation.ScriptFingerprints()

	paths := configured.GetLuaInitScriptPaths()
	if !slices.Equal(startupScriptPaths(scripts), paths) {
		return fmt.Errorf("%w: startup Lua preparation paths do not match configuration", policyruntime.ErrInvalidGeneration)
	}

	artifacts, err := config.EnsureArtifactSnapshot(configured)
	if err != nil {
		return fmt.Errorf("%w: inspect prepared startup artifact snapshot: %v", pluginruntime.ErrRestartRequired, err)
	}

	if err = artifacts.ValidateLive(); err != nil {
		return fmt.Errorf("%w: inspect prepared startup artifacts: %v", pluginruntime.ErrRestartRequired, err)
	}

	candidate, err := bootfx.FingerprintPreparedLuaInitScripts(artifacts, paths)
	if err != nil {
		return fmt.Errorf("%w: inspect prepared startup Lua scripts: %v", pluginruntime.ErrRestartRequired, err)
	}

	if !slices.Equal(scripts, candidate) {
		return fmt.Errorf("%w: startup Lua script content changed during preparation", pluginruntime.ErrRestartRequired)
	}

	return c.capture(configured, preparation.CatalogOverlays(), scripts)
}

// capture freezes validated startup overlays, script fingerprints, and system localization once.
func (c *StartupCatalog) capture(
	configured config.File,
	overlays []localization.CatalogOverlay,
	scripts []bootfx.LuaInitScriptFingerprint,
) error {
	if c == nil || configured == nil {
		return fmt.Errorf("%w: startup catalog dependencies are incomplete", policyruntime.ErrInvalidGeneration)
	}

	system, err := corelanguage.CaptureSystemLocalizationFingerprint(configured)
	if err != nil {
		return fmt.Errorf("capture system localization baseline: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.captured {
		return fmt.Errorf("%w: startup catalog is already captured", policyruntime.ErrInvalidGeneration)
	}

	if c.pinned {
		if err = validateSystemLocalizationFingerprint(c.system, system); err != nil {
			return err
		}
	} else {
		c.system = system.Clone()
	}

	c.overlays = localization.CloneCatalogOverlays(overlays)

	c.scripts = append([]bootfx.LuaInitScriptFingerprint(nil), scripts...)
	c.captured = true

	return nil
}

// overlaysForCandidate validates restart-bound scripts and returns detached frozen overlays.
func (c *StartupCatalog) overlaysForCandidate(configured config.File) ([]localization.CatalogOverlay, error) {
	if c == nil || configured == nil {
		return nil, fmt.Errorf("%w: startup catalog dependencies are incomplete", policyruntime.ErrInvalidGeneration)
	}

	c.mu.RLock()

	if !c.captured {
		c.mu.RUnlock()

		return nil, fmt.Errorf("%w: startup catalog has not been captured", policyruntime.ErrInvalidGeneration)
	}

	baseline := append([]bootfx.LuaInitScriptFingerprint(nil), c.scripts...)
	system := c.system.Clone()
	overlays := localization.CloneCatalogOverlays(c.overlays)
	c.mu.RUnlock()

	paths := configured.GetLuaInitScriptPaths()
	if !slices.Equal(startupScriptPaths(baseline), paths) {
		return nil, fmt.Errorf("%w: startup Lua script paths changed", pluginruntime.ErrRestartRequired)
	}

	artifacts, err := config.EnsureArtifactSnapshot(configured)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect startup artifact snapshot: %v", pluginruntime.ErrRestartRequired, err)
	}

	if err = artifacts.ValidateLive(); err != nil {
		return nil, fmt.Errorf("%w: inspect startup artifacts: %w", pluginruntime.ErrRestartRequired, err)
	}

	candidate, err := bootfx.FingerprintPreparedLuaInitScripts(artifacts, paths)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect startup Lua scripts: %v", pluginruntime.ErrRestartRequired, err)
	}

	if !slices.Equal(baseline, candidate) {
		return nil, fmt.Errorf("%w: startup Lua script content changed", pluginruntime.ErrRestartRequired)
	}

	candidateSystem, err := corelanguage.CaptureSystemLocalizationFingerprint(configured)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: inspect system localization resources: %v",
			pluginruntime.ErrRestartRequired,
			err,
		)
	}

	if err = validateSystemLocalizationFingerprint(system, candidateSystem); err != nil {
		return nil, err
	}

	return overlays, nil
}

// validateSystemLocalizationFingerprint rejects every candidate that differs from the live system catalog source.
func validateSystemLocalizationFingerprint(
	baseline corelanguage.SystemLocalizationFingerprint,
	candidate corelanguage.SystemLocalizationFingerprint,
) error {
	if baseline.ResourcePath != candidate.ResourcePath {
		return fmt.Errorf("%w: system localization resource path changed", pluginruntime.ErrRestartRequired)
	}

	if !slices.Equal(baseline.ConfiguredLanguages, candidate.ConfiguredLanguages) ||
		!slices.Equal(baseline.EffectiveLanguages, candidate.EffectiveLanguages) {
		return fmt.Errorf("%w: system localization languages changed", pluginruntime.ErrRestartRequired)
	}

	if baseline.DefaultLanguage != candidate.DefaultLanguage {
		return fmt.Errorf("%w: system localization default language changed", pluginruntime.ErrRestartRequired)
	}

	if !slices.Equal(baseline.Resources, candidate.Resources) {
		return fmt.Errorf("%w: system localization resource content changed", pluginruntime.ErrRestartRequired)
	}

	return nil
}

// startupScriptPaths returns the exact ordered path projection from fingerprints.
func startupScriptPaths(fingerprints []bootfx.LuaInitScriptFingerprint) []string {
	paths := make([]string, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		paths = append(paths, fingerprint.Path())
	}

	return paths
}
