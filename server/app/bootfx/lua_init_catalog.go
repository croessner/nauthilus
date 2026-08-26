// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package bootfx

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/hook"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	lua "github.com/yuin/gopher-lua"
)

// LuaInitScriptFingerprint identifies the configured path and exact captured source bytes.
type LuaInitScriptFingerprint struct {
	path   string
	digest [sha256.Size]byte
}

// Path returns the configured source path without exposing captured bytes.
func (f LuaInitScriptFingerprint) Path() string {
	return f.path
}

// Digest returns the exact captured source digest.
func (f LuaInitScriptFingerprint) Digest() [sha256.Size]byte {
	return f.digest
}

// LuaInitCatalogPreparation carries overlays and fingerprints from one exact source snapshot.
type LuaInitCatalogPreparation struct {
	overlays []localization.CatalogOverlay
	scripts  []LuaInitScriptFingerprint
}

// CatalogOverlays returns detached overlays produced by the captured scripts.
func (p LuaInitCatalogPreparation) CatalogOverlays() []localization.CatalogOverlay {
	return localization.CloneCatalogOverlays(p.overlays)
}

// ScriptFingerprints returns the ordered fingerprints paired with the executed prototypes.
func (p LuaInitCatalogPreparation) ScriptFingerprints() []LuaInitScriptFingerprint {
	return append([]LuaInitScriptFingerprint(nil), p.scripts...)
}

// preparedLuaInitScript pairs one compiled prototype with its exact source identity.
type preparedLuaInitScript struct {
	prototype   *lua.FunctionProto
	fingerprint LuaInitScriptFingerprint
}

// PrepareLuaInitCatalogs compiles and executes one immutable snapshot of every startup script.
func PrepareLuaInitCatalogs(
	ctx context.Context,
	cfg config.File,
	logger *slog.Logger,
	redis rediscli.Client,
	tolerance tolerate.Tolerate,
	system localization.Catalog,
) (LuaInitCatalogPreparation, error) {
	if ctx == nil || cfg == nil {
		return LuaInitCatalogPreparation{}, fmt.Errorf("startup Lua configuration is incomplete")
	}

	if system == nil {
		return LuaInitCatalogPreparation{}, localization.ErrNilCatalog
	}

	artifacts, err := config.EnsureArtifactSnapshot(cfg)
	if err != nil {
		return LuaInitCatalogPreparation{}, fmt.Errorf("seal startup Lua artifacts: %w", err)
	}

	modules, err := luaseal.CaptureSnapshot(config.EffectiveLuaPackagePatterns(cfg), artifacts)
	if err != nil {
		return LuaInitCatalogPreparation{}, fmt.Errorf("seal startup Lua modules: %w", err)
	}

	scripts, err := prepareLuaInitScripts(artifacts, cfg.GetLuaInitScriptPaths())
	if err != nil {
		return LuaInitCatalogPreparation{}, err
	}

	runtime, err := prepareLuaInitCatalogRuntime(cfg, logger, system)
	if err != nil {
		return LuaInitCatalogPreparation{}, err
	}

	if err = runPreparedLuaInitScripts(ctx, cfg, logger, redis, tolerance, modules, runtime, scripts); err != nil {
		return LuaInitCatalogPreparation{}, err
	}

	return LuaInitCatalogPreparation{
		overlays: runtime.CatalogSessionOverlays(),
		scripts:  preparedLuaInitFingerprints(scripts),
	}, nil
}

// prepareLuaInitCatalogRuntime creates a detached catalog session over the immutable system layer.
func prepareLuaInitCatalogRuntime(
	cfg config.File,
	logger *slog.Logger,
	system localization.Catalog,
) (*lualib.I18NRuntime, error) {
	registry, err := localization.NewCatalogRegistry(system)
	if err != nil {
		return nil, fmt.Errorf("prepare startup Lua catalog registry: %w", err)
	}

	defaultLanguage := cfg.GetServer().Frontend.GetDefaultLanguage()

	return lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{
		Registry: registry,
		Logger:   logger,
		DefaultPreference: localization.LanguagePreference{
			Default: defaultLanguage,
		},
		DefaultLanguage: defaultLanguage,
	}).NewCatalogSession(), nil
}

// runPreparedLuaInitScripts executes every prototype against the same sealed module snapshot.
func runPreparedLuaInitScripts(
	ctx context.Context,
	cfg config.File,
	logger *slog.Logger,
	redis rediscli.Client,
	tolerance tolerate.Tolerate,
	modules *luaseal.Modules,
	runtime *lualib.I18NRuntime,
	scripts []preparedLuaInitScript,
) error {
	for _, script := range scripts {
		path := script.fingerprint.Path()
		if err := hook.RunCompiledLuaInitWithI18NRuntime(
			ctx,
			cfg,
			logger,
			redis,
			tolerance,
			path,
			script.prototype,
			modules,
			runtime,
		); err != nil {
			return fmt.Errorf("run startup Lua script %q: %w", path, err)
		}
	}

	return nil
}

// FingerprintPreparedLuaInitScripts returns ordered digests from one sealed config snapshot.
func FingerprintPreparedLuaInitScripts(
	artifacts *config.ArtifactSnapshot,
	paths []string,
) ([]LuaInitScriptFingerprint, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	if artifacts == nil {
		return nil, fmt.Errorf("startup Lua artifact snapshot is nil")
	}

	fingerprints := make([]LuaInitScriptFingerprint, 0, len(paths))
	for _, path := range paths {
		fingerprint, err := artifacts.Fingerprint(path)
		if err != nil {
			return nil, fmt.Errorf("fingerprint startup Lua script %q: %w", path, err)
		}

		fingerprints = append(fingerprints, LuaInitScriptFingerprint{path: path, digest: fingerprint.Digest})
	}

	return fingerprints, nil
}

// prepareLuaInitScripts compiles every source from the same bytes used for its fingerprint.
func prepareLuaInitScripts(
	artifacts *config.ArtifactSnapshot,
	paths []string,
) ([]preparedLuaInitScript, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	scripts := make([]preparedLuaInitScript, 0, len(paths))
	for _, path := range paths {
		source, fingerprint, err := readLuaInitScript(artifacts, path)
		if err != nil {
			return nil, err
		}

		prototype, err := lualib.CompileLuaSource(path, source)
		clear(source)

		if err != nil {
			return nil, fmt.Errorf("compile startup Lua script %q: %w", path, err)
		}

		scripts = append(scripts, preparedLuaInitScript{
			prototype:   prototype,
			fingerprint: fingerprint,
		})
	}

	return scripts, nil
}

// readLuaInitScript returns one private byte snapshot and its matching digest.
func readLuaInitScript(
	artifacts *config.ArtifactSnapshot,
	path string,
) ([]byte, LuaInitScriptFingerprint, error) {
	if artifacts == nil {
		return nil, LuaInitScriptFingerprint{}, fmt.Errorf("read startup Lua script %q: artifact snapshot is nil", path)
	}

	source, err := artifacts.ReadFile(path)
	if err != nil {
		return nil, LuaInitScriptFingerprint{}, fmt.Errorf("read startup Lua script %q: %w", path, err)
	}

	return source, LuaInitScriptFingerprint{path: path, digest: sha256.Sum256(source)}, nil
}

// preparedLuaInitFingerprints detaches the ordered non-secret baseline from compiled scripts.
func preparedLuaInitFingerprints(scripts []preparedLuaInitScript) []LuaInitScriptFingerprint {
	fingerprints := make([]LuaInitScriptFingerprint, 0, len(scripts))
	for _, script := range scripts {
		fingerprints = append(fingerprints, script.fingerprint)
	}

	return fingerprints
}
