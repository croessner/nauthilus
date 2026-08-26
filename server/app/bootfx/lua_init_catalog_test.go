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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"

	"golang.org/x/text/language"
)

const startupCatalogTestKey = "auth.policy.company.startup"

func TestPrepareLuaInitCatalogsReturnsDetachedOverlaysWithoutGlobalPublication(t *testing.T) {
	scriptPath := writeLuaInitCatalogScript(t, `
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "en",
			namespace = "startup",
			entries = { ["auth.policy.company.startup"] = "Startup message." },
		})
	`)
	configured := luaInitCatalogConfig(scriptPath)

	retireLuaInitCatalogTest(t)

	system := localization.NewMapCatalog(map[string]map[string]string{
		"en": {startupCatalogTestKey: "System message."},
	})
	setLuaInitCatalogTestDefault(t, system)

	preparation, err := PrepareLuaInitCatalogs(
		context.Background(),
		configured,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
		system,
	)
	if err != nil {
		t.Fatalf("PrepareLuaInitCatalogs() error = %v", err)
	}

	overlays := preparation.CatalogOverlays()
	if len(overlays) != 1 {
		t.Fatalf("startup overlays = %d, want 1", len(overlays))
	}

	assertLuaInitCatalogText(t, lualib.DefaultI18NRuntime().Registry.Active(), "System message.")

	effective, _, err := localization.NewEffectiveCatalog(system, overlays...)
	if err != nil {
		t.Fatalf("NewEffectiveCatalog() error = %v", err)
	}

	assertLuaInitCatalogText(t, effective, "Startup message.")
}

func TestPrepareLuaInitCatalogsFailurePublishesNeitherPartialOverlayNorGenerationInput(t *testing.T) {
	firstPath := writeLuaInitCatalogScript(t, `
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "en",
			namespace = "startup",
			entries = { ["auth.policy.company.startup"] = "Partial message." },
		})
	`)
	secondPath := writeLuaInitCatalogScript(t, `error("startup failed")`)
	configured := luaInitCatalogConfig(firstPath, secondPath)

	retireLuaInitCatalogTest(t)

	system := localization.NewMapCatalog(map[string]map[string]string{
		"en": {startupCatalogTestKey: "System message."},
	})
	setLuaInitCatalogTestDefault(t, system)

	preparation, err := PrepareLuaInitCatalogs(
		context.Background(),
		configured,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
		system,
	)
	if err == nil {
		t.Fatal("PrepareLuaInitCatalogs() accepted a failing second startup script")
	}

	if overlays := preparation.CatalogOverlays(); len(overlays) != 0 {
		t.Fatalf("failed startup overlays = %d, want none", len(overlays))
	}

	assertLuaInitCatalogText(t, lualib.DefaultI18NRuntime().Registry.Active(), "System message.")
}

func TestPrepareLuaInitCatalogsPairsExecutionAndFingerprintFromOneSourceSnapshot(t *testing.T) {
	firstPath, secondPath, originalSecond := luaInitSnapshotFixture(t)
	configured := luaInitCatalogConfig(firstPath, secondPath)

	retireLuaInitCatalogTest(t)

	system := localization.NewMapCatalog(map[string]map[string]string{
		"en": {startupCatalogTestKey: "System message."},
	})

	preparation, err := PrepareLuaInitCatalogs(
		context.Background(),
		configured,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
		system,
	)
	if err != nil {
		t.Fatalf("PrepareLuaInitCatalogs() error = %v", err)
	}

	effective, _, err := localization.NewEffectiveCatalog(system, preparation.CatalogOverlays()...)
	if err != nil {
		t.Fatalf("NewEffectiveCatalog() error = %v", err)
	}

	assertLuaInitCatalogText(t, effective, "Captured message.")

	fingerprints := preparation.ScriptFingerprints()
	if len(fingerprints) != 2 {
		t.Fatalf("startup fingerprints = %d, want 2", len(fingerprints))
	}

	if fingerprints[1].Path() != secondPath || fingerprints[1].Digest() != sha256.Sum256(originalSecond) {
		t.Fatal("second startup fingerprint does not identify the bytes used for execution")
	}
}

// luaInitSnapshotFixture captures one script before a preceding script mutates its live file.
func luaInitSnapshotFixture(t *testing.T) (string, string, []byte) {
	t.Helper()

	secondPath := writeLuaInitCatalogScript(t, `
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "en",
			namespace = "startup",
			entries = { ["auth.policy.company.startup"] = "Captured message." },
		})
	`)

	originalSecond, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("read second startup fixture: %v", err)
	}

	replacement := `function nauthilus_run_hook(request)
	local i18n = require("nauthilus_i18n")
	i18n.register_catalog({
		language = "en",
		namespace = "startup",
		entries = { ["auth.policy.company.startup"] = "Mutated message." },
	})
	return {}
end
`
	firstPath := writeLuaInitCatalogScript(t, fmt.Sprintf(`
		local output = assert(io.open(%q, "w"))
		assert(output:write(%q))
		assert(output:close())
	`, secondPath, replacement))

	return firstPath, secondPath, originalSecond
}

func TestPrepareLuaInitCatalogsUsesCapturedLuaModuleBytes(t *testing.T) {
	directory := t.TempDir()
	modulePath := filepath.Join(directory, "startup_exact_module.lua")

	originalModule := `return { message = "Captured module message." }
`
	if err := os.WriteFile(modulePath, []byte(originalModule), 0o600); err != nil {
		t.Fatalf("write startup Lua module fixture: %v", err)
	}

	firstPath := writeLuaInitCatalogScript(t, fmt.Sprintf(`
		local output = assert(io.open(%q, "w"))
		assert(output:write(%q))
		assert(output:close())
	`, modulePath, `return { message = "Mutated module message." }
`))
	secondPath := writeLuaInitCatalogScript(t, `
		local exact = require("startup_exact_module")
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "en",
			namespace = "startup",
			entries = { ["auth.policy.company.startup"] = exact.message },
		})
	`)
	configured := luaInitCatalogConfig(firstPath, secondPath)
	configured.Lua.Config.PackagePath = filepath.Join(directory, "?.lua")

	retireLuaInitCatalogTest(t)

	system := localization.NewMapCatalog(map[string]map[string]string{
		"en": {startupCatalogTestKey: "System message."},
	})

	preparation, err := PrepareLuaInitCatalogs(
		context.Background(),
		configured,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
		system,
	)
	if err != nil {
		t.Fatalf("PrepareLuaInitCatalogs() error = %v", err)
	}

	effective, _, err := localization.NewEffectiveCatalog(system, preparation.CatalogOverlays()...)
	if err != nil {
		t.Fatalf("NewEffectiveCatalog() error = %v", err)
	}

	assertLuaInitCatalogText(t, effective, "Captured module message.")
}

// writeLuaInitCatalogScript writes one syntactically valid startup hook fixture.
func writeLuaInitCatalogScript(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "init.lua")

	script := "function nauthilus_run_hook(request)\n" + body + "\nreturn {}\nend\n"
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write Lua init fixture: %v", err)
	}

	return path
}

// luaInitCatalogConfig constructs the process-owned startup-script carrier.
func luaInitCatalogConfig(paths ...string) *config.FileSettings {
	return &config.FileSettings{Lua: &config.LuaSection{Config: &config.LuaConf{
		InitScriptPaths: append([]string(nil), paths...),
	}}}
}

// retireLuaInitCatalogTest retires process-local Lua state created by startup execution.
func retireLuaInitCatalogTest(t *testing.T) {
	t.Helper()

	t.Cleanup(func() {
		if err := vmpool.GetManager().Delete(vmpool.PoolKey("hook:default")); err != nil {
			t.Errorf("retire hook VM pool: %v", err)
		}
	})
}

// setLuaInitCatalogTestDefault proves off-side preparation does not mutate the ambient runtime.
func setLuaInitCatalogTestDefault(t *testing.T, system localization.Catalog) {
	t.Helper()

	previous := lualib.DefaultI18NRuntime()

	registry, err := localization.NewCatalogRegistry(system)
	if err != nil {
		t.Fatalf("NewCatalogRegistry() error = %v", err)
	}

	lualib.SetDefaultI18NRuntime(lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{Registry: registry}))
	t.Cleanup(func() { lualib.SetDefaultI18NRuntime(previous) })
}

// assertLuaInitCatalogText checks one exact English catalog value.
func assertLuaInitCatalogText(t *testing.T, catalog localization.Catalog, want string) {
	t.Helper()

	got, found := catalog.Lookup(language.English, startupCatalogTestKey)
	if !found || got != want {
		t.Fatalf("catalog message = %q/%v, want %q", got, found, want)
	}
}
