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

package policyfx

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/config"
	corelanguage "github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type systemLocalizationDriftMutation struct {
	mutate func(*testing.T, *config.FileSettings, string)
	name   string
}

// systemLocalizationDriftMutations returns every process-owned localization change.
func systemLocalizationDriftMutations() []systemLocalizationDriftMutation {
	return []systemLocalizationDriftMutation{
		{
			name: "resource path",
			mutate: func(t *testing.T, candidate *config.FileSettings, _ string) {
				t.Helper()

				replacement := writeSystemLocalizationResources(t, map[string]string{
					"en": `{"baseline":"english"}`,
					"de": `{"baseline":"german"}`,
				})
				candidate.Server.Frontend.LanguageResources = replacement
			},
		},
		{
			name: "configured languages",
			mutate: func(t *testing.T, candidate *config.FileSettings, _ string) {
				t.Helper()

				candidate.Server.Frontend.Languages = []string{"de"}
			},
		},
		{
			name: "default language",
			mutate: func(t *testing.T, candidate *config.FileSettings, _ string) {
				t.Helper()

				candidate.Server.Frontend.DefaultLanguage = "de"
			},
		},
		{
			name: "resource content",
			mutate: func(t *testing.T, _ *config.FileSettings, resourcePath string) {
				t.Helper()

				writeSystemLocalizationResource(t, resourcePath, "en", `{"candidate":"changed"}`)
			},
		},
	}
}

func TestStartupCatalogRejectsSystemLocalizationDrift(t *testing.T) {
	tests := systemLocalizationDriftMutations()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resourcePath := writeSystemLocalizationResources(t, map[string]string{
				"en": `{"baseline":"english"}`,
				"de": `{"baseline":"german"}`,
			})
			configured := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")

			catalog := NewStartupCatalog()
			if err := catalog.Capture(configured, bootfx.LuaInitCatalogPreparation{}); err != nil {
				t.Fatalf("Capture() error = %v", err)
			}

			candidate := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")
			test.mutate(t, candidate, resourcePath)

			if _, err := catalog.overlaysForCandidate(candidate); !errors.Is(err, pluginruntime.ErrRestartRequired) {
				t.Fatalf("overlaysForCandidate() error = %v, want restart required", err)
			}
		})
	}
}

func TestStartupCatalogAcceptsDetachedEquivalentSystemLocalization(t *testing.T) {
	resourcePath := writeSystemLocalizationResources(t, map[string]string{
		"en": `{"baseline":"english"}`,
	})
	configured := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")

	catalog := NewStartupCatalog()
	if err := catalog.Capture(configured, bootfx.LuaInitCatalogPreparation{}); err != nil {
		t.Fatalf("Capture() error = %v", err)
	}

	candidate := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")
	if _, err := catalog.overlaysForCandidate(candidate); err != nil {
		t.Fatalf("overlaysForCandidate(equivalent) error = %v", err)
	}
}

func TestStartupCatalogRejectsResourceDriftBetweenManagerLoadAndInitialCapture(t *testing.T) {
	resourcePath := writeSystemLocalizationResources(t, map[string]string{
		"en": `{"baseline":"loaded"}`,
	})
	configured := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")

	manager, err := corelanguage.NewManager(configured, nil)
	if err != nil {
		t.Fatalf("language.NewManager() error = %v", err)
	}

	catalog, err := provideStartupCatalog(manager)
	if err != nil {
		t.Fatalf("provideStartupCatalog() error = %v", err)
	}

	writeSystemLocalizationResource(t, resourcePath, "en", `{"candidate":"changed-before-capture"}`)

	if err = catalog.Capture(
		configured,
		bootfx.LuaInitCatalogPreparation{},
	); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Capture(drifted resource) error = %v, want restart required", err)
	}

	if _, err = catalog.overlaysForCandidate(configured); err == nil {
		t.Fatal("failed initial capture published a startup catalog")
	}
}

func TestProductionStartupCatalogRejectsManagerWithoutSourceFingerprint(t *testing.T) {
	resourcePath := writeSystemLocalizationResources(t, map[string]string{
		"en": `{"baseline":"loaded"}`,
	})
	configured := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")

	manager, err := corelanguage.NewManager(configured, nil)
	if err != nil {
		t.Fatalf("language.NewManager() error = %v", err)
	}

	_, err = provideStartupCatalog(managerWithoutFingerprint{Manager: manager})
	if !errors.Is(err, policyruntime.ErrInvalidGeneration) {
		t.Fatalf("provideStartupCatalog(unfingerprinted manager) error = %v, want invalid generation", err)
	}
}

func TestProductionModuleUsesOnlyManagerBoundStartupCatalogProvider(t *testing.T) {
	contents, err := os.ReadFile("module.go")
	if err != nil {
		t.Fatalf("read policyfx module: %v", err)
	}

	source := string(contents)
	if !strings.Contains(source, "fx.Provide(provideStartupCatalog)") {
		t.Fatal("production module does not bind StartupCatalog to the live language manager")
	}

	if strings.Contains(source, "fx.Provide(NewStartupCatalog)") {
		t.Fatal("production module retains an unbound StartupCatalog provider")
	}
}

func TestStartupCatalogAcceptsUnmaterializedOffSideResourcePath(t *testing.T) {
	configured := &config.FileSettings{}

	catalog := NewStartupCatalog()
	if err := catalog.Capture(configured, bootfx.LuaInitCatalogPreparation{}); err != nil {
		t.Fatalf("Capture(unmaterialized off-side config) error = %v", err)
	}

	if _, err := catalog.overlaysForCandidate(configured); err != nil {
		t.Fatalf("overlaysForCandidate(unmaterialized off-side config) error = %v", err)
	}
}

// systemLocalizationCandidate returns one detached system-localization carrier.
func systemLocalizationCandidate(resourcePath string, languages []string, defaultLanguage string) *config.FileSettings {
	return &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		LanguageResources: resourcePath,
		Languages:         slices.Clone(languages),
		DefaultLanguage:   defaultLanguage,
	}}}
}

// writeSystemLocalizationResources creates one test-owned localization corpus.
func writeSystemLocalizationResources(t *testing.T, resources map[string]string) string {
	t.Helper()

	resourcePath := t.TempDir()
	for language, content := range resources {
		writeSystemLocalizationResource(t, resourcePath, language, content)
	}

	return resourcePath
}

// writeSystemLocalizationResource writes one exact language resource carrier.
func writeSystemLocalizationResource(t *testing.T, resourcePath string, language string, content string) {
	t.Helper()

	path := filepath.Join(resourcePath, language+".json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write localization resource %q: %v", path, err)
	}
}

// managerWithoutFingerprint exposes only the legacy language.Manager surface.
type managerWithoutFingerprint struct {
	corelanguage.Manager
}
