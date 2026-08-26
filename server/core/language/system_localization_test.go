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

package language

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

func TestManagerFingerprintUsesTheExactLoadedResourceBytes(t *testing.T) {
	resourcePath := t.TempDir()
	resourceFile := filepath.Join(resourcePath, "en.json")

	loadedContent := []byte(`{"message":"loaded"}`)
	if err := os.WriteFile(resourceFile, loadedContent, 0o600); err != nil {
		t.Fatalf("write loaded localization resource: %v", err)
	}

	configured := &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		LanguageResources: resourcePath,
		Languages:         []string{"en"},
		DefaultLanguage:   "en",
	}}}

	manager, err := NewManager(configured, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	provider, ok := manager.(SystemLocalizationFingerprintProvider)
	if !ok {
		t.Fatal("production language manager does not expose its source fingerprint")
	}

	loaded := provider.GetSystemLocalizationFingerprint()
	assertLoadedSystemLocalizationFingerprint(t, loaded, resourcePath, loadedContent)
	assertSystemLocalizationFingerprintDetached(t, provider, loaded)

	changedContent := []byte(`{"message":"changed"}`)
	if err = os.WriteFile(resourceFile, changedContent, 0o600); err != nil {
		t.Fatalf("change localization resource: %v", err)
	}

	candidate, err := CaptureSystemLocalizationFingerprint(configured)
	if err != nil {
		t.Fatalf("CaptureSystemLocalizationFingerprint() error = %v", err)
	}

	assertChangedSystemLocalizationFingerprint(t, provider, candidate, loadedContent, changedContent)
}

// assertLoadedSystemLocalizationFingerprint verifies the exact metadata and bytes captured at construction.
func assertLoadedSystemLocalizationFingerprint(
	t *testing.T,
	loaded SystemLocalizationFingerprint,
	resourcePath string,
	loadedContent []byte,
) {
	t.Helper()

	if loaded.ResourcePath != resourcePath || loaded.DefaultLanguage != "en" {
		t.Fatalf("loaded fingerprint metadata = %#v", loaded)
	}

	if len(loaded.ConfiguredLanguages) != 1 || loaded.ConfiguredLanguages[0] != "en" {
		t.Fatalf("loaded configured languages = %#v", loaded.ConfiguredLanguages)
	}

	if len(loaded.EffectiveLanguages) != 1 || loaded.EffectiveLanguages[0] != "en" {
		t.Fatalf("loaded effective languages = %#v", loaded.EffectiveLanguages)
	}

	if len(loaded.Resources) != 1 || loaded.Resources[0].Digest != sha256.Sum256(loadedContent) {
		t.Fatalf("loaded resource fingerprint = %#v", loaded.Resources)
	}
}

// assertSystemLocalizationFingerprintDetached verifies that callers cannot mutate the live manager fingerprint.
func assertSystemLocalizationFingerprintDetached(
	t *testing.T,
	provider SystemLocalizationFingerprintProvider,
	loaded SystemLocalizationFingerprint,
) {
	t.Helper()

	loaded.ConfiguredLanguages[0] = "mutated"
	if provider.GetSystemLocalizationFingerprint().ConfiguredLanguages[0] != "en" {
		t.Fatal("manager returned an aliased source fingerprint")
	}
}

// assertChangedSystemLocalizationFingerprint verifies candidate recapture without mutating the live manager.
func assertChangedSystemLocalizationFingerprint(
	t *testing.T,
	provider SystemLocalizationFingerprintProvider,
	candidate SystemLocalizationFingerprint,
	loadedContent []byte,
	changedContent []byte,
) {
	t.Helper()

	if candidate.Resources[0].Digest != sha256.Sum256(changedContent) {
		t.Fatalf("candidate resource fingerprint = %#v", candidate.Resources)
	}

	if provider.GetSystemLocalizationFingerprint().Resources[0].Digest != sha256.Sum256(loadedContent) {
		t.Fatal("manager source fingerprint changed after the resource carrier changed")
	}
}

func TestCaptureSystemLocalizationFingerprintExpandsDefaultLanguageOrder(t *testing.T) {
	resourcePath := t.TempDir()
	for _, tag := range config.DefaultLanguageTags {
		path := filepath.Join(resourcePath, tag.String()+".json")
		if err := os.WriteFile(path, []byte(`{"message":"default"}`), 0o600); err != nil {
			t.Fatalf("write default localization resource %q: %v", path, err)
		}
	}

	configured := &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		LanguageResources: resourcePath,
	}}}

	fingerprint, err := CaptureSystemLocalizationFingerprint(configured)
	if err != nil {
		t.Fatalf("CaptureSystemLocalizationFingerprint() error = %v", err)
	}

	if len(fingerprint.ConfiguredLanguages) != 0 {
		t.Fatalf("configured languages = %#v, want omitted", fingerprint.ConfiguredLanguages)
	}

	if len(fingerprint.EffectiveLanguages) != len(config.DefaultLanguageTags) {
		t.Fatalf("effective languages = %#v", fingerprint.EffectiveLanguages)
	}

	for index, tag := range config.DefaultLanguageTags {
		if fingerprint.EffectiveLanguages[index] != tag.String() {
			t.Fatalf("effective language %d = %q, want %q", index, fingerprint.EffectiveLanguages[index], tag)
		}
	}
}
