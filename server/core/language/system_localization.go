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
	"fmt"
	"os"
	"slices"

	"github.com/croessner/nauthilus/v3/server/config"
)

// SystemLocalizationResourceFingerprint identifies one exact loaded resource carrier.
type SystemLocalizationResourceFingerprint struct {
	Path     string
	Language string
	Digest   [sha256.Size]byte
}

// SystemLocalizationFingerprint identifies the complete restart-bound system catalog source.
type SystemLocalizationFingerprint struct {
	ResourcePath        string
	ConfiguredLanguages []string
	EffectiveLanguages  []string
	DefaultLanguage     string
	Resources           []SystemLocalizationResourceFingerprint
}

// SystemLocalizationFingerprintProvider exposes the source bytes used by one live manager.
type SystemLocalizationFingerprintProvider interface {
	GetSystemLocalizationFingerprint() SystemLocalizationFingerprint
}

type systemLocalizationResource struct {
	path     string
	language string
	content  []byte
}

// CaptureSystemLocalizationFingerprint reads the exact source carriers selected by one candidate.
func CaptureSystemLocalizationFingerprint(configured config.File) (SystemLocalizationFingerprint, error) {
	fingerprint, err := describeSystemLocalizationSource(configured)
	if err != nil || fingerprint.ResourcePath == "" {
		return fingerprint, err
	}

	_, err = readSystemLocalizationResources(&fingerprint)

	return fingerprint, err
}

// readSystemLocalizationSource captures metadata and bytes in one pass for manager construction.
func readSystemLocalizationSource(
	configured config.File,
) (SystemLocalizationFingerprint, []systemLocalizationResource, error) {
	fingerprint, err := describeSystemLocalizationSource(configured)
	if err != nil {
		return SystemLocalizationFingerprint{}, nil, err
	}

	resources, err := readSystemLocalizationResources(&fingerprint)
	if err != nil {
		return SystemLocalizationFingerprint{}, nil, err
	}

	return fingerprint, resources, nil
}

// readSystemLocalizationResources reads and fingerprints the exact selected files once.
func readSystemLocalizationResources(
	fingerprint *SystemLocalizationFingerprint,
) ([]systemLocalizationResource, error) {
	resources := make([]systemLocalizationResource, 0, len(fingerprint.EffectiveLanguages))

	for _, languageName := range fingerprint.EffectiveLanguages {
		path := fingerprint.ResourcePath + "/" + languageName + ".json"

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf(
				"failed to load language bundle for %s: %w",
				languageName,
				readErr,
			)
		}

		fingerprint.Resources = append(fingerprint.Resources, SystemLocalizationResourceFingerprint{
			Path: path, Language: languageName, Digest: sha256.Sum256(content),
		})
		resources = append(resources, systemLocalizationResource{
			path: path, language: languageName, content: content,
		})
	}

	return resources, nil
}

// describeSystemLocalizationSource projects config-only metadata before any resource read.
func describeSystemLocalizationSource(configured config.File) (SystemLocalizationFingerprint, error) {
	if configured == nil {
		return SystemLocalizationFingerprint{}, fmt.Errorf("system localization configuration is nil")
	}

	frontend := configured.GetServer().Frontend
	configuredLanguages := slices.Clone(frontend.GetLanguages())
	effectiveLanguages := effectiveSystemLanguages(configuredLanguages)

	return SystemLocalizationFingerprint{
		ResourcePath:        frontend.GetLanguageResources(),
		ConfiguredLanguages: configuredLanguages,
		EffectiveLanguages:  effectiveLanguages,
		DefaultLanguage:     frontend.GetDefaultLanguage(),
		Resources:           make([]SystemLocalizationResourceFingerprint, 0, len(effectiveLanguages)),
	}, nil
}

// effectiveSystemLanguages expands the exact default order used by the language manager.
func effectiveSystemLanguages(configured []string) []string {
	if len(configured) > 0 {
		return slices.Clone(configured)
	}

	effective := make([]string, 0, len(config.DefaultLanguageTags))
	for _, tag := range config.DefaultLanguageTags {
		effective = append(effective, tag.String())
	}

	return effective
}

// Clone detaches the mutable projections held by this fingerprint.
func (f SystemLocalizationFingerprint) Clone() SystemLocalizationFingerprint {
	f.ConfiguredLanguages = slices.Clone(f.ConfiguredLanguages)
	f.EffectiveLanguages = slices.Clone(f.EffectiveLanguages)
	f.Resources = slices.Clone(f.Resources)

	return f
}
