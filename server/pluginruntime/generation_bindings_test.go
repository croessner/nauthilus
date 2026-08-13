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

package pluginruntime

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

// TestGenerationBindingsCaptureLoadedCapabilitiesImmutably proves detached native indexes.
func TestGenerationBindingsCaptureLoadedCapabilitiesImmutably(t *testing.T) {
	artifact := writeGenerationArtifact(t, []byte("native-generation-one"))

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("DigestArtifact() error = %v", err)
	}

	instances := []pluginloader.ModuleInstance{{
		Module: config.PluginModule{
			Name: "native_test",
			Type: config.PluginModuleTypeGo,
			Path: artifact,
		},
		Descriptors: []pluginregistry.Component{{
			QualifiedName: "native_test/source",
			ModuleName:    "native_test",
			LocalName:     "source",
			Kind:          pluginregistry.ComponentKindEnvironmentSource,
			Origin:        pluginregistry.ComponentOriginNative,
			Value:         &struct{}{},
		}},
		Capabilities:   []pluginapi.Capability{pluginapi.CapabilityCredentials},
		ArtifactPath:   artifact,
		ArtifactDigest: digest,
		ModuleName:     "native_test",
		Status:         pluginloader.ModuleStatusRegistered,
	}}

	bindings, err := CaptureGenerationBindings(instances)
	if err != nil {
		t.Fatalf("CaptureGenerationBindings() error = %v", err)
	}

	instances[0].Capabilities[0] = pluginapi.CapabilityMail
	instances[0].Descriptors[0].QualifiedName = "mutated/source"

	modules := bindings.Modules()
	if len(modules) != 1 {
		t.Fatalf("captured modules = %d, want 1", len(modules))
	}

	if !slices.Equal(modules[0].Capabilities(), []pluginapi.Capability{pluginapi.CapabilityCredentials}) {
		t.Fatalf("captured capabilities = %v, want credentials", modules[0].Capabilities())
	}

	components := modules[0].Components()
	if len(components) != 1 || components[0].QualifiedName != "native_test/source" {
		t.Fatalf("captured components = %#v, want immutable native_test/source", components)
	}

	modules[0].Components()[0].QualifiedName = "caller/mutation"
	if got := bindings.Modules()[0].Components()[0].QualifiedName; got != "native_test/source" {
		t.Fatalf("generation binding mutated through accessor: %q", got)
	}
}

// TestGenerationBindingsIgnoreFailedOptionalModules captures only loaded process objects.
func TestGenerationBindingsIgnoreFailedOptionalModules(t *testing.T) {
	artifact := writeGenerationArtifact(t, []byte("native-generation-one"))

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("DigestArtifact() error = %v", err)
	}

	bindings, err := CaptureGenerationBindings([]pluginloader.ModuleInstance{
		{
			Module:       config.PluginModule{Name: "optional_failed", Path: artifact, Optional: true},
			ArtifactPath: artifact, ArtifactDigest: digest, ModuleName: "optional_failed",
			Status: pluginloader.ModuleStatusFailed, Optional: true,
		},
		{
			Module:       config.PluginModule{Name: "native_test", Path: artifact},
			ArtifactPath: artifact, ArtifactDigest: digest, ModuleName: "native_test",
			Status: pluginloader.ModuleStatusRegistered,
		},
	})
	if err != nil {
		t.Fatalf("CaptureGenerationBindings() error = %v", err)
	}

	modules := bindings.Modules()
	if len(modules) != 1 || modules[0].ModuleName() != "native_test" {
		t.Fatalf("captured modules = %#v, want only native_test", modules)
	}
}

// TestGenerationBindingsRejectBinaryReplacementAndRemovalAsRestartRequired proves process lifetime semantics.
func TestGenerationBindingsRejectBinaryReplacementAndRemovalAsRestartRequired(t *testing.T) {
	tests := []struct {
		mutate func(*testing.T, string)
		name   string
	}{
		{
			name: "replacement",
			mutate: func(t *testing.T, artifact string) {
				t.Helper()

				if err := os.WriteFile(artifact, []byte("native-generation-two"), 0o600); err != nil {
					t.Fatalf("replace native artifact: %v", err)
				}
			},
		},
		{
			name: "removal",
			mutate: func(t *testing.T, artifact string) {
				t.Helper()

				if err := os.Remove(artifact); err != nil {
					t.Fatalf("remove native artifact: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := writeGenerationArtifact(t, []byte("native-generation-one"))

			digest, err := pluginloader.DigestArtifact(artifact)
			if err != nil {
				t.Fatalf("DigestArtifact() error = %v", err)
			}

			bindings, err := CaptureGenerationBindings([]pluginloader.ModuleInstance{{
				Module: config.PluginModule{
					Name: "native_test",
					Type: config.PluginModuleTypeGo,
					Path: artifact,
				},
				ArtifactPath:   artifact,
				ArtifactDigest: digest,
				ModuleName:     "native_test",
				Status:         pluginloader.ModuleStatusRegistered,
			}})
			if err != nil {
				t.Fatalf("CaptureGenerationBindings() error = %v", err)
			}

			test.mutate(t, artifact)

			if err = bindings.ValidateArtifacts(); !errors.Is(err, ErrRestartRequired) {
				t.Fatalf("ValidateArtifacts() error = %v, want ErrRestartRequired", err)
			}
		})
	}
}

// writeGenerationArtifact creates one deterministic native artifact fixture.
func writeGenerationArtifact(t *testing.T, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "generation-plugin.so")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write native artifact: %v", err)
	}

	return path
}
