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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// TestGenerationCoordinatorKeepsActiveGenerationWhenPreparationFails proves compiler isolation.
func TestGenerationCoordinatorKeepsActiveGenerationWhenPreparationFails(t *testing.T) {
	store := policyruntime.NewGenerationStore()

	coordinator, err := newCoordinator(store, compiler.NewCompiler(), nil)
	if err != nil {
		t.Fatalf("newCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(context.Background(), configfx.Snapshot{
		File:    &config.FileSettings{},
		Version: 3,
	}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	activeBefore := store.Active()

	err = coordinator.Apply(context.Background(), configfx.Snapshot{
		File: &config.FileSettings{
			Auth: &config.AuthSection{
				Policy: config.AuthPolicySection{
					Mode:          "enforce",
					DefaultPolicy: policy.BuiltinDefaultSet,
					Policies: []config.PolicyRuleConfig{
						{
							Name:  "invalid",
							Stage: string(policy.StagePreAuth),
							If: config.PolicyConditionConfig{
								Attribute: "auth.missing",
								Is:        true,
							},
							Then: config.PolicyThenConfig{
								Decision: string(policy.DecisionDeny),
							},
						},
					},
				},
			},
		},
		Version: 4,
	})
	if err == nil {
		t.Fatal("Apply() error = nil, want compile error")
	}

	activeAfter := store.Active()
	if activeAfter != activeBefore {
		t.Fatal("failed preparation replaced the active generation")
	}

	if activeAfter == nil || activeAfter.ID() != 3 || activeAfter.PolicySnapshot().Generation != 3 {
		t.Fatal("failed preparation did not retain the complete previous generation")
	}
}

// TestGenerationReloadRejectsNativeBinaryReplacementWithoutMutation proves restart-only artifact identity.
func TestGenerationReloadRejectsNativeBinaryReplacementWithoutMutation(t *testing.T) {
	tests := []struct {
		mutate func(*testing.T, string)
		name   string
	}{
		{
			name: "replacement",
			mutate: func(t *testing.T, path string) {
				t.Helper()

				if err := os.WriteFile(path, []byte("replacement-native-binary"), 0o600); err != nil {
					t.Fatalf("replace native binary: %v", err)
				}
			},
		},
		{
			name: "removal",
			mutate: func(t *testing.T, path string) {
				t.Helper()

				if err := os.Remove(path); err != nil {
					t.Fatalf("remove native binary: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertNativeBinaryMutationRejected(t, test.mutate)
		})
	}
}

// assertNativeBinaryMutationRejected proves one restart-required artifact mutation is non-mutating.
func assertNativeBinaryMutationRejected(t *testing.T, mutate func(*testing.T, string)) {
	t.Helper()

	artifact := filepath.Join(t.TempDir(), "native-generation.so")
	if err := os.WriteFile(artifact, []byte("initial-native-binary"), 0o600); err != nil {
		t.Fatalf("write native binary: %v", err)
	}

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("DigestArtifact() error = %v", err)
	}

	native, err := pluginruntime.CaptureGenerationBindings([]pluginloader.ModuleInstance{{
		Module:       config.PluginModule{Name: "native_generation", Type: config.PluginModuleTypeGo, Path: artifact},
		ArtifactPath: artifact, ArtifactDigest: digest, ModuleName: "native_generation",
		Status: pluginloader.ModuleStatusRegistered,
	}})
	if err != nil {
		t.Fatalf("CaptureGenerationBindings() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()

	coordinator, err := newCoordinatorWithNativeBindings(store, compiler.NewCompiler(), nil, native)
	if err != nil {
		t.Fatalf("newCoordinatorWithNativeBindings() error = %v", err)
	}

	file := &config.FileSettings{Plugins: &config.PluginsSection{Modules: []config.PluginModule{{
		Name: "native_generation", Type: config.PluginModuleTypeGo, Path: artifact,
	}}}}
	if err = coordinator.Apply(context.Background(), configfx.Snapshot{File: file, Version: 1}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	active := store.Active()
	if got := active.Bindings().NativeModuleIDs(); len(got) != 1 || got[0] != "native_generation" {
		t.Fatalf("captured native modules = %v, want native_generation", got)
	}

	mutate(t, artifact)

	err = coordinator.Apply(context.Background(), configfx.Snapshot{File: file, Version: 2})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("replacement Apply() error = %v, want ErrRestartRequired", err)
	}

	if store.Active() != active {
		t.Fatal("native artifact replacement changed the active generation")
	}
}

// TestGenerationPreparationKeepsLuaAndNativeBindingChangesRestartBound proves safe adapter deferral.
func TestGenerationPreparationKeepsLuaAndNativeBindingChangesRestartBound(t *testing.T) {
	tests := []struct {
		name      string
		candidate *config.FileSettings
	}{
		{
			name: "Lua",
			candidate: &config.FileSettings{Lua: &config.LuaSection{
				Actions: []config.LuaAction{{ScriptName: "candidate"}},
			}},
		},
		{
			name: "native plugin",
			candidate: &config.FileSettings{Plugins: &config.PluginsSection{
				VerificationPolicy: "strict",
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := policyruntime.NewGenerationStore()

			coordinator, err := newCoordinator(store, compiler.NewCompiler(), nil)
			if err != nil {
				t.Fatalf("newCoordinator() error = %v", err)
			}

			if err = coordinator.Apply(context.Background(), configfx.Snapshot{
				File: &config.FileSettings{}, Version: 1,
			}); err != nil {
				t.Fatalf("initial Apply() error = %v", err)
			}

			active := store.Active()

			err = coordinator.Apply(context.Background(), configfx.Snapshot{
				File: test.candidate, Version: 2,
			})
			if !errors.Is(err, errPolicyBindingsRestartRequired) {
				t.Fatalf("binding Apply() error = %v, want restart-required rejection", err)
			}

			if store.Active() != active {
				t.Fatal("restart-bound binding change replaced the active generation")
			}
		})
	}
}
