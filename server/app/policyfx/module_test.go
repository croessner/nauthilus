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
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
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
