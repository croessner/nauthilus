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
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestReloaderKeepsActiveSnapshotWhenCompileFails(t *testing.T) {
	store := policyruntime.NewSnapshotStore(&policyruntime.Snapshot{Generation: 3})
	reloader := &Reloader{
		store: store,
	}

	err := reloader.ApplyConfig(context.Background(), configfx.Snapshot{
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
		t.Fatal("ApplyConfig() error = nil, want compile error")
	}

	active := store.Active()
	if active == nil {
		t.Fatal("active snapshot is nil")
	}

	if active.Generation != 3 {
		t.Fatalf("active generation = %d, want 3", active.Generation)
	}
}
