// Copyright (C) 2026 Christian Roessner
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
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

const pluginPolicyModeEnforce = "enforce"

type pluginPolicySnapshotSpec struct {
	stage         policy.Stage
	category      policyregistry.AttributeCategory
	attributeType policyregistry.AttributeType
	checkName     string
	checkType     string
	configRef     string
}

// newStartedTestRunnerWithModule starts a test runner and fails the test on lifecycle errors.
func newStartedTestRunnerWithModule(
	t *testing.T,
	plugin pluginapi.Plugin,
	module config.PluginModule,
	register func(pluginapi.Registrar) error,
	options ...Option,
) *Runner {
	t.Helper()

	runner := newTestRunnerWithModule(t, plugin, module, register, options...)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return runner
}

// activatePluginPolicySnapshot installs a minimal plugin-aware policy snapshot for bridge tests.
func activatePluginPolicySnapshot(t *testing.T, spec pluginPolicySnapshotSpec, attributes ...string) {
	t.Helper()

	snapshot := &policyruntime.Snapshot{
		Generation:        1,
		Mode:              pluginPolicyModeEnforce,
		DefaultPolicy:     policy.BuiltinDefaultSet,
		AttributeRegistry: pluginAttributeRegistry(spec, attributes),
		StagePlans:        pluginStagePlans(spec),
	}

	if err := policyruntime.DefaultStore().Activate(snapshot); err != nil {
		t.Fatalf("activate policy snapshot: %v", err)
	}

	t.Cleanup(func() {
		if err := policyruntime.DefaultStore().Activate(&policyruntime.Snapshot{}); err != nil {
			t.Fatalf("restore policy snapshot: %v", err)
		}
	})
}

// pluginAttributeRegistry builds attribute definitions for plugin-owned policy facts.
func pluginAttributeRegistry(
	spec pluginPolicySnapshotSpec,
	attributes []string,
) map[string]policyregistry.AttributeDefinition {
	attributeRegistry := make(map[string]policyregistry.AttributeDefinition)
	for _, attribute := range attributes {
		attributeRegistry[attribute] = policyregistry.AttributeDefinition{
			ID:         attribute,
			Stage:      spec.stage,
			Operations: []policy.Operation{policy.OperationAuthenticate},
			Category:   spec.category,
			Type:       spec.attributeType,
			Source:     policyregistry.SourcePlugin,
		}
	}

	return attributeRegistry
}

// pluginStagePlans builds one compiled check for the target plugin stage.
func pluginStagePlans(spec pluginPolicySnapshotSpec) map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan {
	return map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
		policy.OperationAuthenticate: {
			spec.stage: {
				Stage: spec.stage,
				Checks: []policyruntime.CompiledCheck{
					{
						Name:       spec.checkName,
						Type:       spec.checkType,
						Stage:      spec.stage,
						Operations: []policy.Operation{policy.OperationAuthenticate},
						ConfigRef:  spec.configRef,
						RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
					},
				},
			},
		},
	}
}
