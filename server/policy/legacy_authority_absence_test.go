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

package policy_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var forbiddenProductionPolicyAuthority = []string{
	"AuthPolicySection",
	"GetAuthPolicy",
	"StagePlans",
	"CompileAndActivate",
	"pluginloader.DefaultState",
	"SetDefaultState",
	"policyruntime.DefaultStore()",
	"policyruntime.DefaultGenerationStore()",
	"BindDefaultGenerationStore",
	"BindDefaultStoreToGeneration",
	"BuiltinDefaultSet",
	"NoopAdapter",
	"PolicySnapshotFromContext",
	"policyruntime.Snapshot",
	"getPluginSubjectSourceBridge",
	"getPluginEnvironmentSourceBridge",
	"getPluginEffectBridge",
	"getPostActionSupervisor",
	"RegisterPluginSubjectSourceBridge",
	"RegisterPluginEnvironmentSourceBridge",
	"RegisterPluginEffectBridge",
	"RegisterPostActionSupervisor",
	"fallbackPostActionSupervisor",
	"PostActionSupervisor",
	"DefaultRunner()",
	"SetDefaultRunner",
	".QueueLuaPostAction(",
	".RunLuaPostAction(",
	"ScriptSchedulePlan",
	"ScriptScheduleOverride",
	".ScriptPlan(",
	"ScriptScheduled(",
	"SubjectScriptPhases",
	"AnalyzeSchedule(",
	"CheckScheduled(",
	"policyCheckScheduled(",
	"ApplySchedule(",
	`"github.com/croessner/nauthilus/v4/server/lualib/policyschedule"`,
	`"github.com/croessner/nauthilus/v4/server/policy/evaluation"`,
}

func TestLegacyProductionPolicyAuthorityIsAbsent(t *testing.T) {
	legacySources := []string{
		"evaluation/enforce.go",
		"evaluation/observe.go",
		"evaluation/standard.go",
		"runtime/default_generation.go",
		"runtime/default_store.go",
		"runtime/snapshot.go",
		"runtime/snapshot_context.go",
		"../core/post_action_supervisor.go",
		"../pluginruntime/effects.go",
		"../pluginruntime/environment.go",
		"../pluginruntime/subject.go",
		"../lualib/policyschedule/planner.go",
	}

	assertDirectoryHasNoSources(t, "compiler")
	assertDirectoryHasNoSources(t, "enforcement")

	for _, path := range legacySources {
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("legacy production policy source %s still exists", path)
		}
	}

	assertProductionSourceOmitsLegacyPolicyAuthority(t, "..")
}

// assertDirectoryHasNoSources rejects every file beneath a retired package path.
func assertDirectoryHasNoSources(t *testing.T, path string) {
	t.Helper()

	err := filepath.WalkDir(path, func(entryPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !entry.IsDir() {
			t.Errorf("retired policy package %s still contains %s", path, entryPath)
		}

		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("scan retired policy package %s: %v", path, err)
	}
}

// assertProductionSourceOmitsLegacyPolicyAuthority rejects old compiler and evaluator entry points.
func assertProductionSourceOmitsLegacyPolicyAuthority(t *testing.T, root string) {
	t.Helper()

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		return assertProductionFileOmitsLegacyPolicyAuthority(t, path)
	})
	if err != nil {
		t.Fatalf("scan production source under %s: %v", root, err)
	}
}

// assertProductionFileOmitsLegacyPolicyAuthority scans one production Go source.
func assertProductionFileOmitsLegacyPolicyAuthority(t *testing.T, path string) error {
	t.Helper()

	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	for _, value := range forbiddenProductionPolicyAuthority {
		if strings.Contains(string(contents), value) {
			t.Errorf("production source %s retains legacy policy authority %q", path, value)
		}
	}

	return nil
}
