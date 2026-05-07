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

package core

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestPolicyReportEnabledEmitsDefaultPolicyDebugReport(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	enablePolicyDebugModule(t, cfg)

	var logBuffer bytes.Buffer

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    203,
		Mode:          policyModeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		Report: policyruntime.ReportSettings{
			Enabled:           true,
			IncludeFSM:        true,
			IncludeChecks:     true,
			IncludeAttributes: false,
		},
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.deps.Logger = slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = false
	passDBResult.UserFound = true
	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultFail, passDBResult, nil)
	auth.defaultPolicyAuthResult(ctx, definitions.AuthResultOK)
	auth.completePolicyStage(ctx, policy.StageAuthBackend)

	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "policy_component=report") {
		t.Fatalf("policy report log missing component: %s", logOutput)
	}

	if !strings.Contains(logOutput, "completed_stage=auth_backend") {
		t.Fatalf("policy report log missing completed stage: %s", logOutput)
	}

	if !strings.Contains(logOutput, "standard_auth_failure") {
		t.Fatalf("policy report log missing selected default decision: %s", logOutput)
	}

	if strings.Contains(logOutput, "auth.request.client_ip") {
		t.Fatalf("policy report logged attributes despite include_attributes=false: %s", logOutput)
	}
}

func enablePolicyDebugModule(t *testing.T, cfg *config.FileSettings) {
	t.Helper()

	if cfg == nil || cfg.Server == nil {
		t.Fatal("test config has no server section")
	}

	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())

	verbosity := config.Verbosity{}
	if err := verbosity.Set(definitions.LogLevelNameDebug); err != nil {
		t.Fatalf("set verbosity: %v", err)
	}

	policyDebugModule := &config.DbgModule{}
	if err := policyDebugModule.Set(definitions.DbgPolicyName); err != nil {
		t.Fatalf("set policy debug module: %v", err)
	}

	cfg.Server.Log.Level = verbosity
	cfg.Server.Log.DbgModules = []*config.DbgModule{policyDebugModule}
}
