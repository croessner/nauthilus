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

package luatest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyMockRecordsExpectedEmitAttributeCalls(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "environment.lua")
	mockPath := filepath.Join(dir, "mock.json")

	writePolicyMockTestFile(t, scriptPath, `
local policy = require("nauthilus_policy")

function nauthilus_call_environment(request)
  policy.emit_attribute({
    id = "lua.test.risk",
    value = true,
    details = {
      reason = "unit",
    },
  })

  return true, false, 0
end
`)
	writePolicyMockTestFile(t, mockPath, `{
  "policy": {
    "expected_calls": [
      {
        "method": "emit_attribute",
        "arg_contains": "id=lua.test.risk value=true details.reason=unit"
      }
    ]
  }
}`)

	runner, err := NewTestRunner(scriptPath, "environment", mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("result.Success = false, errors = %v", result.Errors)
	}

	if runner.mockData.Policy == nil || len(runner.mockData.Policy.Emitted) != 1 {
		t.Fatalf("policy emissions = %#v, want exactly one emission", runner.mockData.Policy)
	}

	if got := runner.mockData.Policy.Emitted[0].ID; got != "lua.test.risk" {
		t.Fatalf("policy emission ID = %q, want lua.test.risk", got)
	}
}

func TestPolicyMockReportsMissingExpectedEmitAttributeCall(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "environment.lua")
	mockPath := filepath.Join(dir, "mock.json")

	writePolicyMockTestFile(t, scriptPath, `
function nauthilus_call_environment(request)
  return true, false, 0
end
`)
	writePolicyMockTestFile(t, mockPath, `{
  "policy": {
    "expected_calls": [
      {
        "method": "emit_attribute",
        "arg_contains": "id=lua.test.risk"
      }
    ]
  }
}`)

	runner, err := NewTestRunner(scriptPath, "environment", mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Success {
		t.Fatalf("result.Success = true, want false for missing policy expected_call")
	}

	if !policyMockErrorsContain(result.Errors, "missing expected policy call") {
		t.Fatalf("errors = %v, want missing expected policy call", result.Errors)
	}
}

func writePolicyMockTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func policyMockErrorsContain(errors []error, substring string) bool {
	for _, err := range errors {
		if err != nil && strings.Contains(err.Error(), substring) {
			return true
		}
	}

	return false
}
