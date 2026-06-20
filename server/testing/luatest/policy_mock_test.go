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
	"testing"
)

const policyEmitAttributeScript = `
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
`

const policyEmitAttributeMock = `{
  "policy": {
    "expected_calls": [
      {
        "method": "emit_attribute",
        "arg_contains": "id=lua.test.risk value=true details.reason=unit"
      }
    ]
  }
}`

func TestPolicyMockRecordsExpectedEmitAttributeCalls(t *testing.T) {
	runner := runSuccessfulLuaMockFixture(t, "environment.lua", "environment", policyEmitAttributeScript, policyEmitAttributeMock)
	requireSinglePolicyEmission(t, runner)
}

// requireSinglePolicyEmission checks the policy mock captured the expected emitted attribute.
func requireSinglePolicyEmission(t *testing.T, runner *TestRunner) {
	t.Helper()

	if runner.mockData.Policy == nil {
		t.Fatalf("policy mock = nil, want one emission")
	}

	requireSingleCapturedValue(t, "policy emission", runner.mockData.Policy.Emitted, func(emission PolicyEmission) string {
		return emission.ID
	}, "lua.test.risk")
}

func TestPolicyMockReportsMissingExpectedEmitAttributeCall(t *testing.T) {
	_, result := runLuaMockFixture(t, "environment.lua", "environment", `
function nauthilus_call_environment(request)
  return true, false, 0
end
`, `{
  "policy": {
    "expected_calls": [
      {
        "method": "emit_attribute",
        "arg_contains": "id=lua.test.risk"
      }
    ]
  }
}`)

	if result.Success {
		t.Fatalf("result.Success = true, want false for missing policy expected_call")
	}

	if !testErrorsContain(result.Errors, "missing expected policy call") {
		t.Fatalf("errors = %v, want missing expected policy call", result.Errors)
	}
}
