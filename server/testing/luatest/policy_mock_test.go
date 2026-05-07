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

func TestPolicyMockRecordsExpectedEmitAttributeCalls(t *testing.T) {
	runner, result := runLuaMockFixture(t, "environment.lua", "environment", `
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
`, `{
  "policy": {
    "expected_calls": [
      {
        "method": "emit_attribute",
        "arg_contains": "id=lua.test.risk value=true details.reason=unit"
      }
    ]
  }
}`)
	requireLuaMockSuccess(t, result)

	if runner.mockData.Policy == nil || len(runner.mockData.Policy.Emitted) != 1 {
		t.Fatalf("policy emissions = %#v, want exactly one emission", runner.mockData.Policy)
	}

	if got := runner.mockData.Policy.Emitted[0].ID; got != "lua.test.risk" {
		t.Fatalf("policy emission ID = %q, want lua.test.risk", got)
	}
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
