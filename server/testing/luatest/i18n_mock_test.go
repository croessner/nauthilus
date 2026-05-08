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

func TestI18NMockRecordsRegisterCatalogCalls(t *testing.T) {
	runner, result := runLuaMockFixture(t, "init.lua", "hook", `
local i18n = require("nauthilus_i18n")

function nauthilus_run_hook(logging)
  i18n.register_catalog({
    language = "de",
    namespace = "rns",
    entries = {
      ["auth.policy.rns.account_not_enabled"] = "Account disabled",
    },
  })
end
`, `{
  "i18n": {
    "expected_calls": [
      {
        "method": "register_catalog",
        "arg_contains": "language=de namespace=rns entries.auth.policy.rns.account_not_enabled=Account disabled"
      }
    ]
  }
}`)
	requireLuaMockSuccess(t, result)

	if runner.mockData.I18N == nil || len(runner.mockData.I18N.Catalogs) != 1 {
		t.Fatalf("i18n catalogs = %#v, want exactly one registration", runner.mockData.I18N)
	}

	if got := runner.mockData.I18N.Catalogs[0].Language; got != "de" {
		t.Fatalf("i18n catalog language = %q, want de", got)
	}
}
