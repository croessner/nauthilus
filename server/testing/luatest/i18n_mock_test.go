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

const i18NRegisterCatalogScript = `
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
`

const i18NRegisterCatalogMock = `{
  "i18n": {
    "expected_calls": [
      {
        "method": "register_catalog",
        "arg_contains": "language=de namespace=rns entries.auth.policy.rns.account_not_enabled=Account disabled"
      }
    ]
  }
}`

func TestI18NMockRecordsRegisterCatalogCalls(t *testing.T) {
	runner := runSuccessfulLuaMockFixture(t, "init.lua", "hook", i18NRegisterCatalogScript, i18NRegisterCatalogMock)
	requireSingleI18NCatalog(t, runner)
}

// requireSingleI18NCatalog checks the i18n mock captured the expected catalog registration.
func requireSingleI18NCatalog(t *testing.T, runner *TestRunner) {
	t.Helper()

	if runner.mockData.I18N == nil {
		t.Fatalf("i18n mock = nil, want one registration")
	}

	requireSingleCapturedValue(t, "i18n catalog", runner.mockData.I18N.Catalogs, func(registration I18NCatalogRegistration) string {
		return registration.Language
	}, "de")
}
