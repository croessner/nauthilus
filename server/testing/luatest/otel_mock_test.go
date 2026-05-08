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

	lua "github.com/yuin/gopher-lua"
)

func TestOTELMockProvidesDisabledRuntimeHelpers(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	cleanup, err := SetupMockModules(L, &MockData{}, &MockLogger{})
	if err != nil {
		t.Fatalf("SetupMockModules failed: %v", err)
	}
	defer cleanup()

	err = L.DoString(`
local otel = require("nauthilus_opentelemetry")
if otel.is_enabled() then
  error("otel mock should be disabled by default")
end

local tracer = otel.tracer("nauthilus/test")
tracer:with_span("test.span", function(span)
  span:set_attributes({ ["test.attr"] = "ok" })
end, { kind = "client" })
`)
	if err != nil {
		t.Fatalf("otel mock should expose disabled helpers and with_span: %v", err)
	}
}
