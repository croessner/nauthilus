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

package luatest

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestLoaderModUtilMock_ProvidesLevelLoggingHelpers(t *testing.T) {
	t.Helper()

	L := lua.NewState()
	defer L.Close()

	utilMock := &UtilMock{}
	L.PreloadModule("nauthilus_util", LoaderModUtilMock(utilMock))

	if err := L.DoString(`
		local util = require("nauthilus_util")
		util.log_info({}, { message = "info" })
		util.log_debug({}, { message = "debug" })
		util.log_notice({}, { message = "notice" })
		util.log_warn({}, { message = "warn" })
		util.log_error({}, { message = "error" }, "boom")
	`); err != nil {
		t.Fatalf("expected util mock logging helpers to be callable: %v", err)
	}
}
