package luatest

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

func TestSetupBuiltinTableProvidesStatusMessageSet(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	logger := &MockLogger{}
	SetupBuiltinTable(L, logger)

	err := L.DoString(`nauthilus_builtin.status_message_set("Access denied")`)
	if err != nil {
		t.Fatalf("status_message_set should be available in nauthilus_builtin: %v", err)
	}

	if len(logger.Logs) == 0 {
		t.Fatalf("status_message_set should produce observable output in test mode")
	}
}

func TestSetupMockModulesDoesNotExposeNauthilusLog(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	mockData := &MockData{}
	logger := &MockLogger{}
	cleanup, err := SetupMockModules(L, mockData, logger)
	if err != nil {
		t.Fatalf("SetupMockModules failed: %v", err)
	}
	defer cleanup()

	// The runtime does not provide a standalone nauthilus_log module.
	// Test mode should mirror that behavior and fail on require().
	err = L.DoString(`local _ = require("nauthilus_log")`)
	if err == nil {
		t.Fatalf("require(\"nauthilus_log\") should fail in test mode")
	}

	// Builtins table must still be present.
	if definitions.LuaDefaultTable != "nauthilus_builtin" {
		t.Fatalf("unexpected builtin table name: %s", definitions.LuaDefaultTable)
	}
	if L.GetGlobal(definitions.LuaDefaultTable).Type() != lua.LTTable {
		t.Fatalf("%s should be a table", definitions.LuaDefaultTable)
	}
}
