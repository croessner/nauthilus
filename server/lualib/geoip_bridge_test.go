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

package lualib

import (
	"encoding/json"
	"path/filepath"
	"testing"

	luajson "github.com/vadv/gopher-lua-libs/json"
	lua "github.com/yuin/gopher-lua"
)

func TestGeoIPBridgeAttachesNativeRuntimeValues(t *testing.T) {
	L := newGeoIPBridgeTestState(t)
	defer L.Close()

	if err := L.DoString(`
local bridge = require("nauthilus_geoip_bridge")

local native = {
  matched = true,
  country_iso = "de",
  country_name = "Germany",
  city_name = "Berlin",
  asn = 64500,
  asn_org = "Example Access GmbH",
  asn_prefix = "203.0.113.0/24",
  asn_registry = "ripencc",
  asn_country_iso = "DE",
  asn_allocated = "2024-01-01",
  asn_status = "allocated",
}

ctx_state["plugin.environment.geoip"] = native
local info = bridge.attach()
local rt = ctx_state["rt"]

result_country = info.current_country_code
result_source = info.source
result_status = info.status
result_asn = info.asn
result_prefix = info.asn_prefix
result_rt_country = rt.geoip_info.current_country_code
result_iso_seen = ctx_state["geoippolicyd_iso_codes_seen"][1]
`); err != nil {
		t.Fatalf("geoip bridge script failed: %v", err)
	}

	assertLuaString(t, L.GetGlobal("result_country"), "DE")
	assertLuaString(t, L.GetGlobal("result_source"), "native_geoip")
	assertLuaString(t, L.GetGlobal("result_status"), "matched")
	assertLuaNumber(t, L.GetGlobal("result_asn"), 64500)
	assertLuaString(t, L.GetGlobal("result_prefix"), "203.0.113.0/24")
	assertLuaString(t, L.GetGlobal("result_rt_country"), "DE")
	assertLuaString(t, L.GetGlobal("result_iso_seen"), "DE")
}

func TestGeoIPBridgePreservesPolicyGeoIPDecision(t *testing.T) {
	L := newGeoIPBridgeTestState(t)
	defer L.Close()

	if err := L.DoString(`
local bridge = require("nauthilus_geoip_bridge")

ctx_state["rt"] = {
  geoip_info = {
    guid = "policy-guid",
    current_country_code = "FR",
    status = "reject",
    iso_codes_seen = {"FR"},
  },
}
ctx_state["plugin.environment.geoip"] = {
  matched = true,
  country_iso = "DE",
  asn = 64500,
}

local info = bridge.attach()

result_guid = info.guid
result_country = info.current_country_code
result_status = info.status
result_native_country = info.native_country_iso
result_asn = info.asn
result_iso_seen = ctx_state["geoippolicyd_iso_codes_seen"][1]
`); err != nil {
		t.Fatalf("geoip bridge script failed: %v", err)
	}

	assertLuaString(t, L.GetGlobal("result_guid"), "policy-guid")
	assertLuaString(t, L.GetGlobal("result_country"), "FR")
	assertLuaString(t, L.GetGlobal("result_status"), "reject")
	assertLuaString(t, L.GetGlobal("result_native_country"), "DE")
	assertLuaNumber(t, L.GetGlobal("result_asn"), 64500)
	assertLuaString(t, L.GetGlobal("result_iso_seen"), "FR")
}

func TestClickHouseActionUsesNativeGeoIPBridgeValues(t *testing.T) {
	L := newGeoIPBridgeTestState(t)
	defer L.Close()

	preloadClickHouseActionTestModules(t, L)
	loadClickHouseAction(t, L)
	callClickHouseActionWithNativeGeoIP(t, L)
	assertClickHouseGeoIPRow(t, readLastClickHouseRow(t, L))
}

func TestClickHouseActionUsesGeoIPReputationPolicyFacts(t *testing.T) {
	L := newGeoIPBridgeTestState(t)
	defer L.Close()

	preloadClickHouseActionTestModules(t, L)
	loadClickHouseAction(t, L)

	if err := L.DoString(`
ctx_state.policy_facts = {
  geoip_reputation = {
    score = 0.625,
    positive_score = 0.91,
    negative_score = 0.12,
    ip_score = 0.73,
    asn_score = 0.54,
    country_score = 0.31,
    asn_country_score = 0.27,
    samples = 57,
    decision = "suspicious",
  },
}

local request = {
  no_auth = false,
  authenticated = false,
  user_found = false,
  service = "smtp",
  protocol = "smtp",
  method = "plain",
  session = "s-2",
  client_ip = "198.51.100.20",
  client_port = "25",
  username = "bob@example.test",
  account = "",
}

nauthilus_call_action(request)
`); err != nil {
		t.Fatalf("clickhouse action failed: %v", err)
	}

	row := readLastClickHouseRow(t, L)
	assertRowValue(t, row, "reputation_score", 0.625)
	assertRowValue(t, row, "reputation_positive_score", 0.91)
	assertRowValue(t, row, "reputation_negative_score", 0.12)
	assertRowValue(t, row, "reputation_ip_score", 0.73)
	assertRowValue(t, row, "reputation_asn_score", 0.54)
	assertRowValue(t, row, "reputation_country_score", 0.31)
	assertRowValue(t, row, "reputation_asn_country_score", 0.27)
	assertRowValue(t, row, "reputation_samples", float64(57))
	assertRowValue(t, row, "reputation_source", "policy_facts")
	assertRowValue(t, row, "reputation_decision", "suspicious")
}

func newGeoIPBridgeTestState(t *testing.T) *lua.LState {
	t.Helper()

	L := lua.NewState()
	addLuaPluginSharePath(t, L)
	preloadContextStateModule(L)

	return L
}

func preloadContextStateModule(L *lua.LState) {
	state := L.NewTable()
	L.SetGlobal("ctx_state", state)
	L.PreloadModule("nauthilus_context", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("context_get", L.NewFunction(func(L *lua.LState) int {
			L.Push(state.RawGetString(L.CheckString(1)))

			return 1
		}))
		mod.RawSetString("context_set", L.NewFunction(func(L *lua.LState) int {
			state.RawSetString(L.CheckString(1), L.CheckAny(2))

			return 0
		}))
		L.Push(mod)

		return 1
	})
}

func preloadClickHouseActionTestModules(t *testing.T, L *lua.LState) {
	t.Helper()

	builtin := L.NewTable()
	builtin.RawSetString("ACTION_RESULT_OK", lua.LNumber(0))
	L.SetGlobal("nauthilus_builtin", builtin)

	L.PreloadModule("json", luajson.Loader)
	preloadClickHouseUtilModule(L)
	preloadClickHousePasswordModule(L)
	preloadClickHouseCacheModule(L)
	preloadClickHouseRedisModule(L)
	preloadEmptyTableModule(L, "glua_http")
	preloadClickHouseBase64Module(L)
	preloadFixedTimeModule(L, "2023-11-14 22:13:20")
}

func preloadClickHouseUtilModule(L *lua.LState) {
	L.PreloadModule("nauthilus_util", func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			luaFnGetenv: func(L *lua.LState) int {
				name := L.CheckString(1)
				def := L.OptString(2, "")

				switch name {
				case "CLICKHOUSE_BATCH_SIZE":
					L.Push(lua.LString("100"))
				default:
					L.Push(lua.LString(def))
				}

				return 1
			},
			luaFnGetRedisKey: func(L *lua.LState) int {
				L.Push(lua.LString(L.CheckString(2)))

				return 1
			},
			luaFnIsTable: func(L *lua.LState) int {
				L.Push(lua.LBool(L.Get(1).Type() == lua.LTTable))

				return 1
			},
			"table_length": func(L *lua.LState) int {
				tbl, ok := L.Get(1).(*lua.LTable)
				if !ok {
					L.Push(lua.LNumber(0))

					return 1
				}

				count := 0

				tbl.ForEach(func(lua.LValue, lua.LValue) {
					count++
				})
				L.Push(lua.LNumber(count))

				return 1
			},
			luaFnIfErrorRaise: func(L *lua.LState) int {
				if L.Get(1) != lua.LNil {
					L.RaiseError("%s", L.Get(1).String())
				}

				return 0
			},
			"log": func(*lua.LState) int {
				return 0
			},
		})
		L.Push(mod)

		return 1
	})
}

func preloadClickHousePasswordModule(L *lua.LState) {
	preloadStringFunctionModule(L, "nauthilus_password", "generate_password_hash", "hash")
}

func preloadClickHouseCacheModule(L *lua.LState) {
	L.PreloadModule("nauthilus_cache", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("cache_push", L.NewFunction(func(L *lua.LState) int {
			L.SetGlobal("last_clickhouse_row", L.CheckAny(2))
			L.Push(lua.LNumber(1))

			return 1
		}))
		mod.RawSetString("cache_pop_all", L.NewFunction(func(L *lua.LState) int {
			L.Push(L.NewTable())

			return 1
		}))
		L.Push(mod)

		return 1
	})
}

func preloadClickHouseRedisModule(L *lua.LState) {
	L.PreloadModule("nauthilus_redis", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("redis_set", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LBool(true))
			L.Push(lua.LNil)

			return 2
		}))
		L.Push(mod)

		return 1
	})
}

func preloadEmptyTableModule(L *lua.LState, name string) {
	L.PreloadModule(name, func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	})
}

func preloadClickHouseBase64Module(L *lua.LState) {
	L.PreloadModule("base64", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("RawStdEncoding", L.NewTable())
		L.Push(mod)

		return 1
	})
}

func loadClickHouseAction(t *testing.T, L *lua.LState) {
	t.Helper()

	if err := L.DoFile(filepath.Join("..", "lua-plugins.d", "actions", "clickhouse.lua")); err != nil {
		t.Fatalf("failed to load clickhouse action: %v", err)
	}
}

func callClickHouseActionWithNativeGeoIP(t *testing.T, L *lua.LState) {
	t.Helper()

	if err := L.DoString(`
ctx_state["plugin.environment.geoip"] = {
  matched = true,
  country_iso = "DE",
  country_name = "Germany",
  city_name = "Berlin",
  asn = 64500,
  asn_org = "Example Access GmbH",
  asn_prefix = "203.0.113.0/24",
  asn_registry = "ripencc",
  asn_country_iso = "DE",
  asn_allocated = "2024-01-01",
  asn_status = "allocated",
}

ctx_state.rt = {}
ctx_state.rt.geoip_reputation = {
  score = 0.375,
  positive_score = 0.82,
  negative_score = 0.14,
  ip_score = 0.71,
  asn_score = 0.48,
  country_score = 0.22,
  asn_country_score = 0.19,
  samples = 42,
  source = "redis",
  decision = "suspicious",
}

local request = {
  no_auth = false,
  authenticated = false,
  user_found = false,
  service = "imap",
  protocol = "imap",
  method = "plain",
  session = "s-1",
  client_ip = "203.0.113.10",
  client_port = "12345",
  username = "alice@example.test",
  account = "",
}

nauthilus_call_action(request)
`); err != nil {
		t.Fatalf("clickhouse action failed: %v", err)
	}
}

func readLastClickHouseRow(t *testing.T, L *lua.LState) map[string]any {
	t.Helper()

	rowJSON := L.GetGlobal("last_clickhouse_row").String()
	if rowJSON == "" || rowJSON == lua.LNil.String() {
		t.Fatal("clickhouse action did not queue a row")
	}

	var row map[string]any
	if err := json.Unmarshal([]byte(rowJSON), &row); err != nil {
		t.Fatalf("decode clickhouse row: %v", err)
	}

	return row
}

func assertClickHouseGeoIPRow(t *testing.T, row map[string]any) {
	t.Helper()

	assertRowValue(t, row, "geoip_country", "DE")
	assertRowValue(t, row, "geoip_source", "native_geoip")
	assertRowValue(t, row, "geoip_status", "matched")
	assertRowValue(t, row, "geoip_asn", float64(64500))
	assertRowValue(t, row, "geoip_asn_org", "Example Access GmbH")
	assertRowValue(t, row, "geoip_asn_prefix", "203.0.113.0/24")
	assertRowValue(t, row, "geoip_asn_registry", "ripencc")
	assertRowValue(t, row, "geoip_asn_country", "DE")
	assertRowValue(t, row, "geoip_asn_allocated", "2024-01-01")
	assertRowValue(t, row, "geoip_asn_status", "allocated")
	assertRowValue(t, row, "reputation_score", 0.375)
	assertRowValue(t, row, "reputation_positive_score", 0.82)
	assertRowValue(t, row, "reputation_negative_score", 0.14)
	assertRowValue(t, row, "reputation_ip_score", 0.71)
	assertRowValue(t, row, "reputation_asn_score", 0.48)
	assertRowValue(t, row, "reputation_country_score", 0.22)
	assertRowValue(t, row, "reputation_asn_country_score", 0.19)
	assertRowValue(t, row, "reputation_samples", float64(42))
	assertRowValue(t, row, "reputation_source", "redis")
	assertRowValue(t, row, "reputation_decision", "suspicious")
}

func assertLuaString(t *testing.T, value lua.LValue, want string) {
	t.Helper()

	if got := value.String(); got != want {
		t.Fatalf("Lua value = %q, want %q", got, want)
	}
}

func assertLuaNumber(t *testing.T, value lua.LValue, want float64) {
	t.Helper()

	got, ok := value.(lua.LNumber)
	if !ok {
		t.Fatalf("Lua value type = %s, want number", value.Type())
	}

	if float64(got) != want {
		t.Fatalf("Lua value = %v, want %v", got, want)
	}
}

func assertRowValue(t *testing.T, row map[string]any, key string, want any) {
	t.Helper()

	if got := row[key]; got != want {
		t.Fatalf("row[%s] = %#v, want %#v", key, got, want)
	}
}
