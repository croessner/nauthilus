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
	"path/filepath"
	"strconv"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

const luaReputationTestThreshold = "0.2"

func TestGeoIPReputationTracksFailedLoginAndEmitsRiskScore(t *testing.T) {
	L, redisState := newGeoIPReputationTestState(t)
	defer L.Close()

	loadGeoIPReputationSubject(t, L)
	callGeoIPReputationSubject(t, L, false)

	assertRedisHashValue(t, redisState, "nt:geoip:reputation:ip:203.0.113.10", "failure", 1)
	assertRedisHashValue(t, redisState, "nt:geoip:reputation:asn:64500", "failure", 1)
	assertPositiveLuaNumber(t, geoIPReputationFact(t, L, "ip_score"))
	assertPositiveLuaNumber(t, geoIPReputationRT(t, L, "ip_score"))
	assertLuaString(t, geoIPReputationFact(t, L, "decision"), "suspicious")
	assertLuaString(t, geoIPReputationRT(t, L, "source"), "redis")
}

func TestGeoIPReputationTracksSuccessfulLoginAndEmitsTrustScore(t *testing.T) {
	L, redisState := newGeoIPReputationTestState(t)
	defer L.Close()

	loadGeoIPReputationSubject(t, L)
	callGeoIPReputationSubject(t, L, true)

	assertRedisHashValue(t, redisState, "nt:geoip:reputation:ip:203.0.113.10", "success", 1)
	assertRedisHashValue(t, redisState, "nt:geoip:reputation:country:DE", "success", 1)
	assertNegativeLuaNumber(t, geoIPReputationFact(t, L, "ip_score"))
	assertPositiveLuaNumber(t, geoIPReputationFact(t, L, "negative_score"))
	assertLuaString(t, geoIPReputationFact(t, L, "decision"), "trusted")
}

func TestGeoIPReputationSkipsBackendHealthChecks(t *testing.T) {
	L, redisState := newGeoIPReputationTestState(t)
	defer L.Close()

	loadGeoIPReputationSubject(t, L)
	callGeoIPReputationSubjectWithHealthCheck(t, L, false, true)

	if len(redisState) != 0 {
		t.Fatalf("redis reputation state = %#v, want no health-check writes", redisState)
	}

	ctxState := luaTableValue(t, L.GetGlobal("ctx_state"), "ctx_state")
	if policyFacts := ctxState.RawGetString("policy_facts"); policyFacts != lua.LNil {
		assertLuaTableMissingKey(t, policyFacts, "geoip_reputation")
	}

	if rt := ctxState.RawGetString("rt"); rt != lua.LNil {
		assertLuaTableMissingKey(t, rt, "geoip_reputation")
	}
}

type geoIPReputationRedisState map[string]map[string]float64

func newGeoIPReputationTestState(t *testing.T) (*lua.LState, geoIPReputationRedisState) {
	t.Helper()

	L := lua.NewState()
	addLuaPluginSharePath(t, L)
	preloadContextStateModule(L)
	L.PreloadModule("nauthilus_policy", LoaderPolicyStatelessForTest())

	redisState := geoIPReputationRedisState{}
	preloadGeoIPReputationTestModules(t, L, redisState)
	setGeoIPReputationNativeContext(t, L)

	return L, redisState
}

func preloadGeoIPReputationTestModules(t *testing.T, L *lua.LState, redisState geoIPReputationRedisState) {
	t.Helper()

	preloadGeoIPReputationBuiltin(L)
	preloadGeoIPReputationUtilModule(L)
	preloadGeoIPReputationRedisModule(L, redisState)
}

func preloadGeoIPReputationBuiltin(L *lua.LState) {
	builtin := L.NewTable()
	builtin.RawSetString("SUBJECT_ACCEPT", lua.LNumber(0))
	builtin.RawSetString("SUBJECT_RESULT_OK", lua.LNumber(0))
	builtin.RawSetString("custom_log_add", L.NewFunction(func(*lua.LState) int {
		return 0
	}))
	L.SetGlobal("nauthilus_builtin", builtin)
}

func preloadGeoIPReputationUtilModule(L *lua.LState) {
	L.PreloadModule("nauthilus_util", func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			luaFnGetenv: func(L *lua.LState) int {
				name := L.CheckString(1)
				def := L.OptString(2, "")

				values := map[string]string{
					"GEOIP_REPUTATION_ALPHA":                "1",
					"GEOIP_REPUTATION_SATURATION":           "1",
					"GEOIP_REPUTATION_TEMPERATURE":          "1",
					"GEOIP_REPUTATION_SUSPICIOUS_THRESHOLD": luaReputationTestThreshold,
					"GEOIP_REPUTATION_TRUSTED_THRESHOLD":    luaReputationTestThreshold,
				}

				if value, ok := values[name]; ok {
					L.Push(lua.LString(value))
				} else {
					L.Push(lua.LString(def))
				}

				return 1
			},
			luaFnGetRedisKey: func(L *lua.LState) int {
				L.Push(lua.LString("nt:" + L.CheckString(2)))

				return 1
			},
			luaFnIfErrorRaise: func(L *lua.LState) int {
				if L.Get(1) != lua.LNil {
					L.RaiseError("%s", L.Get(1).String())
				}

				return 0
			},
			luaFnIsTable: func(L *lua.LState) int {
				L.Push(lua.LBool(L.Get(1).Type() == lua.LTTable))

				return 1
			},
			luaFnLogInfo: func(*lua.LState) int {
				return 0
			},
		})
		L.Push(mod)

		return 1
	})
}

func preloadGeoIPReputationRedisModule(L *lua.LState, redisState geoIPReputationRedisState) {
	L.PreloadModule("nauthilus_redis", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("redis_pipeline", L.NewFunction(func(L *lua.LState) int {
			results := runGeoIPReputationRedisPipeline(L, redisState)
			L.Push(results)
			L.Push(lua.LNil)

			return 2
		}))
		L.Push(mod)

		return 1
	})
}

func runGeoIPReputationRedisPipeline(L *lua.LState, redisState geoIPReputationRedisState) *lua.LTable {
	L.CheckString(2)
	commands := L.CheckTable(3)
	results := L.NewTable()

	commands.ForEach(func(_, row lua.LValue) {
		results.Append(handleGeoIPReputationRedisCommand(L, redisState, row))
	})

	return results
}

func handleGeoIPReputationRedisCommand(
	L *lua.LState,
	redisState geoIPReputationRedisState,
	row lua.LValue,
) *lua.LTable {
	rowTable, ok := row.(*lua.LTable)
	if !ok {
		return redisPipelineResult(L, lua.LNil)
	}

	command := rowTable.RawGetInt(1).String()
	key := rowTable.RawGetInt(2).String()
	hash := redisState.ensureHash(key)

	switch command {
	case "hincrby":
		return handleGeoIPReputationHIncrBy(L, rowTable, hash)
	case "expire":
		return redisPipelineResult(L, lua.LBool(true))
	case "hgetall":
		return redisPipelineResult(L, geoIPReputationHashTable(L, hash))
	default:
		return redisPipelineResult(L, lua.LNil)
	}
}

func handleGeoIPReputationHIncrBy(L *lua.LState, rowTable *lua.LTable, hash map[string]float64) *lua.LTable {
	field := rowTable.RawGetInt(3).String()
	increment := float64(lua.LVAsNumber(rowTable.RawGetInt(4)))
	hash[field] += increment

	return redisPipelineResult(L, lua.LNumber(hash[field]))
}

func geoIPReputationHashTable(L *lua.LState, hash map[string]float64) *lua.LTable {
	value := L.NewTable()
	for field, fieldValue := range hash {
		value.RawSetString(field, lua.LString(strconv.FormatFloat(fieldValue, 'f', -1, 64)))
	}

	return value
}

func (state geoIPReputationRedisState) ensureHash(key string) map[string]float64 {
	if state[key] == nil {
		state[key] = map[string]float64{}
	}

	return state[key]
}

func redisPipelineResult(L *lua.LState, value lua.LValue) *lua.LTable {
	result := L.NewTable()
	result.RawSetString("ok", lua.LBool(true))
	result.RawSetString("value", value)

	return result
}

func setGeoIPReputationNativeContext(t *testing.T, L *lua.LState) {
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
}
`); err != nil {
		t.Fatalf("failed to seed native GeoIP context: %v", err)
	}
}

func loadGeoIPReputationSubject(t *testing.T, L *lua.LState) {
	t.Helper()

	scriptPath := filepath.Join("..", "lua-plugins.d", "subject", "geoip_reputation.lua")
	if err := L.DoFile(scriptPath); err != nil {
		t.Fatalf("failed to load geoip reputation subject: %v", err)
	}
}

func callGeoIPReputationSubject(t *testing.T, L *lua.LState, authenticated bool) {
	t.Helper()

	callGeoIPReputationSubjectWithHealthCheck(t, L, authenticated, false)
}

func callGeoIPReputationSubjectWithHealthCheck(t *testing.T, L *lua.LState, authenticated bool, healthCheck bool) {
	t.Helper()

	request := L.NewTable()
	request.RawSetString("no_auth", lua.LBool(false))
	request.RawSetString("health_check", lua.LBool(healthCheck))
	request.RawSetString("authenticated", lua.LBool(authenticated))
	request.RawSetString("client_ip", lua.LString("203.0.113.10"))
	request.RawSetString("username", lua.LString("alice@example.test"))
	request.RawSetString("account", lua.LString("alice@example.test"))
	request.RawSetString("protocol", lua.LString("imap"))

	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("nauthilus_call_subject"),
		NRet:    2,
		Protect: true,
	}, request); err != nil {
		t.Fatalf("geoip reputation subject failed: %v", err)
	}
}

func geoIPReputationFact(t *testing.T, L *lua.LState, key string) lua.LValue {
	t.Helper()

	facts := luaTableField(t, luaTableField(t, luaTableField(t, L.GetGlobal("ctx_state"), "policy_facts"), "geoip_reputation"), key)

	return facts
}

func geoIPReputationRT(t *testing.T, L *lua.LState, key string) lua.LValue {
	t.Helper()

	return luaTableField(t, luaTableField(t, luaTableField(t, L.GetGlobal("ctx_state"), "rt"), "geoip_reputation"), key)
}

func luaTableField(t *testing.T, value lua.LValue, key string) lua.LValue {
	t.Helper()

	tableValue := luaTableValue(t, value, key)

	field := tableValue.RawGetString(key)
	if field == lua.LNil {
		t.Fatalf("Lua table missing key %q", key)
	}

	return field
}

func luaTableValue(t *testing.T, value lua.LValue, key string) *lua.LTable {
	t.Helper()

	tableValue, ok := value.(*lua.LTable)
	if !ok {
		t.Fatalf("Lua value for %q has type %s, want table", key, value.Type())
	}

	return tableValue
}

func assertLuaTableMissingKey(t *testing.T, value lua.LValue, key string) {
	t.Helper()

	tableValue := luaTableValue(t, value, key)

	if field := tableValue.RawGetString(key); field != lua.LNil {
		t.Fatalf("Lua table key %q = %s, want nil", key, field.String())
	}
}

func assertRedisHashValue(t *testing.T, state geoIPReputationRedisState, key string, field string, want float64) {
	t.Helper()

	hash, ok := state[key]
	if !ok {
		t.Fatalf("Redis key %q missing", key)
	}

	if got := hash[field]; got != want {
		t.Fatalf("Redis hash %s[%s] = %v, want %v", key, field, got, want)
	}
}

func assertPositiveLuaNumber(t *testing.T, value lua.LValue) {
	t.Helper()

	number, ok := value.(lua.LNumber)
	if !ok {
		t.Fatalf("Lua value type = %s, want number", value.Type())
	}

	if number <= 0 {
		t.Fatalf("Lua number = %v, want positive", number)
	}
}

func assertNegativeLuaNumber(t *testing.T, value lua.LValue) {
	t.Helper()

	number, ok := value.(lua.LNumber)
	if !ok {
		t.Fatalf("Lua value type = %s, want number", value.Type())
	}

	if number >= 0 {
		t.Fatalf("Lua number = %v, want negative", number)
	}
}
