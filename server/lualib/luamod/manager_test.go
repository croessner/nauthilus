// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package luamod

import (
	"context"
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luapool"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	lua "github.com/yuin/gopher-lua"
)

const policyRequestProfileAssertions = `
assert(dynamic_loader == nil)
for _, name in ipairs(forbidden_modules) do
  local ok = pcall(require, name)
  assert(ok == false, name)
end

local redis = require("nauthilus_redis")
assert(redis.register_redis_pool == nil)
assert(type(redis.get_redis_connection) == "function")
local named, named_error = redis.get_redis_connection("ambient")
assert(named == nil and type(named_error) == "string")
assert(redis.redis_run_script == nil)
assert(redis.redis_upload_script == nil)
assert(redis.redis_set == nil)
assert(type(redis.redis_get) == "function")

local psnet = require("nauthilus_psnet")
assert(psnet.register_connection_target == nil)
assert(type(psnet.get_connection_target) == "function")

local brute_force = require("nauthilus_brute_force")
assert(brute_force.set_custom_tolerations == nil)
assert(brute_force.set_custom_toleration == nil)
assert(brute_force.delete_custom_toleration == nil)
assert(type(brute_force.get_custom_tolerations) == "function")

local i18n = require("nauthilus_i18n")
assert(i18n.register_catalog == nil)
assert(type(i18n.get_localized) == "function")

local misc = require("nauthilus_misc")
assert(misc.wait_random == nil)
assert(type(misc.get_country_name) == "function")

local cache = require("nauthilus_cache")
assert(cache.cache_set == nil)
assert(cache.cache_delete == nil)
assert(type(cache.cache_get) == "function")

local prometheus = require("nauthilus_prometheus")
assert(prometheus.create_counter_vec == nil)
assert(type(prometheus.increment_counter) == "function")

local policy_time = require("time")
assert(type(policy_time.unix) == "function")
assert(type(policy_time.format) == "function")
`

func TestRequestI18NRuntimeDoesNotFallBackToProcessDefault(t *testing.T) {
	processDefault := lualib.DefaultI18NRuntime()
	runtime := requestI18NRuntime(context.Background())

	if runtime == nil {
		t.Fatal("requestI18NRuntime() = nil, would select the process default")
	}

	if runtime == processDefault {
		t.Fatal("requestI18NRuntime() returned the process default")
	}
}

func TestPolicyRequestProfileOmitsMutableModulesAndRegistrationFunctions(t *testing.T) {
	configured := &config.FileSettings{Server: &config.ServerSection{}}

	state := luapool.NewLuaState(http.DefaultClient, configured)
	defer state.Close()

	requestCtx := lualib.NewContext()

	if err := luaseal.PreparePolicyProfile(state, nil, luaseal.PolicyProfileEnvironment); err != nil {
		t.Fatalf("PreparePolicyProfile() error = %v", err)
	}

	luapool.PrepareRequestEnv(state)

	manager := NewModuleManager(t.Context(), configured, nil, nil)
	manager.BindAllPolicyRequest(t.Context(), state, requestCtx, nil)

	if err := luaseal.InstallPolicy(state, nil); err != nil {
		t.Fatalf("InstallPolicy() error = %v", err)
	}

	state.SetGlobal("forbidden_modules", luaStringTable(state, []string{
		definitions.LuaModMail,
		definitions.LuaModLDAP,
		definitions.LuaModBackend,
		definitions.LuaModSoftWhitelist,
		definitions.LuaModDNS,
		"glua_http",
	}))

	if err := state.DoString(policyRequestProfileAssertions); err != nil {
		t.Fatalf("Policy request profile: %v", err)
	}
}

// luaStringTable projects one immutable Go string slice into Lua assertions.
func luaStringTable(state *lua.LState, values []string) *lua.LTable {
	table := state.NewTable()
	for _, value := range values {
		table.Append(lua.LString(value))
	}

	return table
}
