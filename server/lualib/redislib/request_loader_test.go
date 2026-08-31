// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package redislib

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	lua "github.com/yuin/gopher-lua"
)

// TestLoaderModRedisRequestHidesPoolRegistration proves Policy request VMs cannot mutate process Redis pools.
func TestLoaderModRedisRequestHidesPoolRegistration(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	state.PreloadModule(
		definitions.LuaModRedis,
		LoaderModRedisRequest(context.Background(), &config.FileSettings{}, rediscli.Client(nil)),
	)

	if err := state.DoString(`
		local redis = require("nauthilus_redis")
		assert(redis.register_redis_pool == nil)
		assert(type(redis.get_redis_connection) == "function")
		local named, named_error = redis.get_redis_connection("ambient")
		assert(named == nil and type(named_error) == "string")
		assert(redis.redis_run_script == nil)
		assert(redis.redis_upload_script == nil)
		assert(redis.redis_set == nil)
		assert(type(redis.redis_get) == "function")
	`); err != nil {
		t.Fatalf("restricted Redis module: %v", err)
	}
}
