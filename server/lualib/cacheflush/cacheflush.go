// Copyright (C) 2025 Christian Rößner
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

// Package cacheflush executes the optional Lua callback used by cache flush endpoints.
package cacheflush

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luamod"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/rediscli"

	lua "github.com/yuin/gopher-lua"
)

// Result holds the return values from the Lua cache flush script.
type Result struct {
	// AdditionalKeys contains additional Redis keys to delete.
	AdditionalKeys []string

	// AccountName is an optional account name. If non-empty, the caller can skip account lookup.
	AccountName string
}

var (
	compiledScript *lua.FunctionProto
	compileMu      sync.RWMutex
)

// compileScript compiles the Lua cache flush script and caches the result.
func compileScript(scriptPath string) (*lua.FunctionProto, error) {
	compileMu.RLock()
	if compiledScript != nil {
		defer compileMu.RUnlock()

		return compiledScript, nil
	}
	compileMu.RUnlock()

	compileMu.Lock()
	defer compileMu.Unlock()

	// Double-check after acquiring write lock.
	if compiledScript != nil {
		return compiledScript, nil
	}

	proto, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("compiling cache flush script %s: %w", scriptPath, err)
	}

	compiledScript = proto

	return compiledScript, nil
}

// RunCacheFlushScript executes the configured Lua cache flush script.
// It passes the user information as a request table and returns additional Redis keys
// and an optional account name from the script.
// If no script is configured, it returns nil (no-op).
func RunCacheFlushScript(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, user string, guid string) (*Result, error) {
	scriptPath := cfg.GetLuaCacheFlushScriptPath()
	if scriptPath == "" {
		return nil, nil
	}

	proto, err := compileScript(scriptPath)
	if err != nil {
		return nil, err
	}

	luaCtx, luaCancel := context.WithTimeout(ctx, cfg.GetServer().GetTimeouts().GetLuaScript())
	defer luaCancel()

	pool := vmpool.GetManager().GetOrCreate("cacheflush:default", vmpool.PoolOptions{
		MaxVMs: cfg.GetLuaHookVMPoolSize(),
		Config: cfg,
	})

	L, acqErr := pool.Acquire(luaCtx)
	if acqErr != nil {
		return nil, fmt.Errorf("acquiring Lua VM for cache flush script: %w", acqErr)
	}

	replaceVM := false

	defer func() {
		if r := recover(); r != nil {
			replaceVM = true
		}

		if replaceVM {
			pool.Replace(L)
		} else {
			pool.Release(L)
		}
	}()

	L.SetContext(luaCtx)

	luapool.PrepareRequestEnv(L)

	modManager := luamod.NewModuleManager(ctx, cfg, logger, redisClient)

	modManager.BindAllDefault(L, lualib.NewContext(), luaCtx, tolerate.GetTolerate())
	modManager.BindLDAP(L, backend.LoaderModLDAP(luaCtx, cfg))
	logs := new(lualib.CustomLogKeyValue)
	var statusMessage *string

	lualib.SetBuiltinTableForCacheFlush(
		L,
		lualib.NewLoggingManager(luaCtx, cfg, logger, logs).AddCustomLog,
		&statusMessage,
	)
	// The cache-flush callback is an administrative maintenance hook.
	// A Lua status_message_set() value is intentionally not propagated to user-facing auth responses.

	requestTable := buildRequestTable(L, cfg, user, guid)

	if err = executeCacheFlushScript(L, cfg, proto, requestTable, scriptPath); err != nil {
		logScriptError(logger, err, scriptPath)

		return nil, err
	}

	logCustomLogs(logger, guid, scriptPath, *logs)

	return parseReturnValues(L), nil
}

// resolveLuaFunction looks up a Lua function first in __NAUTH_REQ_ENV, then in _G.
func resolveLuaFunction(L *lua.LState, name string) lua.LValue {
	if v := L.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
		if fn := L.GetField(v, name); fn != nil && fn != lua.LNil {
			return fn
		}
	}

	return L.GetGlobal(name)
}

func buildRequestTable(L *lua.LState, cfg config.File, user string, guid string) *lua.LTable {
	requestTable := L.NewTable()
	cr := lualib.GetCommonRequest()
	cr.Session = guid
	cr.Username = user
	cr.RedisPrefix = cfg.GetServer().GetRedis().GetPrefix()
	cr.SetupRequest(L, cfg, requestTable)
	lualib.PutCommonRequest(cr)

	return requestTable
}

func executeCacheFlushScript(L *lua.LState, cfg config.File, proto *lua.FunctionProto, requestTable *lua.LTable, scriptPath string) error {
	if err := lualib.PackagePath(L, cfg); err != nil {
		return err
	}

	if err := lualib.DoCompiledFile(L, proto); err != nil {
		return err
	}

	entryFn := resolveLuaFunction(L, definitions.LuaFnCacheFlushHook)
	if entryFn.Type() != lua.LTFunction {
		return fmt.Errorf("entry function '%s' is not defined in the cache flush script %s", definitions.LuaFnCacheFlushHook, scriptPath)
	}

	return L.CallByParam(lua.P{
		Fn:      entryFn,
		NRet:    2,
		Protect: true,
	}, requestTable)
}

// parseReturnValues extracts the two return values from the Lua stack:
// 1. A table (list of strings) - additional Redis keys to delete
// 2. A string - account name
func parseReturnValues(L *lua.LState) *Result {
	result := &Result{}

	top := L.GetTop()

	// First return value: table of additional keys (or nil)
	if top >= 1 {
		lv := L.Get(-top)
		if lv != lua.LNil {
			if goVal := convert.LuaValueToGo(lv); goVal != nil {
				if arr, ok := goVal.([]any); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							result.AdditionalKeys = append(result.AdditionalKeys, s)
						}
					}
				}
			}
		}
	}

	// Second return value: account name string (or nil)
	if top >= 2 {
		lv := L.Get(-top + 1)
		if lv != lua.LNil {
			if s, ok := lv.(lua.LString); ok {
				result.AccountName = string(s)
			}
		}
	}

	return result
}

// logScriptError logs an error that occurred during cache flush script execution.
func logScriptError(logger *slog.Logger, err error, scriptPath string) {
	if ae, ok := errors.AsType[*lua.ApiError](err); ok && ae != nil {
		_ = level.Error(logger).Log(
			"script", scriptPath,
			definitions.LogKeyMsg, "Error executing cache flush script",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		)

		return
	}

	_ = level.Error(logger).Log(
		"script", scriptPath,
		definitions.LogKeyMsg, "Error executing cache flush script",
		definitions.LogKeyError, err,
	)
}

func logCustomLogs(logger *slog.Logger, guid string, scriptPath string, logs lualib.CustomLogKeyValue) {
	if len(logs) == 0 {
		return
	}

	keyvals := make([]any, 0, len(logs)+6)
	keyvals = append(keyvals,
		definitions.LogKeyGUID, guid,
		"script", scriptPath,
		definitions.LogKeyMsg, "Lua cache flush custom logs",
	)
	keyvals = append(keyvals, logs...)

	_ = level.Info(logger).Log(keyvals...)
}
