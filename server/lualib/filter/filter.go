package filter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

var LuaFilters *PreCompiledLuaFilters

func PreCompileLuaFilters() (err error) {
	if config.LoadableConfig.Lua != nil {
		if LuaFilters == nil {
			LuaFilters = &PreCompiledLuaFilters{}
		} else {
			LuaFilters.Reset()
		}

		for index := range config.LoadableConfig.Lua.Filters {
			var luaFilter *LuaFilter

			luaFilter, err = NewLuaFilter(config.LoadableConfig.Lua.Filters[index].Name, config.LoadableConfig.Lua.Filters[index].ScriptPath)
			if err != nil {
				return err
			}

			// Add compiled Lua Filters.
			LuaFilters.Add(luaFilter)
		}
	}

	return nil
}

type PreCompiledLuaFilters struct {
	LuaScripts []*LuaFilter
	Mu         sync.RWMutex
}

func (a *PreCompiledLuaFilters) Add(luaFilter *LuaFilter) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaFilter)
}

func (a *PreCompiledLuaFilters) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaFilter, 0)
}

type LuaFilter struct {
	Name           string
	CompiledScript *lua.FunctionProto
}

func NewLuaFilter(name string, scriptPath string) (*LuaFilter, error) {
	if name == "" {
		return nil, errors2.ErrFilterLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors2.ErrFilterLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaFilter{
		Name:           name,
		CompiledScript: compiledScript,
	}, nil
}

type Request struct {
	Debug         bool
	UserFound     bool
	Authenticated bool
	NoAuth        bool

	Session      string // GUID
	ClientIP     string
	ClientPort   string
	ClientHost   string
	ClientID     string
	LocalIP      string
	LocalPort    string
	Username     string
	Account      string
	UniqueUserID string
	DisplayName  string
	Password     string
	Protocol     string

	Logs *lualib.CustomLogKeyValue

	*lualib.Context
}

// CallFilterLua calls all defined Lua scripts and returns the action state and error.
func (r *Request) CallFilterLua(ctx *gin.Context) (action bool, err error) {
	if LuaFilters == nil || len(LuaFilters.LuaScripts) == 0 {
		return false, errors2.ErrNoFiltersDefined
	}

	resultMap := make(map[int]string, 2)

	resultMap[0] = "ok"
	resultMap[1] = "fail"

	LuaFilters.Mu.RLock()

	defer LuaFilters.Mu.RUnlock()

	L := lua.NewState()

	// Useful libraries
	libs.Preload(L)
	gluacrypto.Preload(L)

	if config.EnvConfig.DevMode {
		util.DebugModule(decl.DbgFilter, decl.LogKeyMsg, fmt.Sprintf("%+v", r))
	}

	r.Logs = new(lualib.CustomLogKeyValue)
	globals := L.NewTable()

	globals.RawSet(lua.LString(decl.LuaFilterAccept), lua.LBool(false))
	globals.RawSet(lua.LString(decl.LuaFilterREJECT), lua.LBool(true))
	globals.RawSet(lua.LString(decl.LuaFilterResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(decl.LuaFilterResultFail), lua.LNumber(1))

	globals.RawSetString(decl.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(r.Context)))
	globals.RawSetString(decl.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(r.Context)))
	globals.RawSetString(decl.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(r.Context)))
	globals.RawSetString(decl.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))

	L.SetGlobal(decl.LuaDefaultTable, globals)

	request := L.NewTable()

	request.RawSet(lua.LString(decl.LuaRequestDebug), lua.LBool(r.Debug))
	request.RawSet(lua.LString(decl.LuaRequestNoAuth), lua.LBool(r.NoAuth))
	request.RawSet(lua.LString(decl.LuaRequestAuthenticated), lua.LBool(r.Authenticated))
	request.RawSet(lua.LString(decl.LuaRequestUserFound), lua.LBool(r.UserFound))
	request.RawSetString(decl.LuaRequestSession, lua.LString(r.Session))
	request.RawSetString(decl.LuaRequestClientIP, lua.LString(r.ClientIP))
	request.RawSetString(decl.LuaRequestClientPort, lua.LString(r.ClientPort))
	request.RawSetString(decl.LuaRequestClientHost, lua.LString(r.ClientHost))
	request.RawSetString(decl.LuaRequestClientID, lua.LString(r.ClientID))
	request.RawSetString(decl.LuaRequestLocalIP, lua.LString(r.LocalIP))
	request.RawSetString(decl.LuaRequestLocalPort, lua.LString(r.LocalPort))
	request.RawSetString(decl.LuaRequestUsername, lua.LString(r.Username))
	request.RawSetString(decl.LuaRequestAccount, lua.LString(r.Account))
	request.RawSetString(decl.LuaRequestUniqueUserID, lua.LString(r.UniqueUserID))
	request.RawSetString(decl.LuaRequestDisplayName, lua.LString(r.DisplayName))
	request.RawSetString(decl.LuaRequestPassword, lua.LString(r.Password))
	request.RawSetString(decl.LuaRequestProtocol, lua.LString(r.Protocol))

	for index := range LuaFilters.LuaScripts {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}

		luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

		L.SetContext(luaCtx)

		if err = lualib.DoCompiledFile(L, LuaFilters.LuaScripts[index].CompiledScript); err != nil {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyGUID, r.Session,
				"name", LuaFilters.LuaScripts[index].Name,
				decl.LogKeyError, err,
			)

			luaCancel()

			continue
		}

		if err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal(decl.LuaFnCallFilter),
			NRet:    2,
			Protect: true,
		}, request); err != nil {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyGUID, r.Session,
				"name", LuaFilters.LuaScripts[index].Name,
				decl.LogKeyError, err,
			)

			luaCancel()

			continue
		}

		ret := L.ToInt(-1)
		L.Pop(1)

		action = L.ToBool(-1)
		L.Pop(1)

		if err == nil {
			level.Info(logging.DefaultLogger).Log(
				decl.LogKeyGUID, r.Session,
				"name", LuaFilters.LuaScripts[index].Name,
				decl.LogKeyMsg, "Lua Filter finished",
				"action", action,
				"result", func() string {
					if ret == 0 || ret == 1 {
						return resultMap[ret]
					}

					return fmt.Sprintf("unknown(%d)", ret)
				}(),
			)
		}

		luaCancel()

		if action {
			break
		}
	}

	return
}
