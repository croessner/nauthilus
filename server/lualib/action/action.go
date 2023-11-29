package action

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	"github.com/yuin/gopher-lua"
)

var (
	RequestChan   chan *Action
	WorkerEndChan chan lualib.Done
)

type Done struct{}

type LuaScriptAction struct {
	ScriptPath     string
	ScriptCompiled *lua.FunctionProto
	LuaAction      decl.LuaAction
}

// Action contains a subset of the Authentication structure.
type Action struct {
	LuaAction decl.LuaAction

	Debug         bool
	Repeating     bool
	UserFound     bool
	Authenticated bool
	NoAuth        bool

	BruteForceCounter uint

	Session      string // GUID
	ClientIP     string
	ClientPort   string
	ClientNet    string
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

	BruteForceName string
	FeatureName    string

	*lualib.Context

	FinishedChan chan Done
}

func Worker(ctx context.Context) {
	var (
		err              error
		luaActionRequest *Action
		actionScripts    []*LuaScriptAction
	)

	resultMap := make(map[int]string, 2)

	resultMap[0] = "ok"
	resultMap[1] = "fail"

	RequestChan = make(chan *Action, decl.MaxChannelSize)

	if config.LoadableConfig.Lua == nil {
		return
	}

	for index := range config.LoadableConfig.Lua.Actions {
		var scriptCompiled *lua.FunctionProto

		luaAction := &LuaScriptAction{}

		actionType, scriptPath := config.LoadableConfig.Lua.Actions[index].GetAction()

		switch actionType {
		case decl.LuaActionBruteForceName:
			luaAction.LuaAction = decl.LuaActionBruteForce
		case decl.LuaActionRBLName:
			luaAction.LuaAction = decl.LuaActionRBL
		case decl.LuaActionTLSName:
			luaAction.LuaAction = decl.LuaActionTLS
		case decl.LuaActionRelayDomainsName:
			luaAction.LuaAction = decl.LuaActionRelayDomains
		case decl.LuaActionLuaName:
			luaAction.LuaAction = decl.LuaActionLua
		case decl.LuaActionPostName:
			luaAction.LuaAction = decl.LuaActionPost
		default:
			luaAction.LuaAction = decl.LuaActionNone
		}

		if luaAction.LuaAction != decl.LuaActionNone {
			if scriptCompiled, err = lualib.CompileLua(scriptPath); err != nil {
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

				continue
			}

			luaAction.ScriptPath = scriptPath
			luaAction.ScriptCompiled = scriptCompiled

			actionScripts = append(actionScripts, luaAction)
		}
	}

	for {
		select {
		case <-ctx.Done():
			WorkerEndChan <- lualib.Done{}

			break

		case luaActionRequest = <-RequestChan:
			L := lua.NewState()

			// Useful libraries
			libs.Preload(L)
			gluacrypto.Preload(L)

			if config.EnvConfig.DevMode {
				util.DebugModule(decl.DbgAction, decl.LogKeyMsg, fmt.Sprintf("%+v", luaActionRequest))
			}

			logs := new(lualib.CustomLogKeyValue)
			globals := L.NewTable()

			globals.RawSet(lua.LString(decl.LuaActionResultOk), lua.LNumber(0))
			globals.RawSet(lua.LString(decl.LuaActionResultFail), lua.LNumber(1))

			globals.RawSetString(decl.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(luaActionRequest.Context)))
			globals.RawSetString(decl.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(luaActionRequest.Context)))
			globals.RawSetString(decl.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(luaActionRequest.Context)))
			globals.RawSetString(decl.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))

			L.SetGlobal(decl.LuaDefaultTable, globals)

			request := L.NewTable()

			request.RawSet(lua.LString(decl.LuaRequestDebug), lua.LBool(luaActionRequest.Debug))
			request.RawSet(lua.LString(decl.LuaRequestRepeating), lua.LBool(luaActionRequest.Repeating))
			request.RawSet(lua.LString(decl.LuaRequestBruteForceCounter), lua.LNumber(luaActionRequest.BruteForceCounter))
			request.RawSet(lua.LString(decl.LuaRequestNoAuth), lua.LBool(luaActionRequest.NoAuth))
			request.RawSet(lua.LString(decl.LuaRequestAuthenticated), lua.LBool(luaActionRequest.Authenticated))
			request.RawSet(lua.LString(decl.LuaRequestUserFound), lua.LBool(luaActionRequest.UserFound))
			request.RawSetString(decl.LuaRequestSession, lua.LString(luaActionRequest.Session))
			request.RawSetString(decl.LuaRequestClientIP, lua.LString(luaActionRequest.ClientIP))
			request.RawSetString(decl.LuaRequestClientPort, lua.LString(luaActionRequest.ClientPort))
			request.RawSetString(decl.LuaRequestClientNet, lua.LString(luaActionRequest.ClientNet))
			request.RawSetString(decl.LuaRequestClientHost, lua.LString(luaActionRequest.ClientHost))
			request.RawSetString(decl.LuaRequestClientID, lua.LString(luaActionRequest.ClientID))
			request.RawSetString(decl.LuaRequestLocalIP, lua.LString(luaActionRequest.LocalIP))
			request.RawSetString(decl.LuaRequestLocalPort, lua.LString(luaActionRequest.LocalPort))
			request.RawSetString(decl.LuaRequestUsername, lua.LString(luaActionRequest.Username))
			request.RawSetString(decl.LuaRequestAccount, lua.LString(luaActionRequest.Account))
			request.RawSetString(decl.LuaRequestUniqueUserID, lua.LString(luaActionRequest.UniqueUserID))
			request.RawSetString(decl.LuaRequestDisplayName, lua.LString(luaActionRequest.DisplayName))
			request.RawSetString(decl.LuaRequestPassword, lua.LString(luaActionRequest.Password))
			request.RawSetString(decl.LuaRequestProtocol, lua.LString(luaActionRequest.Protocol))
			request.RawSetString(decl.LuaRequestBruteForceBucket, lua.LString(luaActionRequest.BruteForceName))
			request.RawSetString(decl.LuaRequestFeature, lua.LString(luaActionRequest.FeatureName))

			for index := range actionScripts {
				if actionScripts[index].LuaAction == luaActionRequest.LuaAction {
					if errors.Is(ctx.Err(), context.Canceled) {
						break
					}

					luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

					L.SetContext(luaCtx)

					if err = lualib.DoCompiledFile(L, actionScripts[index].ScriptCompiled); err != nil {
						level.Error(logging.DefaultErrLogger).Log(
							decl.LogKeyGUID, luaActionRequest.Session,
							"script", actionScripts[index].ScriptPath,
							decl.LogKeyError, err,
						)

						luaCancel()

						continue
					}

					additionalLogs := func() []any {
						if len(*logs) > 0 && len(*logs)%2 == 0 {
							var l []any

							for i := range *logs {
								l = append(l, (*logs)[i])
							}

							return l
						}

						return nil
					}

					if err = L.CallByParam(lua.P{
						Fn:      L.GetGlobal(decl.LuaFnCallAction),
						NRet:    1,
						Protect: true,
					}, request); err != nil {
						level.Error(logging.DefaultErrLogger).Log(
							append([]any{
								decl.LogKeyGUID, luaActionRequest.Session,
								"script", actionScripts[index].ScriptPath,
								decl.LogKeyError, err,
							}, additionalLogs()...)...,
						)

						luaCancel()

						continue
					}

					ret := L.ToInt(-1)
					L.Pop(1)

					util.DebugModule(
						decl.DbgAction,
						"context", fmt.Sprintf("%+v", luaActionRequest.Context),
					)

					if err == nil {
						level.Info(logging.DefaultLogger).Log(
							append([]any{
								decl.LogKeyGUID, luaActionRequest.Session,
								"script", actionScripts[index].ScriptPath,
								"feature", func() string {
									if luaActionRequest.FeatureName != "" {
										return luaActionRequest.FeatureName
									}

									return decl.NotAvailable
								}(),
								decl.LogKeyMsg, "Lua action finished",
								"result", func() string {
									if ret == 0 || ret == 1 {
										return resultMap[ret]
									}

									return fmt.Sprintf("unknown(%d)", ret)
								}(),
							}, additionalLogs()...)...,
						)
					}

					luaCancel()
				}

			}

			luaActionRequest.FinishedChan <- Done{}

			L.Close()
		}
	}
}
