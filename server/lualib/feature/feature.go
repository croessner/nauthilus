package feature

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

var LuaFeatures *PreCompiledLuaFeatures

func PreCompileLuaFeatures() (err error) {
	if config.LoadableConfig.Lua != nil {
		if LuaFeatures == nil {
			LuaFeatures = &PreCompiledLuaFeatures{}
		} else {
			LuaFeatures.Reset()
		}

		for index := range config.LoadableConfig.Lua.Features {
			var luaFeature *LuaFeature

			luaFeature, err = NewLuaFeature(config.LoadableConfig.Lua.Features[index].Name, config.LoadableConfig.Lua.Features[index].ScriptPath)
			if err != nil {
				return err
			}

			// Add compiled Lua features.
			LuaFeatures.Add(luaFeature)
		}
	}

	return nil
}

type PreCompiledLuaFeatures struct {
	LuaScripts []*LuaFeature
	Mu         sync.RWMutex
}

func (a *PreCompiledLuaFeatures) Add(luaFeature *LuaFeature) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaFeature)
}

func (a *PreCompiledLuaFeatures) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaFeature, 0)
}

type LuaFeature struct {
	Name           string
	CompiledScript *lua.FunctionProto
}

func NewLuaFeature(name string, scriptPath string) (*LuaFeature, error) {
	if name == "" {
		return nil, errors2.ErrFeatureLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors2.ErrFeatureLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaFeature{
		Name:           name,
		CompiledScript: compiledScript,
	}, nil
}

type Request struct {
	Debug bool

	Session             string // GUID
	ClientIP            string
	ClientPort          string
	Username            string
	Password            string
	Protocol            string
	ClientID            string
	LocalIP             string
	LocalPort           string
	UserAgent           string
	XSSL                string
	XSSLSessionID       string
	XSSLClientVerify    string
	XSSLClientDN        string
	XSSLClientCN        string
	XSSLIssuer          string
	XSSLClientNotBefore string
	XSSLClientNotAfter  string
	XSSLSubjectDN       string
	XSSLIssuerDN        string
	XSSLClientSubjectDN string
	XSSLClientIssuerDN  string
	XSSLProtocol        string
	XSSLCipher          string

	Logs *lualib.CustomLogKeyValue

	*lualib.Context
}

// CallFeatureLua calls all defined Lua scripts and returns the trigger state and error.
func (r *Request) CallFeatureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	resultMap := make(map[int]string, 2)

	resultMap[0] = "ok"
	resultMap[1] = "fail"

	LuaFeatures.Mu.RLock()

	defer LuaFeatures.Mu.RUnlock()

	L := lua.NewState()

	// Useful libraries
	libs.Preload(L)
	gluacrypto.Preload(L)

	if config.EnvConfig.DevMode {
		util.DebugModule(decl.DbgFeature, decl.LogKeyMsg, fmt.Sprintf("%+v", r))
	}

	r.Logs = new(lualib.CustomLogKeyValue)
	globals := L.NewTable()

	globals.RawSet(lua.LString(decl.LuaFeatureTriggerNo), lua.LBool(false))
	globals.RawSet(lua.LString(decl.LuaFeatureTriggerYes), lua.LBool(true))
	globals.RawSet(lua.LString(decl.LuaFeatureAbortNo), lua.LBool(false))
	globals.RawSet(lua.LString(decl.LuaFeatureAbortYes), lua.LBool(true))
	globals.RawSet(lua.LString(decl.LuaFeatureResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(decl.LuaFeatureResultFail), lua.LNumber(1))

	globals.RawSetString(decl.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(r.Context)))
	globals.RawSetString(decl.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(r.Context)))
	globals.RawSetString(decl.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(r.Context)))
	globals.RawSetString(decl.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))

	L.SetGlobal(decl.LuaDefaultTable, globals)

	request := L.NewTable()

	request.RawSet(lua.LString(decl.LuaRequestDebug), lua.LBool(r.Debug))
	request.RawSetString(decl.LuaRequestSession, lua.LString(r.Session))
	request.RawSetString(decl.LuaRequestClientIP, lua.LString(r.ClientIP))
	request.RawSetString(decl.LuaRequestClientPort, lua.LString(r.ClientPort))
	request.RawSetString(decl.LuaRequestUsername, lua.LString(r.Username))
	request.RawSetString(decl.LuaRequestPassword, lua.LString(r.Password))
	request.RawSetString(decl.LuaRequestProtocol, lua.LString(r.Protocol))
	request.RawSetString(decl.LuaRequestClientID, lua.LString(r.ClientID))
	request.RawSetString(decl.LuaRequestLocalIP, lua.LString(r.LocalIP))
	request.RawSetString(decl.LuaRequestLocalPort, lua.LString(r.LocalPort))
	request.RawSetString(decl.LuaRequestUserAgent, lua.LString(r.UserAgent))
	request.RawSetString(decl.LuaRequestXSSL, lua.LString(r.XSSL))
	request.RawSetString(decl.LuaRequestXSSSLSessionID, lua.LString(r.XSSLSessionID))
	request.RawSetString(decl.LuaRequestXSSLClientVerify, lua.LString(r.XSSLClientVerify))
	request.RawSetString(decl.LuaRequestXSSLClientDN, lua.LString(r.XSSLClientDN))
	request.RawSetString(decl.LuaRequestXSSLClientCN, lua.LString(r.XSSLClientCN))
	request.RawSetString(decl.LuaRequestXSSLIssuer, lua.LString(r.XSSLIssuer))
	request.RawSetString(decl.LuaRequestXSSLClientNotBefore, lua.LString(r.XSSLClientNotBefore))
	request.RawSetString(decl.LuaRequestXSSLClientNotAfter, lua.LString(r.XSSLClientNotAfter))
	request.RawSetString(decl.LuaRequestXSSLSubjectDN, lua.LString(r.XSSLSubjectDN))
	request.RawSetString(decl.LuaRequestXSSLIssuerDN, lua.LString(r.XSSLIssuerDN))
	request.RawSetString(decl.LuaRequestXSSLClientSubjectDN, lua.LString(r.XSSLClientSubjectDN))
	request.RawSetString(decl.LuaRequestXSSLClientIssuerDN, lua.LString(r.XSSLClientIssuerDN))
	request.RawSetString(decl.LuaRequestXSSLProtocol, lua.LString(r.XSSLProtocol))
	request.RawSetString(decl.LuaRequestXSSLCipher, lua.LString(r.XSSLCipher))

	for index := range LuaFeatures.LuaScripts {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}

		luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

		L.SetContext(luaCtx)

		if err = lualib.DoCompiledFile(L, LuaFeatures.LuaScripts[index].CompiledScript); err != nil {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyGUID, r.Session,
				"name", LuaFeatures.LuaScripts[index].Name,
				decl.LogKeyError, err,
			)

			luaCancel()

			continue
		}

		if err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal(decl.LuaFnCallFeature),
			NRet:    3,
			Protect: true,
		}, request); err != nil {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyGUID, r.Session,
				"name", LuaFeatures.LuaScripts[index].Name,
				decl.LogKeyError, err,
			)

			luaCancel()

			continue
		}

		ret := L.ToInt(-1)
		L.Pop(1)

		abortFeatures = L.ToBool(-1)
		L.Pop(1)

		triggered = L.ToBool(-1)
		L.Pop(1)

		if err == nil {
			level.Info(logging.DefaultLogger).Log(
				decl.LogKeyGUID, r.Session,
				"name", LuaFeatures.LuaScripts[index].Name,
				decl.LogKeyMsg, "Lua feature finished",
				"triggered", triggered,
				"abort_features", abortFeatures,
				"result", func() string {
					if ret == 0 || ret == 1 {
						return resultMap[ret]
					}

					return fmt.Sprintf("unknown(%d)", ret)
				}(),
			)
		}

		luaCancel()

		if triggered || abortFeatures {
			break
		}
	}

	return
}
