package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

var (
	LuaRequestChan       chan *LuaRequest
	LuaMainWorkerEndChan chan Done
)

// LuaRequest is a subset from the Authentication struct.
type LuaRequest struct {
	Debug  bool
	NoAuth bool

	Function decl.LuaCommand

	Session             *string // GUID
	Username            string
	Password            string
	ClientIP            string
	ClientPort          string
	ClientHost          string
	LocalIP             string
	LocalPprt           string
	ClientID            string
	TOTPSecret          string
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
	UserAgent           string
	Service             string
	Protocol            *config.Protocol

	Logs *lualib.CustomLogKeyValue

	*lualib.Context

	LuaReplyChan chan *LuaBackendResult
}

// LuaBackendResult is a structure to store Lua backend results. The fields are mostly identical to core.PassDBResult.
type LuaBackendResult struct {
	Authenticated     bool
	UserFound         bool
	AccountField      string
	TOTPSecretField   string
	TOTPRecoveryField string
	UniqueUserIDField string
	DisplayNameField  string
	Err               error
	Attributes        map[any]any

	Logs *lualib.CustomLogKeyValue
}

const luaBackendResultTypeName = "backend_result"

// Registers the backend result type to given L.
func registerBackendResultType(L *lua.LState) {
	mt := L.NewTypeMetatable(luaBackendResultTypeName)

	L.SetGlobal("backend_result", mt)

	// Static attributes
	L.SetField(mt, "new", L.NewFunction(newBackendResult))

	// Methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), backendResultMethods))
}

func newBackendResult(L *lua.LState) int {
	backendResult := &LuaBackendResult{}
	userData := L.NewUserData()

	userData.Value = backendResult

	L.SetMetatable(userData, L.GetTypeMetatable(luaBackendResultTypeName))
	L.Push(userData)

	return 1
}

// Checks whether the first lua argument is a *LUserData with *LuaBackendResult and returns this *LuaBackendResult.
func checkBackendResult(L *lua.LState) *LuaBackendResult {
	userData := L.CheckUserData(1)

	if value, ok := userData.Value.(*LuaBackendResult); ok {
		return value
	}

	L.ArgError(1, "backend_result expected")

	return nil
}

var backendResultMethods = map[string]lua.LGFunction{
	"authenticated":        backendResultGetSetAuthenticated,
	"user_found":           backendResultGetSetUserFound,
	"account_field":        backendResultGetSetAccountField,
	"totp_secret_field":    backendResultGetSetTOTPSecretField,
	"totp_recovery_field":  backendResultGetSetTOTPRecoveryField,
	"unique_user_id_field": backendResultGetSetUniqueUserIDField,
	"display_name_field":   backendResultGetSetDisplayNameField,
	"attributes":           backendResultGetSetAttributes,
}

// Getter and setter for the BackendResult#Authenticated field
func backendResultGetSetAuthenticated(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.Authenticated = L.CheckBool(2)

		return 0
	}

	L.Push(lua.LBool(backendResult.Authenticated))

	return 1
}

// Getter and setter for the BackendResult#UserFound field
func backendResultGetSetUserFound(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.UserFound = L.CheckBool(2)

		return 0
	}

	L.Push(lua.LBool(backendResult.UserFound))

	return 1
}

// Getter and setter for the BackendResult#AcountField field
func backendResultGetSetAccountField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.AccountField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.AccountField))

	return 1
}

// Getter and setter for the BackendResult#TOTPSecretField field
func backendResultGetSetTOTPSecretField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.TOTPSecretField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.TOTPSecretField))

	return 1
}

// Getter and setter for the BackendResult#TOTPRecoveryField field
func backendResultGetSetTOTPRecoveryField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.TOTPRecoveryField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.TOTPRecoveryField))

	return 1
}

// Getter and setter for the BackendResult#UniqueUserIDField field
func backendResultGetSetUniqueUserIDField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.UniqueUserIDField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.UniqueUserIDField))

	return 1
}

// Getter and setter for the BackendResult#DisplayNameField field
func backendResultGetSetDisplayNameField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.DisplayNameField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.DisplayNameField))

	return 1
}

// Getter and setter for the BackendResult#Attributes field
func backendResultGetSetAttributes(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		// XXX: We expect keys to be strings!
		backendResult.Attributes = lualib.LuaTableToMap(L.CheckTable(2))

		return 0
	}

	L.Push(lua.LString(backendResult.DisplayNameField))

	return 1
}

// LuaMainWorker is the central backend worker for clients that are processed over the Lua backend driver.
func LuaMainWorker(ctx context.Context) {
	var luaRequest *LuaRequest

	scriptPath := config.LoadableConfig.GetLuaScriptPath()
	compiledScript, err := lualib.CompileLua(scriptPath)

	if err != nil {
		panic(err)
	}

	for {
		select {
		case <-ctx.Done():
			LuaMainWorkerEndChan <- Done{}

			return
		case luaRequest = <-LuaRequestChan:
			go func(luaRequest *LuaRequest) {
				var (
					nret         int
					luaCommand   string
					userData     *lua.LUserData
					accountTable *lua.LTable
				)

				luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

				L := lua.NewState()

				L.SetContext(luaCtx)

				defer luaCancel()
				defer L.Close()

				// Useful libraries
				libs.Preload(L)
				gluacrypto.Preload(L)

				logs := new(lualib.CustomLogKeyValue)

				registerBackendResultType(L)

				L.PreloadModule(decl.LuaModUtil, lualib.Loader)

				globals := L.NewTable()

				globals.RawSet(lua.LString(decl.LuaBackendResultOk), lua.LNumber(0))
				globals.RawSet(lua.LString(decl.LuaBackendResultFail), lua.LNumber(1))

				globals.RawSetString(decl.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(luaRequest.Context)))
				globals.RawSetString(decl.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(luaRequest.Context)))
				globals.RawSetString(decl.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(luaRequest.Context)))

				request := L.NewTable()

				switch luaRequest.Function {
				case decl.LuaCommandPassDB:
					luaCommand = decl.LuaFnBackendVerifyPassword
					nret = 2

					request.RawSet(lua.LString(decl.LuaRequestNoAuth), lua.LBool(luaRequest.NoAuth))
					request.RawSetString(decl.LuaRequestUsername, lua.LString(luaRequest.Username))
					request.RawSetString(decl.LuaRequestPassword, lua.LString(luaRequest.Password))
					request.RawSetString(decl.LuaRequestClientIP, lua.LString(luaRequest.ClientIP))
					request.RawSetString(decl.LuaRequestClientPort, lua.LString(luaRequest.ClientPort))
					request.RawSetString(decl.LuaRequestClientHost, lua.LString(luaRequest.ClientHost))
					request.RawSetString(decl.LuaRequestClientID, lua.LString(luaRequest.ClientID))
					request.RawSetString(decl.LuaRequestLocalIP, lua.LString(luaRequest.LocalIP))
					request.RawSetString(decl.LuaRequestLocalPort, lua.LString(luaRequest.LocalPprt))
					request.RawSetString(decl.LuaRequestUserAgent, lua.LString(luaRequest.UserAgent))
					request.RawSetString(decl.LuaRequestService, lua.LString(luaRequest.Service))
					request.RawSetString(decl.LuaRequestProtocol, lua.LString(luaRequest.Protocol.String()))
					request.RawSetString(decl.LuaRequestXSSL, lua.LString(luaRequest.XSSL))
					request.RawSetString(decl.LuaRequestXSSSLSessionID, lua.LString(luaRequest.XSSLSessionID))
					request.RawSetString(decl.LuaRequestXSSLClientVerify, lua.LString(luaRequest.XSSLClientVerify))
					request.RawSetString(decl.LuaRequestXSSLClientDN, lua.LString(luaRequest.XSSLClientDN))
					request.RawSetString(decl.LuaRequestXSSLClientCN, lua.LString(luaRequest.XSSLClientCN))
					request.RawSetString(decl.LuaRequestXSSLIssuer, lua.LString(luaRequest.XSSLIssuer))
					request.RawSetString(decl.LuaRequestXSSLClientNotBefore, lua.LString(luaRequest.XSSLClientNotBefore))
					request.RawSetString(decl.LuaRequestXSSLClientNotAfter, lua.LString(luaRequest.XSSLClientNotAfter))
					request.RawSetString(decl.LuaRequestXSSLSubjectDN, lua.LString(luaRequest.XSSLSubjectDN))
					request.RawSetString(decl.LuaRequestXSSLIssuerDN, lua.LString(luaRequest.XSSLIssuerDN))
					request.RawSetString(decl.LuaRequestXSSLClientSubjectDN, lua.LString(luaRequest.XSSLClientSubjectDN))
					request.RawSetString(decl.LuaRequestXSSLClientIssuerDN, lua.LString(luaRequest.XSSLClientIssuerDN))
					request.RawSetString(decl.LuaRequestXSSLProtocol, lua.LString(luaRequest.XSSLProtocol))
					request.RawSetString(decl.LuaRequestXSSLCipher, lua.LString(luaRequest.XSSLCipher))

					globals.RawSetString(decl.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))
				case decl.LuaCommandListAccounts:
					luaCommand = decl.LuaFnBackendListAccounts
					nret = 2
				case decl.LuaCommandAddMFAValue:
					luaCommand = decl.LuaFnBackendAddTOTPSecret
					nret = 1

					request.RawSetString(decl.LuaRequestTOTPSecret, lua.LString(luaRequest.TOTPSecret))
				}

				request.RawSet(lua.LString(decl.LuaRequestDebug), lua.LBool(luaRequest.Debug))
				request.RawSetString(decl.LuaRequestSession, lua.LString(*luaRequest.Session))

				L.SetGlobal(decl.LuaDefaultTable, globals)

				if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
					level.Error(logging.DefaultErrLogger).Log(
						decl.LogKeyGUID, luaRequest.Session,
						"script", config.LoadableConfig.GetLuaScriptPath(),
						decl.LogKeyError, err,
					)

					luaRequest.LuaReplyChan <- &LuaBackendResult{
						Err:  err,
						Logs: logs,
					}

					return
				}

				if err = L.CallByParam(lua.P{
					Fn:      L.GetGlobal(luaCommand),
					NRet:    nret,
					Protect: true,
				}, request); err != nil {
					level.Error(logging.DefaultErrLogger).Log(
						decl.LogKeyGUID, luaRequest.Session,
						"script", config.LoadableConfig.GetLuaScriptPath(),
						decl.LogKeyError, err,
					)

					luaRequest.LuaReplyChan <- &LuaBackendResult{
						Err:  err,
						Logs: logs,
					}

					return
				}

				ret := L.ToInt(-nret)

				if ret != 0 {
					luaRequest.LuaReplyChan <- &LuaBackendResult{
						Err:  errors.ErrBackendLua.WithDetail("Lua script finished with an error"),
						Logs: logs,
					}

					return
				}

				switch luaRequest.Function {
				case decl.LuaCommandPassDB:
					userData = L.ToUserData(-1)

					if luaBackendResult, ok := userData.Value.(*LuaBackendResult); ok {
						luaBackendResult.Logs = logs

						util.DebugModule(
							decl.DbgLua,
							decl.LogKeyGUID, luaRequest.Session,
							"result", fmt.Sprintf("%+v", luaBackendResult),
						)

						luaRequest.LuaReplyChan <- luaBackendResult
					} else {
						luaRequest.LuaReplyChan <- &LuaBackendResult{
							Err:  errors.ErrBackendLuaWrongUserData.WithDetail("Lua script returned a wrong user data object"),
							Logs: logs,
						}
					}
				case decl.LuaCommandListAccounts:
					accountTable = L.ToTable(-1)

					luaRequest.LuaReplyChan <- &LuaBackendResult{
						Attributes: lualib.LuaTableToMap(accountTable),
					}
				case decl.LuaCommandAddMFAValue:
					fallthrough
				default:
					luaRequest.LuaReplyChan <- &LuaBackendResult{}
				}
			}(luaRequest)
		}
	}
}
