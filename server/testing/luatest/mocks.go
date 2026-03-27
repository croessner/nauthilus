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

package luatest

import (
	"context"
	"fmt"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cjoudrey/gluahttp"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/testing/dbmock"
	gluacrypto "github.com/tengattack/gluacrypto/crypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

// LoaderModContextMock creates a mock nauthilus_context module.
func LoaderModContextMock(mockData *ContextMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// Bind context get/set/delete functions using ContextManager
		// which will look up the context from the global request environment
		manager := lualib.NewContextManager()
		L.SetField(mod, definitions.LuaFnCtxSet, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnCtxSet, key); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			return manager.ContextSet(L)
		}))
		L.SetField(mod, definitions.LuaFnCtxGet, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnCtxGet, key); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			return manager.ContextGet(L)
		}))
		L.SetField(mod, definitions.LuaFnCtxDelete, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnCtxDelete, key); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			return manager.ContextDelete(L)
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModLDAPMock creates a mock nauthilus_ldap module.
func LoaderModLDAPMock(mockData *LDAPMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		searchResult := map[string][]string{}
		searchError := ""
		modifyOK := true
		modifyError := ""
		endpointHost := "localhost"
		endpointPort := 389
		endpointError := ""

		if mockData != nil {
			if mockData.SearchResult != nil {
				searchResult = mockData.SearchResult
			}

			searchError = mockData.SearchError
			modifyError = mockData.ModifyError
			endpointError = mockData.EndpointError

			if mockData.ModifyOK != nil {
				modifyOK = *mockData.ModifyOK
			}

			if mockData.EndpointHost != "" {
				endpointHost = mockData.EndpointHost
			}

			if mockData.EndpointPort > 0 {
				endpointPort = mockData.EndpointPort
			}
		}

		L.SetField(mod, definitions.LuaFnLDAPSearch, L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall(definitions.LuaFnLDAPSearch, "search"); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 2
			}

			if searchError != "" {
				L.Push(lua.LNil)
				L.Push(lua.LString(searchError))

				return 2
			}

			result := L.NewTable()
			for attrName, values := range searchResult {
				valueTable := L.NewTable()
				for index, value := range values {
					valueTable.RawSetInt(index+1, lua.LString(value))
				}
				result.RawSetString(attrName, valueTable)
			}

			L.Push(result)

			return 1
		}))

		L.SetField(mod, definitions.LuaFnLDAPModify, L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall(definitions.LuaFnLDAPModify, "modify"); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 2
			}

			if modifyError != "" {
				L.Push(lua.LNil)
				L.Push(lua.LString(modifyError))

				return 2
			}

			if !modifyOK {
				L.Push(lua.LNil)
				L.Push(lua.LString("mock ldap modify failed"))

				return 2
			}

			L.Push(lua.LString("OK"))

			return 1
		}))

		L.SetField(mod, definitions.LuaFnLDAPEndpoint, L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall(definitions.LuaFnLDAPEndpoint, "endpoint"); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 3
			}

			if endpointError != "" {
				L.Push(lua.LNil)
				L.Push(lua.LNil)
				L.Push(lua.LString(endpointError))

				return 3
			}

			L.Push(lua.LString(endpointHost))
			L.Push(lua.LNumber(endpointPort))
			L.Push(lua.LNil)

			return 3
		}))

		L.Push(mod)

		return 1
	}
}

type mockDBConn struct {
	mock       *dbmock.Mock
	conn       *dbmock.Conn
	lastInsert int64
	closed     bool
	execError  string
	queryError string
}

type mockDBStmt struct {
	conn       *mockDBConn
	stmt       *dbmock.Stmt
	prepareExp *dbmock.PrepareExpectation
	query      string
	closed     bool
}

// LoaderModDBMock creates a mock db module.
func LoaderModDBMock(mockData *DBMock) lua.LGFunction {
	if mockData == nil {
		mockData = &DBMock{}
	}

	openError := ""
	execError := ""
	queryError := ""
	declarativeMode := false

	if mockData != nil {
		openError = mockData.OpenError
		execError = mockData.ExecError
		queryError = mockData.QueryError
		declarativeMode = mockData.DeclarativeMode
	}

	return func(L *lua.LState) int {
		dbMT := L.NewTypeMetatable("db_ud_mock")
		stmtMT := L.NewTypeMetatable("db_stmt_ud_mock")

		collectArgs := func(L *lua.LState, startIndex int) []any {
			if L.GetTop() < startIndex {
				return []any{}
			}

			args := make([]any, 0, L.GetTop()-startIndex+1)
			for i := startIndex; i <= L.GetTop(); i++ {
				args = append(args, convert.LuaValueToGo(L.Get(i)))
			}

			return args
		}

		configExecExpectation := func(conn *mockDBConn, query string, args []any) (int64, int64) {
			rowsAffected := int64(0)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(query)), "create ") {
				rowsAffected = 0
			} else {
				rowsAffected = 1
			}

			if expected := mockData.LastMatchedCall(); expected != nil && expected.RowsAffected != nil {
				rowsAffected = *expected.RowsAffected
			}

			lastInsertID := int64(0)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(query)), "insert ") {
				conn.lastInsert++
				lastInsertID = conn.lastInsert
			}

			if expected := mockData.LastMatchedCall(); expected != nil && expected.LastInsertID != nil {
				lastInsertID = *expected.LastInsertID
			}

			if !declarativeMode {
				conn.mock.ExpectExec(query, args...).WillReturnResult(rowsAffected, lastInsertID)
			}

			return rowsAffected, lastInsertID
		}

		execSQL := func(conn *mockDBConn, query string, args []any) (lua.LValue, error) {
			if conn == nil {
				return lua.LNil, fmt.Errorf("invalid mock db connection")
			}
			if conn.closed {
				return lua.LNil, fmt.Errorf("mock db connection is closed")
			}
			if conn.execError != "" {
				return lua.LNil, fmt.Errorf("%s", conn.execError)
			}

			rowsAffected, lastInsertID := configExecExpectation(conn, query, args)
			if !declarativeMode {
				result, errExec := conn.conn.Exec(query, args...)
				if errExec != nil {
					return lua.LNil, errExec
				}
				rowsAffected = result.RowsAffected
				lastInsertID = result.LastInsertID
			}

			luaResult := L.NewTable()
			luaResult.RawSetString("rows_affected", lua.LNumber(rowsAffected))
			if lastInsertID > 0 {
				luaResult.RawSetString("last_insert_id", lua.LNumber(lastInsertID))
			}

			return luaResult, nil
		}

		execStmtSQL := func(stmt *mockDBStmt, args []any) (lua.LValue, error) {
			if stmt == nil || stmt.conn == nil {
				return lua.LNil, fmt.Errorf("invalid mock db statement")
			}
			if stmt.closed {
				return lua.LNil, fmt.Errorf("invalid mock db statement")
			}
			if stmt.conn.execError != "" {
				return lua.LNil, fmt.Errorf("%s", stmt.conn.execError)
			}

			rowsAffected := int64(0)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(stmt.query)), "create ") {
				rowsAffected = 0
			} else {
				rowsAffected = 1
			}

			if expected := mockData.LastMatchedCall(); expected != nil && expected.RowsAffected != nil {
				rowsAffected = *expected.RowsAffected
			}

			lastInsertID := int64(0)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(stmt.query)), "insert ") {
				stmt.conn.lastInsert++
				lastInsertID = stmt.conn.lastInsert
			}

			if expected := mockData.LastMatchedCall(); expected != nil && expected.LastInsertID != nil {
				lastInsertID = *expected.LastInsertID
			}

			if declarativeMode {
				luaResult := L.NewTable()
				luaResult.RawSetString("rows_affected", lua.LNumber(rowsAffected))
				if lastInsertID > 0 {
					luaResult.RawSetString("last_insert_id", lua.LNumber(lastInsertID))
				}

				return luaResult, nil
			}

			stmt.prepareExp.ExpectExec(args...).WillReturnResult(rowsAffected, lastInsertID)
			result, errExec := stmt.stmt.Exec(args...)
			if errExec != nil {
				return lua.LNil, errExec
			}

			luaResult := L.NewTable()
			luaResult.RawSetString("rows_affected", lua.LNumber(result.RowsAffected))
			if result.LastInsertID > 0 {
				luaResult.RawSetString("last_insert_id", lua.LNumber(result.LastInsertID))
			}

			return luaResult, nil
		}

		querySQL := func(conn *mockDBConn, query string, args []any) (lua.LValue, error) {
			if conn == nil {
				return lua.LNil, fmt.Errorf("invalid mock db connection")
			}
			if conn.closed {
				return lua.LNil, fmt.Errorf("mock db connection is closed")
			}
			if conn.queryError != "" {
				return lua.LNil, fmt.Errorf("%s", conn.queryError)
			}

			rowsResult := dbmock.NewRows()
			if expected := mockData.LastMatchedCall(); expected != nil {
				if len(expected.Columns) > 0 {
					rowsResult = dbmock.NewRows(expected.Columns...)
				}

				for _, row := range expected.Rows {
					rowValues := make([]any, len(row))
					copy(rowValues, row)
					rowsResult = rowsResult.AddRow(rowValues...)
				}
			}

			if len(rowsResult.Columns) == 0 && len(rowsResult.Data) > 0 {
				columnCount := len(rowsResult.Data[0])
				columns := make([]string, 0, columnCount)
				for idx := range columnCount {
					columns = append(columns, fmt.Sprintf("col_%d", idx+1))
				}
				filled := dbmock.NewRows(columns...)
				for _, row := range rowsResult.Data {
					filled = filled.AddRow(row...)
				}
				rowsResult = filled
			}

			result := rowsResult
			if !declarativeMode {
				conn.mock.ExpectQuery(query, args...).WillReturnRows(rowsResult)
				queryResult, errQuery := conn.conn.Query(query, args...)
				if errQuery != nil {
					return lua.LNil, errQuery
				}

				result = queryResult
			}

			rowsTable := L.NewTable()
			for rowIndex, row := range result.Data {
				rowTable := L.NewTable()
				for colIndex, value := range row {
					rowTable.RawSetInt(colIndex+1, convert.GoToLuaValue(L, value))
				}
				rowsTable.RawSetInt(rowIndex+1, rowTable)
			}

			columnsTable := L.NewTable()
			for index, col := range result.Columns {
				columnsTable.RawSetInt(index+1, lua.LString(col))
			}

			luaResult := L.NewTable()
			luaResult.RawSetString("rows", rowsTable)
			luaResult.RawSetString("columns", columnsTable)
			return luaResult, nil
		}

		queryStmtSQL := func(stmt *mockDBStmt, args []any) (lua.LValue, error) {
			if stmt == nil || stmt.conn == nil {
				return lua.LNil, fmt.Errorf("invalid mock db statement")
			}
			if stmt.closed {
				return lua.LNil, fmt.Errorf("invalid mock db statement")
			}
			if stmt.conn.queryError != "" {
				return lua.LNil, fmt.Errorf("%s", stmt.conn.queryError)
			}

			rowsResult := dbmock.NewRows()
			if expected := mockData.LastMatchedCall(); expected != nil {
				if len(expected.Columns) > 0 {
					rowsResult = dbmock.NewRows(expected.Columns...)
				}

				for _, row := range expected.Rows {
					rowValues := make([]any, len(row))
					copy(rowValues, row)
					rowsResult = rowsResult.AddRow(rowValues...)
				}
			}

			if len(rowsResult.Columns) == 0 && len(rowsResult.Data) > 0 {
				columnCount := len(rowsResult.Data[0])
				columns := make([]string, 0, columnCount)
				for idx := range columnCount {
					columns = append(columns, fmt.Sprintf("col_%d", idx+1))
				}
				filled := dbmock.NewRows(columns...)
				for _, row := range rowsResult.Data {
					filled = filled.AddRow(row...)
				}
				rowsResult = filled
			}

			result := rowsResult
			if !declarativeMode {
				stmt.prepareExp.ExpectQuery(args...).WillReturnRows(rowsResult)
				queryResult, errQuery := stmt.stmt.Query(args...)
				if errQuery != nil {
					return lua.LNil, errQuery
				}

				result = queryResult
			}

			rowsTable := L.NewTable()
			for rowIndex, row := range result.Data {
				rowTable := L.NewTable()
				for colIndex, value := range row {
					rowTable.RawSetInt(colIndex+1, convert.GoToLuaValue(L, value))
				}
				rowsTable.RawSetInt(rowIndex+1, rowTable)
			}

			columnsTable := L.NewTable()
			for index, col := range result.Columns {
				columnsTable.RawSetInt(index+1, lua.LString(col))
			}

			luaResult := L.NewTable()
			luaResult.RawSetString("rows", rowsTable)
			luaResult.RawSetString("columns", columnsTable)
			return luaResult, nil
		}

		L.SetField(dbMT, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"exec": func(L *lua.LState) int {
				connUD := L.CheckUserData(1)
				query := strings.TrimSpace(L.CheckString(2))
				args := collectArgs(L, 3)

				if err := mockData.RecordCall("exec", query); err != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(err.Error()))

					return 2
				}

				conn, ok := connUD.Value.(*mockDBConn)
				if !ok || conn == nil {
					L.Push(lua.LNil)
					L.Push(lua.LString("invalid mock db connection"))

					return 2
				}

				result, errExec := execSQL(conn, query, args)
				if errExec != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(errExec.Error()))
					return 2
				}

				L.Push(result)
				return 1
			},
			"query": func(L *lua.LState) int {
				connUD := L.CheckUserData(1)
				query := strings.TrimSpace(L.CheckString(2))
				args := collectArgs(L, 3)

				if err := mockData.RecordCall("query", query); err != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(err.Error()))

					return 2
				}

				conn, ok := connUD.Value.(*mockDBConn)
				if !ok || conn == nil {
					L.Push(lua.LNil)
					L.Push(lua.LString("invalid mock db connection"))

					return 2
				}

				result, errQuery := querySQL(conn, query, args)
				if errQuery != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(errQuery.Error()))
					return 2
				}

				L.Push(result)
				return 1
			},
			"stmt": func(L *lua.LState) int {
				connUD := L.CheckUserData(1)
				query := strings.TrimSpace(L.CheckString(2))

				if err := mockData.RecordCall("stmt", query); err != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(err.Error()))
					return 2
				}

				conn, ok := connUD.Value.(*mockDBConn)
				if !ok || conn == nil {
					L.Push(lua.LNil)
					L.Push(lua.LString("invalid mock db connection"))
					return 2
				}

				if conn.closed {
					L.Push(lua.LNil)
					L.Push(lua.LString("mock db connection is closed"))
					return 2
				}

				stmt := &mockDBStmt{
					conn:   conn,
					query:  query,
					closed: false,
				}

				if !declarativeMode {
					prepareExp := conn.mock.ExpectPrepare(query)
					preparedStmt, errPrepare := conn.conn.Prepare(query)
					if errPrepare != nil {
						L.Push(lua.LNil)
						L.Push(lua.LString(errPrepare.Error()))
						return 2
					}

					stmt.prepareExp = prepareExp
					stmt.stmt = preparedStmt
				}

				stmtUD := L.NewUserData()
				stmtUD.Value = stmt
				L.SetMetatable(stmtUD, stmtMT)
				L.Push(stmtUD)
				return 1
			},
			"close": func(L *lua.LState) int {
				if err := mockData.RecordCall("close", ""); err != nil {
					L.Push(lua.LString(err.Error()))

					return 1
				}

				connUD := L.CheckUserData(1)
				conn, ok := connUD.Value.(*mockDBConn)
				if !ok || conn == nil {
					L.Push(lua.LString("invalid mock db connection"))

					return 1
				}

				conn.closed = true

				return 0
			},
		}))

		L.SetField(stmtMT, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"exec": func(L *lua.LState) int {
				stmtUD := L.CheckUserData(1)
				stmt, ok := stmtUD.Value.(*mockDBStmt)
				if !ok || stmt == nil || stmt.conn == nil || stmt.closed {
					L.Push(lua.LNil)
					L.Push(lua.LString("invalid mock db statement"))
					return 2
				}

				args := collectArgs(L, 2)

				if err := mockData.RecordCall("exec", stmt.query); err != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(err.Error()))
					return 2
				}

				result, errExec := execStmtSQL(stmt, args)
				if errExec != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(errExec.Error()))
					return 2
				}

				L.Push(result)
				return 1
			},
			"query": func(L *lua.LState) int {
				stmtUD := L.CheckUserData(1)
				stmt, ok := stmtUD.Value.(*mockDBStmt)
				if !ok || stmt == nil || stmt.conn == nil || stmt.closed {
					L.Push(lua.LNil)
					L.Push(lua.LString("invalid mock db statement"))
					return 2
				}

				args := collectArgs(L, 2)

				if err := mockData.RecordCall("query", stmt.query); err != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(err.Error()))
					return 2
				}

				result, errQuery := queryStmtSQL(stmt, args)
				if errQuery != nil {
					L.Push(lua.LNil)
					L.Push(lua.LString(errQuery.Error()))
					return 2
				}

				L.Push(result)
				return 1
			},
			"close": func(L *lua.LState) int {
				stmtUD := L.CheckUserData(1)
				stmt, ok := stmtUD.Value.(*mockDBStmt)
				if !ok || stmt == nil {
					L.Push(lua.LString("invalid mock db statement"))
					return 1
				}

				stmt.closed = true
				if stmt.stmt != nil {
					stmt.stmt.Close()
				}
				return 0
			},
		}))

		mod := L.NewTable()

		L.SetField(mod, "open", L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall("open", ""); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			_ = L.CheckString(1) // driver
			_ = L.CheckString(2) // connection string
			if L.GetTop() > 2 {
				_ = L.CheckTable(3)
			}

			if openError != "" {
				L.Push(lua.LNil)
				L.Push(lua.LString(openError))

				return 2
			}

			internalMock := dbmock.New()

			conn := &mockDBConn{
				mock:       internalMock,
				conn:       internalMock.Conn(),
				lastInsert: 0,
				execError:  execError,
				queryError: queryError,
			}

			ud := L.NewUserData()
			ud.Value = conn
			L.SetMetatable(ud, dbMT)
			L.Push(ud)

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

type backendResultMockValue struct {
	Authenticated       bool
	UserFound           bool
	AccountField        string
	TOTPSecretField     string
	TOTPRecoveryField   string
	UniqueUserIDField   string
	DisplayNameField    string
	WebAuthnCredentials []string
	Attributes          map[any]any
}

// LoaderModBackendMock creates a mock nauthilus_backend module.
func LoaderModBackendMock(mockData *BackendMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		if mockData == nil {
			mockData = &BackendMock{}
		}

		mt := L.NewTypeMetatable(definitions.LuaBackendServerTypeName)
		L.SetField(mt, "__index", L.NewFunction(func(L *lua.LState) int {
			userData := L.CheckUserData(1)
			field := L.CheckString(2)

			server, ok := userData.Value.(*BackendServerMock)
			if !ok || server == nil {
				return 0
			}

			switch field {
			case "protocol":
				L.Push(lua.LString(server.Protocol))
			case "host":
				L.Push(lua.LString(server.Host))
			case "port":
				L.Push(lua.LNumber(server.Port))
			case "request_uri":
				L.Push(lua.LString(server.RequestURI))
			case "test_username":
				L.Push(lua.LString(server.TestUsername))
			case "test_password":
				L.Push(lua.LString(server.TestPassword))
			case "haproxy_v2":
				L.Push(lua.LBool(server.HAProxyV2))
			case "tls":
				L.Push(lua.LBool(server.TLS))
			case "tls_skip_verify":
				L.Push(lua.LBool(server.TLSSkipVerify))
			case "deep_check":
				L.Push(lua.LBool(server.DeepCheck))
			default:
				return 0
			}

			return 1
		}))

		L.SetField(mod, definitions.LuaFnGetBackendServers, L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall(definitions.LuaFnGetBackendServers, ""); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			servers := L.NewTable()
			for index := range mockData.BackendServers {
				server := mockData.BackendServers[index]
				ud := L.NewUserData()
				ud.Value = &server
				L.SetMetatable(ud, L.GetTypeMetatable(definitions.LuaBackendServerTypeName))
				servers.Append(ud)
			}
			L.Push(servers)
			return 1
		}))

		L.SetField(mod, definitions.LuaFnSelectBackendServer, L.NewFunction(func(L *lua.LState) int {
			host := L.CheckString(1)
			port := L.CheckInt(2)
			if err := mockData.RecordCall(definitions.LuaFnSelectBackendServer, host); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			mockData.RuntimeSelectedHost = host
			mockData.RuntimeSelectedPort = &port
			return 0
		}))

		L.SetField(mod, definitions.LuaFnApplyBackendResult, L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall(definitions.LuaFnApplyBackendResult, ""); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			value := L.CheckAny(1)
			switch v := value.(type) {
			case *lua.LUserData:
				if br, ok := v.Value.(*backendResultMockValue); ok && br != nil {
					out := map[string]any{
						definitions.LuaBackendResultAuthenticated:     br.Authenticated,
						definitions.LuaBackendResultUserFound:         br.UserFound,
						definitions.LuaBackendResultAccountField:      br.AccountField,
						definitions.LuaBackendResultTOTPSecretField:   br.TOTPSecretField,
						definitions.LuaBackendResultTOTPRecoveryField: br.TOTPRecoveryField,
						"unique_user_id": br.UniqueUserIDField,
						definitions.LuaBackendResultDisplayNameField: br.DisplayNameField,
					}
					if br.Attributes != nil {
						out[definitions.LuaBackendResultAttributes] = br.Attributes
					}
					if len(br.WebAuthnCredentials) > 0 {
						out[definitions.LuaBackendResultWebAuthnCredentials] = br.WebAuthnCredentials
					}
					mockData.RuntimeAppliedBackendResult = out
				}
			case *lua.LTable:
				converted := convert.LuaValueToGo(v)
				if asMap, ok := converted.(map[any]any); ok {
					out := make(map[string]any, len(asMap))
					for key, val := range asMap {
						out[fmt.Sprintf("%v", key)] = val
					}
					mockData.RuntimeAppliedBackendResult = out
				}
			}
			return 0
		}))

		L.SetField(mod, definitions.LuaFnRemoveFromBackendResult, L.NewFunction(func(L *lua.LState) int {
			tbl := L.CheckTable(1)
			if err := mockData.RecordCall(definitions.LuaFnRemoveFromBackendResult, ""); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			removeAttrs := make([]string, 0)
			tbl.ForEach(func(_, value lua.LValue) {
				removeAttrs = append(removeAttrs, value.String())
			})
			mockData.RuntimeRemovedFromAttributes = removeAttrs
			return 0
		}))

		L.Push(mod)
		return 1
	}
}

// LoaderModBackendResultMock creates a mock nauthilus_backend_result module.
func LoaderModBackendResultMock(mockData *BackendResultMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		if mockData == nil {
			mockData = &BackendResultMock{}
		}

		mt := L.NewTypeMetatable(definitions.LuaBackendResultTypeName)
		L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaBackendResultAuthenticated: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultAuthenticated, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.Authenticated = L.CheckBool(2)
					return 0
				}
				L.Push(lua.LBool(value.Authenticated))
				return 1
			},
			definitions.LuaBackendResultUserFound: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultUserFound, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.UserFound = L.CheckBool(2)
					return 0
				}
				L.Push(lua.LBool(value.UserFound))
				return 1
			},
			definitions.LuaBackendResultAccountField: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultAccountField, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.AccountField = L.CheckString(2)
					return 0
				}
				L.Push(lua.LString(value.AccountField))
				return 1
			},
			definitions.LuaBackendResultTOTPSecretField: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultTOTPSecretField, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.TOTPSecretField = L.CheckString(2)
					return 0
				}
				L.Push(lua.LString(value.TOTPSecretField))
				return 1
			},
			definitions.LuaBackendResultTOTPRecoveryField: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultTOTPRecoveryField, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.TOTPRecoveryField = L.CheckString(2)
					return 0
				}
				L.Push(lua.LString(value.TOTPRecoveryField))
				return 1
			},
			definitions.LuaBAckendResultUniqueUserIDField: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBAckendResultUniqueUserIDField, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.UniqueUserIDField = L.CheckString(2)
					return 0
				}
				L.Push(lua.LString(value.UniqueUserIDField))
				return 1
			},
			definitions.LuaBackendResultDisplayNameField: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultDisplayNameField, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					value.DisplayNameField = L.CheckString(2)
					return 0
				}
				L.Push(lua.LString(value.DisplayNameField))
				return 1
			},
			definitions.LuaBackendResultWebAuthnCredentials: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultWebAuthnCredentials, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					table := L.CheckTable(2)
					credentials := make([]string, 0)
					table.ForEach(func(_, item lua.LValue) {
						credentials = append(credentials, item.String())
					})
					value.WebAuthnCredentials = credentials
					return 0
				}
				table := L.NewTable()
				for _, cred := range value.WebAuthnCredentials {
					table.Append(lua.LString(cred))
				}
				L.Push(table)
				return 1
			},
			definitions.LuaBackendResultAttributes: func(L *lua.LState) int {
				if err := mockData.RecordCall(definitions.LuaBackendResultAttributes, ""); err != nil {
					L.RaiseError("%s", err.Error())
					return 0
				}
				userData := L.CheckUserData(1)
				value, _ := userData.Value.(*backendResultMockValue)
				if value == nil {
					L.ArgError(1, "backend_result expected")
					return 0
				}
				if L.GetTop() == 2 {
					table := L.CheckTable(2)
					if attrs, ok := convert.LuaValueToGo(table).(map[any]any); ok {
						value.Attributes = attrs
					} else {
						value.Attributes = map[any]any{}
					}
					return 0
				}
				L.Push(convert.GoToLuaValue(L, value.Attributes))
				return 1
			},
		}))
		L.SetField(mt, "__newindex", L.NewFunction(func(L *lua.LState) int {
			userData := L.CheckUserData(1)
			field := L.CheckString(2)
			value := L.CheckAny(3)

			br, ok := userData.Value.(*backendResultMockValue)
			if !ok || br == nil {
				L.ArgError(1, "backend_result expected")
				return 0
			}

			switch field {
			case definitions.LuaBackendResultAuthenticated:
				br.Authenticated = lua.LVAsBool(value)
			case definitions.LuaBackendResultUserFound:
				br.UserFound = lua.LVAsBool(value)
			case definitions.LuaBackendResultAccountField:
				br.AccountField = lua.LVAsString(value)
			case definitions.LuaBackendResultTOTPSecretField:
				br.TOTPSecretField = lua.LVAsString(value)
			case definitions.LuaBackendResultTOTPRecoveryField:
				br.TOTPRecoveryField = lua.LVAsString(value)
			case definitions.LuaBAckendResultUniqueUserIDField, "unique_user_id":
				br.UniqueUserIDField = lua.LVAsString(value)
			case definitions.LuaBackendResultDisplayNameField, "display_name":
				br.DisplayNameField = lua.LVAsString(value)
			case definitions.LuaBackendResultAttributes:
				if attrs, ok := convert.LuaValueToGo(value).(map[any]any); ok {
					br.Attributes = attrs
				}
			}

			return 0
		}))

		L.SetField(mod, "new", L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall("new", ""); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}
			result := &backendResultMockValue{
				Authenticated:     mockData.Authenticated,
				UserFound:         mockData.UserFound,
				AccountField:      mockData.AccountField,
				TOTPSecretField:   mockData.TOTPSecret,
				UniqueUserIDField: mockData.UniqueUserID,
				DisplayNameField:  mockData.DisplayName,
				Attributes:        make(map[any]any),
			}

			if len(mockData.TOTPRecovery) > 0 {
				result.TOTPRecoveryField = mockData.TOTPRecovery[0]
			}

			if mockData.Attributes != nil {
				for k, v := range mockData.Attributes {
					result.Attributes[k] = v
				}
			}

			userData := L.NewUserData()
			userData.Value = result
			L.SetMetatable(userData, L.GetTypeMetatable(definitions.LuaBackendResultTypeName))
			L.Push(userData)

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModHTTPRequestMock creates a mock nauthilus_http_request module.
func LoaderModHTTPRequestMock(mockData *HTTPRequestMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		method := "GET"
		path := "/"
		var headers map[string]string
		body := ""

		if mockData != nil {
			method = mockData.Method
			path = mockData.Path
			headers = mockData.Headers
			body = mockData.Body
		}

		// Provide both field access and function access for compatibility
		L.SetField(mod, "method", lua.LString(method))
		L.SetField(mod, "path", lua.LString(path))
		L.SetField(mod, "body", lua.LString(body))

		// Function getters
		L.SetField(mod, "get_http_method", L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall("get_http_method", ""); err != nil {
				L.Push(lua.LNil)
				return 1
			}
			L.Push(lua.LString(method))
			return 1
		}))

		L.SetField(mod, "get_http_path", L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall("get_http_path", ""); err != nil {
				L.Push(lua.LNil)
				return 1
			}
			L.Push(lua.LString(path))
			return 1
		}))

		L.SetField(mod, "get_http_body", L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall("get_http_body", ""); err != nil {
				L.Push(lua.LNil)
				return 1
			}
			L.Push(lua.LString(body))
			return 1
		}))

		L.SetField(mod, definitions.LuaFnGetHTTPQueryParam, L.NewFunction(func(L *lua.LState) int {
			param := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnGetHTTPQueryParam, param); err != nil {
				L.Push(lua.LNil)
				return 1
			}

			parsed, err := url.ParseRequestURI(path)
			if err != nil || parsed == nil {
				L.Push(lua.LNil)
				return 1
			}

			value := parsed.Query().Get(param)
			if value == "" {
				L.Push(lua.LNil)
				return 1
			}

			L.Push(lua.LString(value))
			return 1
		}))

		L.SetField(mod, "get_http_header", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if err := mockData.RecordCall("get_http_header", key); err != nil {
				L.Push(lua.LNil)
				return 1
			}
			if headers != nil {
				if val, ok := headers[key]; ok {
					L.Push(lua.LString(val))
					return 1
				}
			}
			L.Push(lua.LNil)
			return 1
		}))

		L.SetField(mod, definitions.LuaFnGetHTTPRequestHeader, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnGetHTTPRequestHeader, key); err != nil {
				L.Push(lua.LNil)
				return 1
			}
			if headers != nil {
				if val, ok := headers[key]; ok {
					result := L.NewTable()
					result.RawSetInt(1, lua.LString(val))
					L.Push(result)
					return 1
				}
			}

			L.Push(lua.LNil)
			return 1
		}))

		if headers != nil {
			headersTable := L.NewTable()
			for k, v := range headers {
				L.SetField(headersTable, k, lua.LString(v))
			}
			L.SetField(mod, "headers", headersTable)
		}

		L.Push(mod)

		return 1
	}
}

func collectMockHTTPHeaders(headersValue lua.LValue) map[string]string {
	result := map[string]string{}

	headersTable, ok := headersValue.(*lua.LTable)
	if !ok || headersTable == nil {
		return result
	}

	headersTable.ForEach(func(key lua.LValue, value lua.LValue) {
		if key.Type() != lua.LTString {
			return
		}

		result[key.String()] = value.String()
	})

	return result
}

func collectMockHTTPOptions(options *lua.LTable) (string, map[string]string) {
	if options == nil {
		return "", map[string]string{}
	}

	body := ""
	if bodyValue := options.RawGetString("body"); bodyValue.Type() == lua.LTString {
		body = bodyValue.String()
	}

	headers := collectMockHTTPHeaders(options.RawGetString("headers"))

	return body, headers
}

func nextMockHTTPResponse(mockData *HTTPClientMock) HTTPClientResponse {
	if mockData != nil && mockData.responseIndex < len(mockData.Responses) {
		response := mockData.Responses[mockData.responseIndex]
		mockData.responseIndex++

		return response
	}

	return HTTPClientResponse{StatusCode: stdhttp.StatusOK}
}

func pushMockHTTPError(L *lua.LState, errMessage string) int {
	L.Push(lua.LNil)
	L.Push(lua.LString(errMessage))

	return 2
}

func pushMockHTTPResponse(L *lua.LState, response HTTPClientResponse) int {
	responseTable := L.NewTable()
	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = stdhttp.StatusOK
	}

	responseTable.RawSetString("status_code", lua.LNumber(statusCode))
	responseTable.RawSetString("body", lua.LString(response.Body))

	headersTable := L.NewTable()
	for key, value := range response.Headers {
		headersTable.RawSetString(key, lua.LString(value))
	}

	responseTable.RawSetString("headers", headersTable)

	L.Push(responseTable)
	L.Push(lua.LNil)

	return 2
}

func recordMockHTTPCall(mockData *HTTPClientMock, method, url, body string, headers map[string]string) error {
	if mockData == nil {
		return nil
	}

	args := fmt.Sprintf("url=%s body=%s", url, body)
	if err := mockData.RecordCall(method, args); err != nil {
		return err
	}

	mockData.Captured = append(mockData.Captured, HTTPClientCapturedRecord{
		Method:  method,
		URL:     url,
		Body:    body,
		Headers: headers,
	})

	return nil
}

func respondMockHTTPCall(L *lua.LState, mockData *HTTPClientMock, method, url string, options *lua.LTable) int {
	body, headers := collectMockHTTPOptions(options)

	if err := recordMockHTTPCall(mockData, method, url, body, headers); err != nil {
		return pushMockHTTPError(L, err.Error())
	}

	response := nextMockHTTPResponse(mockData)
	if response.Error != "" {
		return pushMockHTTPError(L, response.Error)
	}

	return pushMockHTTPResponse(L, response)
}

// LoaderModHTTPClientMock creates a mock glua_http module.
func LoaderModHTTPClientMock(mockData *HTTPClientMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, "post", L.NewFunction(func(L *lua.LState) int {
			url := L.CheckString(1)
			options := L.OptTable(2, nil)

			return respondMockHTTPCall(L, mockData, "post", url, options)
		}))

		L.SetField(mod, "get", L.NewFunction(func(L *lua.LState) int {
			url := L.CheckString(1)
			options := L.OptTable(2, nil)

			return respondMockHTTPCall(L, mockData, "get", url, options)
		}))

		L.SetField(mod, "request", L.NewFunction(func(L *lua.LState) int {
			method := strings.ToLower(L.CheckString(1))
			url := L.CheckString(2)
			options := L.OptTable(3, nil)

			return respondMockHTTPCall(L, mockData, method, url, options)
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModDNSMock creates a mock nauthilus_dns module.
func LoaderModDNSMock(mockData *DNSMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, "lookup", L.NewFunction(func(L *lua.LState) int {
			name := L.CheckString(1)
			if err := mockData.RecordCall("lookup", name); err != nil {
				L.Push(lua.LNil)
				return 1
			}

			if mockData != nil && mockData.LookupResult != nil {
				if value, ok := mockData.LookupResult[name]; ok {
					L.Push(convert.GoToLuaValue(L, value))
					return 1
				}
			}

			L.Push(L.NewTable())

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModOTELMock creates a mock nauthilus_opentelemetry module.
func LoaderModOTELMock(mockData *OpenTelemetryMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		newSpan := func() *lua.LTable {
			span := L.NewTable()
			L.SetField(span, "set_attributes", L.NewFunction(func(L *lua.LState) int {
				_ = mockData.RecordCall("set_attributes", "")
				return 0
			}))
			L.SetField(span, "record_error", L.NewFunction(func(L *lua.LState) int {
				_ = mockData.RecordCall("record_error", "")
				return 0
			}))
			L.SetField(span, "set_status", L.NewFunction(func(L *lua.LState) int {
				_ = mockData.RecordCall("set_status", "")
				return 0
			}))
			L.SetField(span, "finish", L.NewFunction(func(L *lua.LState) int {
				_ = mockData.RecordCall("finish", "")
				return 0
			}))
			return span
		}

		newTracer := func() *lua.LTable {
			tracer := L.NewTable()
			L.SetField(tracer, "start_span", L.NewFunction(func(L *lua.LState) int {
				_ = mockData.RecordCall("start_span", "")
				L.Push(newSpan())
				return 1
			}))
			return tracer
		}

		L.SetField(mod, "tracer", L.NewFunction(func(L *lua.LState) int {
			_ = L.OptString(1, "")
			_ = mockData.RecordCall("tracer", "")
			L.Push(newTracer())
			return 1
		}))

		L.SetField(mod, "default_tracer", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("default_tracer", "")
			L.Push(newTracer())
			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModBruteForceMock creates a mock nauthilus_brute_force module.
func LoaderModBruteForceMock(mockData *BruteForceMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, "is_blocked", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("is_blocked", "")
			if mockData != nil {
				L.Push(lua.LBool(mockData.IsBlocked))
			} else {
				L.Push(lua.LBool(false))
			}

			return 1
		}))

		L.SetField(mod, "increment", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("increment", "")
			incrementBy := 1
			if mockData != nil && mockData.IncrementBy > 0 {
				incrementBy = mockData.IncrementBy
			}
			L.Push(lua.LNumber(incrementBy))

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModPsnetMock creates a mock nauthilus_psnet module.
func LoaderModPsnetMock(mockData *PsnetMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, "get_stats", L.NewFunction(func(L *lua.LState) int {
			target := L.OptString(1, "")
			_ = mockData.RecordCall("get_stats", target)
			if mockData != nil && mockData.Stats != nil {
				L.Push(convert.GoToLuaValue(L, mockData.Stats))
			} else {
				stats := L.NewTable()
				L.SetField(stats, "connections", lua.LNumber(0))
				L.Push(stats)
			}

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModPrometheusMock creates a no-op nauthilus_prometheus module.
func LoaderModPrometheusMock(mockData *PrometheusMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		noop := func(name string) *lua.LFunction {
			return L.NewFunction(func(L *lua.LState) int {
				_ = mockData.RecordCall(name, "")
				return 0
			})
		}

		L.SetField(mod, "create_summary_vec", noop("create_summary_vec"))
		L.SetField(mod, "create_counter_vec", noop("create_counter_vec"))
		L.SetField(mod, "create_histogram_vec", noop("create_histogram_vec"))
		L.SetField(mod, "create_gauge_vec", noop("create_gauge_vec"))
		L.SetField(mod, "increment_counter", noop("increment_counter"))
		L.SetField(mod, "increment_gauge", noop("increment_gauge"))
		L.SetField(mod, "decrement_gauge", noop("decrement_gauge"))

		L.SetField(mod, "start_histogram_timer", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("start_histogram_timer", "")
			timer := L.NewTable()
			L.SetField(timer, "_mock_timer", lua.LBool(true))
			L.Push(timer)
			return 1
		}))

		L.SetField(mod, "start_summary_timer", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("start_summary_timer", "")
			timer := L.NewTable()
			L.SetField(timer, "_mock_timer", lua.LBool(true))
			L.Push(timer)
			return 1
		}))

		L.SetField(mod, "stop_timer", noop("stop_timer"))

		L.Push(mod)

		return 1
	}
}

// LoaderEmptyModule returns an empty Lua module table.
func LoaderEmptyModule() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())
		return 1
	}
}

// LoaderModMiscMock creates a mock nauthilus_misc module.
func LoaderModMiscMock(mockData *MiscMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, definitions.LuaFnGetCountryName, L.NewFunction(func(L *lua.LState) int {
			isoCode := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnGetCountryName, isoCode); err != nil {
				L.Push(lua.LString("Unknown"))
				L.Push(lua.LString(err.Error()))
				return 2
			}
			L.Push(lua.LString("MockCountry"))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnWaitRandom, L.NewFunction(func(L *lua.LState) int {
			min := L.CheckInt(1)
			max := L.CheckInt(2)
			if err := mockData.RecordCall(definitions.LuaFnWaitRandom, fmt.Sprintf("%d:%d", min, max)); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 2
			}
			if min >= max {
				L.Push(lua.LNil)
				L.Push(lua.LString("invalid wait range"))
				return 2
			}
			L.Push(lua.LNumber(min))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnScopedIP, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckAny(1)
			ip := L.CheckString(2)
			if err := mockData.RecordCall(definitions.LuaFnScopedIP, ip); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 2
			}
			L.Push(lua.LString(ip))
			L.Push(lua.LNil)
			return 2
		}))

		L.Push(mod)
		return 1
	}
}

// LoaderModPasswordMock creates a mock nauthilus_password module.
func LoaderModPasswordMock(mockData *PasswordMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, definitions.LuaFnComparePasswords, L.NewFunction(func(L *lua.LState) int {
			hash := L.CheckString(1)
			plain := L.CheckString(2)
			if err := mockData.RecordCall(definitions.LuaFnComparePasswords, hash+":"+plain); err != nil {
				L.Push(lua.LBool(false))
				L.Push(lua.LString(err.Error()))
				return 2
			}
			result := false
			if mockData != nil {
				result = mockData.CompareResult
			}
			L.Push(lua.LBool(result))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnCheckPasswordPolicy, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckTable(1)
			password := L.CheckString(2)
			if err := mockData.RecordCall(definitions.LuaFnCheckPasswordPolicy, password); err != nil {
				L.Push(lua.LBool(false))
				L.Push(lua.LString(err.Error()))
				return 2
			}
			result := true
			if mockData != nil {
				result = mockData.PolicyResult
			}
			L.Push(lua.LBool(result))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnGeneratePasswordHash, L.NewFunction(func(L *lua.LState) int {
			password := L.CheckString(1)
			if err := mockData.RecordCall(definitions.LuaFnGeneratePasswordHash, password); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 2
			}
			generatedHash := "mock$hash"
			if mockData != nil && mockData.GeneratedHash != "" {
				generatedHash = mockData.GeneratedHash
			}
			L.Push(lua.LString(generatedHash))
			L.Push(lua.LNil)
			return 2
		}))

		L.Push(mod)
		return 1
	}
}

// LoaderModSoftWhitelistMock creates a mock nauthilus_soft_whitelist module.
func LoaderModSoftWhitelistMock(mockData *SoftWhitelistMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		entries := map[string][]string{}
		if mockData != nil && mockData.Entries != nil {
			entries = mockData.Entries
		}

		L.SetField(mod, definitions.LuaFnSoftWhitelistSet, L.NewFunction(func(L *lua.LState) int {
			username := L.CheckString(1)
			network := L.CheckString(2)
			feature := L.CheckString(3)
			if err := mockData.RecordCall(definitions.LuaFnSoftWhitelistSet, username+":"+feature); err != nil {
				L.Push(lua.LString(""))
				L.Push(lua.LString(err.Error()))
				return 2
			}
			key := feature + ":" + username
			entries[key] = append(entries[key], network)
			L.Push(lua.LString("OK"))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnSoftWhitelistGet, L.NewFunction(func(L *lua.LState) int {
			username := L.CheckString(1)
			feature := L.CheckString(2)
			if err := mockData.RecordCall(definitions.LuaFnSoftWhitelistGet, username+":"+feature); err != nil {
				L.Push(L.NewTable())
				L.Push(lua.LString(err.Error()))
				return 2
			}
			key := feature + ":" + username
			result := L.NewTable()
			for i, network := range entries[key] {
				result.RawSetInt(i+1, lua.LString(network))
			}
			L.Push(result)
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnSoftWhitelistDelete, L.NewFunction(func(L *lua.LState) int {
			username := L.CheckString(1)
			network := L.CheckString(2)
			feature := L.CheckString(3)
			if err := mockData.RecordCall(definitions.LuaFnSoftWhitelistDelete, username+":"+feature); err != nil {
				L.Push(lua.LString(""))
				L.Push(lua.LString(err.Error()))
				return 2
			}
			key := feature + ":" + username
			current := entries[key]
			next := make([]string, 0, len(current))
			for _, item := range current {
				if item != network {
					next = append(next, item)
				}
			}
			entries[key] = next
			L.Push(lua.LString("OK"))
			L.Push(lua.LNil)
			return 2
		}))

		L.Push(mod)
		return 1
	}
}

// LoaderModMailMock creates a mock nauthilus_mail module.
func LoaderModMailMock(mockData *MailMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetField(mod, definitions.LuaFnSendMail, L.NewFunction(func(L *lua.LState) int {
			tbl := L.CheckTable(1)
			server := tbl.RawGetString("server").String()
			if err := mockData.RecordCall(definitions.LuaFnSendMail, server); err != nil {
				L.Push(lua.LString(err.Error()))
				return 1
			}
			if mockData != nil && mockData.SendError != "" {
				L.Push(lua.LString(mockData.SendError))
				return 1
			}
			L.Push(lua.LNil)
			return 1
		}))
		L.Push(mod)
		return 1
	}
}

// LoaderModHTTPResponseMock creates a mock nauthilus_http_response module.
func LoaderModHTTPResponseMock(mockData *HTTPResponseMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// Constants
		L.SetField(mod, "STATUS_OK", lua.LNumber(200))
		L.SetField(mod, "STATUS_BAD_REQUEST", lua.LNumber(400))
		L.SetField(mod, "STATUS_UNAUTHORIZED", lua.LNumber(401))
		L.SetField(mod, "STATUS_FORBIDDEN", lua.LNumber(403))
		L.SetField(mod, "STATUS_NOT_FOUND", lua.LNumber(404))
		L.SetField(mod, "STATUS_INTERNAL_ERROR", lua.LNumber(500))

		// Mock functions
		L.SetField(mod, "html", L.NewFunction(func(L *lua.LState) int {
			status := L.CheckInt(1)
			_ = L.CheckString(2)
			if err := mockData.RecordCall("html", strconv.Itoa(status)); err != nil {
				return 0
			}
			return 0
		}))

		L.SetField(mod, "set_http_response_header", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			_ = L.CheckString(2)
			if err := mockData.RecordCall("set_http_response_header", key); err != nil {
				return 0
			}
			return 0
		}))

		L.SetField(mod, "json", L.NewFunction(func(L *lua.LState) int {
			status := L.CheckInt(1)
			_ = L.CheckTable(2)
			if err := mockData.RecordCall("json", strconv.Itoa(status)); err != nil {
				return 0
			}
			return 0
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModUtilMock creates a mock nauthilus_util module.
func LoaderModUtilMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		envs := map[string]string{}
		if mockData != nil && mockData.Envs != nil {
			envs = mockData.Envs
		}

		L.SetField(mod, "getenv", L.NewFunction(func(L *lua.LState) int {
			name := L.CheckString(1)
			default_val := L.OptString(2, "")
			_ = mockData.RecordCall("getenv", name)
			if value, ok := envs[name]; ok {
				L.Push(lua.LString(value))
				return 1
			}
			L.Push(lua.LString(default_val))
			return 1
		}))

		L.SetField(mod, "log", L.NewFunction(func(L *lua.LState) int {
			level := L.OptString(2, "")
			_ = mockData.RecordCall("log", level)
			return 0
		}))

		L.SetField(mod, "get_redis_key", L.NewFunction(func(L *lua.LState) int {
			request := L.CheckAny(1)
			key := L.CheckString(2)
			_ = mockData.RecordCall("get_redis_key", key)

			prefix := ""
			if tbl, ok := request.(*lua.LTable); ok {
				if raw := tbl.RawGetString("redis_prefix"); raw.Type() == lua.LTString {
					prefix = raw.String()
				}
			}

			L.Push(lua.LString(prefix + key))
			return 1
		}))

		L.SetField(mod, "if_error_raise", L.NewFunction(func(L *lua.LState) int {
			errValue := L.CheckAny(1)
			_ = mockData.RecordCall("if_error_raise", errValue.String())

			if errValue.Type() != lua.LTNil {
				L.RaiseError("%s", errValue.String())
			}

			return 0
		}))

		L.SetField(mod, "print_result", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("print_result", "")
			return 0
		}))

		L.SetField(mod, "is_table", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("is_table", "")
			_, ok := L.CheckAny(1).(*lua.LTable)
			L.Push(lua.LBool(ok))
			return 1
		}))

		L.SetField(mod, "table_length", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("table_length", "")
			tbl := L.CheckTable(1)
			length := 0
			tbl.ForEach(func(_ lua.LValue, _ lua.LValue) {
				length++
			})
			L.Push(lua.LNumber(length))
			return 1
		}))

		L.SetField(mod, "is_string", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("is_string", "")
			L.Push(lua.LBool(L.CheckAny(1).Type() == lua.LTString))
			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModCacheMock creates a mock nauthilus_cache module.
func LoaderModCacheMock(mockData *CacheMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		cache := map[string]any{}
		if mockData != nil {
			if mockData.Entries == nil {
				mockData.Entries = map[string]any{}
			}

			cache = mockData.Entries
		} else {
			cache = map[string]any{}
		}

		L.SetField(mod, "cache_set", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			value := convert.LuaValueToGo(L.CheckAny(2))
			_ = mockData.RecordCall(definitions.LuaFnCacheSet, key)
			cache[key] = value
			return 0
		}))

		L.SetField(mod, "cache_get", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			_ = mockData.RecordCall(definitions.LuaFnCacheGet, key)
			if val, ok := cache[key]; ok {
				L.Push(convert.GoToLuaValue(L, val))
			} else {
				L.Push(lua.LNil)
			}
			return 1
		}))

		L.SetField(mod, definitions.LuaFnCacheDelete, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			_ = mockData.RecordCall(definitions.LuaFnCacheDelete, key)
			_, existed := cache[key]
			delete(cache, key)
			L.Push(lua.LBool(existed))
			return 1
		}))

		L.SetField(mod, definitions.LuaFnCacheExists, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			_ = mockData.RecordCall(definitions.LuaFnCacheExists, key)
			_, exists := cache[key]
			L.Push(lua.LBool(exists))
			return 1
		}))

		L.SetField(mod, definitions.LuaFnCacheUpdate, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			updater := L.CheckFunction(2)
			_ = mockData.RecordCall(definitions.LuaFnCacheUpdate, key)
			old := cache[key]
			var oldValue lua.LValue = lua.LNil
			if old != nil {
				oldValue = convert.GoToLuaValue(L, old)
			}
			if err := L.CallByParam(lua.P{Fn: updater, NRet: 1, Protect: true}, oldValue); err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))
				return 2
			}
			newValue := L.Get(-1)
			L.Pop(1)
			cache[key] = convert.LuaValueToGo(newValue)
			L.Push(newValue)
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnCacheKeys, L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall(definitions.LuaFnCacheKeys, "")
			keys := L.NewTable()
			i := 1
			for key := range cache {
				keys.RawSetInt(i, lua.LString(key))
				i++
			}
			L.Push(keys)
			return 1
		}))

		L.SetField(mod, definitions.LuaFnCacheSize, L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall(definitions.LuaFnCacheSize, "")
			L.Push(lua.LNumber(len(cache)))
			return 1
		}))

		L.SetField(mod, definitions.LuaFnCacheFlush, L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall(definitions.LuaFnCacheFlush, "")
			for key := range cache {
				delete(cache, key)
			}
			return 0
		}))

		L.SetField(mod, definitions.LuaFnCachePush, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			value := convert.LuaValueToGo(L.CheckAny(2))
			_ = mockData.RecordCall(definitions.LuaFnCachePush, key)
			current, ok := cache[key]
			if !ok {
				cache[key] = []any{value}
				L.Push(lua.LNumber(1))
				return 1
			}
			list, ok := current.([]any)
			if !ok {
				list = []any{current}
			}
			list = append(list, value)
			cache[key] = list
			L.Push(lua.LNumber(len(list)))
			return 1
		}))

		L.SetField(mod, definitions.LuaFnCachePopAll, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			_ = mockData.RecordCall(definitions.LuaFnCachePopAll, key)
			current, ok := cache[key]
			delete(cache, key)
			result := L.NewTable()
			if !ok {
				L.Push(result)
				return 1
			}
			if list, ok := current.([]any); ok {
				for i, value := range list {
					result.RawSetInt(i+1, convert.GoToLuaValue(L, value))
				}
			} else {
				result.RawSetInt(1, convert.GoToLuaValue(L, current))
			}
			L.Push(result)
			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// bindRequestValue binds a Go value to a Lua table with a specific key.
func bindRequestValue(L *lua.LState, mod *lua.LTable, key string, value any) {
	ud := L.NewUserData()
	ud.Value = value
	L.SetField(mod, key, ud)
}

// bindRequestValueToEnv binds a Go value to the request environment table.
func bindRequestValueToEnv(L *lua.LState, reqEnv *lua.LTable, key string, value any) {
	if L == nil || reqEnv == nil || key == "" || value == nil {
		return
	}

	userData := L.NewUserData()
	userData.Value = value
	L.SetField(reqEnv, key, userData)
}

// luaRequestContextKey is the key used to store context in request environment.
// Must match the key defined in server/lualib/requestenv.go
const luaRequestContextKey = "__NAUTH_REQ_CONTEXT"

// MockLogger captures log output for testing.
type MockLogger struct {
	Logs           []string
	StatusMessages []string
}

// Log adds a log message.
func (m *MockLogger) Log(msg string) {
	m.Logs = append(m.Logs, msg)
}

// LogStatus adds a status message and mirrors it into the generic log stream.
func (m *MockLogger) LogStatus(msg string) {
	m.StatusMessages = append(m.StatusMessages, msg)
	m.Log(fmt.Sprintf("[STATUS] %s", msg))
}

// SetupBuiltinTable configures the global nauthilus_builtin table used by real scripts.
func SetupBuiltinTable(L *lua.LState, logger *MockLogger) {
	if L == nil {
		return
	}

	builtin := L.NewTable()
	builtin.RawSetString(definitions.LuaActionResultOk, lua.LNumber(0))
	builtin.RawSetString(definitions.LuaActionResultFail, lua.LNumber(1))
	builtin.RawSetString(definitions.LuaFilterAccept, lua.LBool(false))
	builtin.RawSetString(definitions.LuaFilterREJECT, lua.LBool(true))
	builtin.RawSetString(definitions.LuaFilterResultOk, lua.LNumber(0))
	builtin.RawSetString(definitions.LuaFilterResultFail, lua.LNumber(1))
	builtin.RawSetString(definitions.LuaFeatureTriggerNo, lua.LBool(false))
	builtin.RawSetString(definitions.LuaFeatureTriggerYes, lua.LBool(true))
	builtin.RawSetString(definitions.LuaFeatureAbortNo, lua.LBool(false))
	builtin.RawSetString(definitions.LuaFeatureAbortYes, lua.LBool(true))
	builtin.RawSetString(definitions.LuaFeatureResultOk, lua.LNumber(0))
	builtin.RawSetString(definitions.LuaFeatureResultFail, lua.LNumber(1))

	builtin.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(func(L *lua.LState) int {
		logKey := L.CheckString(1)
		logValue := L.OptString(2, "")

		if logger != nil {
			logger.Log(fmt.Sprintf("[CUSTOM] %s: %s", logKey, logValue))
		}

		return 0
	}))

	// Match runtime behavior where scripts can set a user-facing status message
	// via nauthilus_builtin.status_message_set(...).
	builtin.RawSetString(definitions.LuaFnSetStatusMessage, L.NewFunction(func(L *lua.LState) int {
		status := L.CheckString(1)

		if logger != nil {
			logger.LogStatus(status)
		}

		return 0
	}))

	L.SetGlobal(definitions.LuaDefaultTable, builtin)
}

// SetupMockModules configures all mock modules in the Lua state.
// It returns a cleanup function that must be called by the caller to release runtime resources.
func SetupMockModules(L *lua.LState, mockData *MockData, logger *MockLogger) (func(), error) {
	if mockData == nil {
		mockData = &MockData{}
	}

	cleanupFns := make([]func(), 0, 2)
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			if cleanupFns[i] != nil {
				cleanupFns[i]()
			}
		}
	}

	// Match production Lua preloads so scripts can use gopher-lua-libs in test mode.
	libs.Preload(L)
	L.PreloadModule("glua_crypto", gluacrypto.Loader)

	// Always shadow gopher-lua-libs db module in test mode so all DB scripts run
	// against the in-memory mock regardless of driver/DSN.
	dbMock := mockData.DB
	if dbMock == nil {
		dbMock = &DBMock{}
	}
	mockData.DB = dbMock
	dbMock.ResetRuntimeState()
	L.PreloadModule("db", LoaderModDBMock(dbMock))

	backendMock := mockData.Backend
	if backendMock == nil {
		backendMock = &BackendMock{}
	}
	mockData.Backend = backendMock
	backendMock.ResetRuntimeState()

	contextMock := mockData.Context
	if contextMock != nil {
		contextMock.ResetRuntimeState()
	}

	redisMock := mockData.Redis
	if redisMock == nil {
		redisMock = &RedisMock{}
	}
	mockData.Redis = redisMock
	redisMock.ResetRuntimeState()

	redisRuntime, err := newRedisRuntime(redisMock)
	if err != nil {
		cleanup()

		return nil, fmt.Errorf("failed to setup miniredis runtime: %w", err)
	}
	cleanupFns = append(cleanupFns, redisRuntime.Close)

	ldapMock := mockData.LDAP
	if ldapMock == nil {
		ldapMock = &LDAPMock{}
	}
	mockData.LDAP = ldapMock
	ldapMock.ResetRuntimeState()

	backendResultMock := mockData.BackendResult
	if backendResultMock == nil {
		backendResultMock = &BackendResultMock{}
	}
	mockData.BackendResult = backendResultMock
	backendResultMock.ResetRuntimeState()

	httpRequestMock := mockData.HTTPRequest
	if httpRequestMock == nil {
		httpRequestMock = &HTTPRequestMock{}
	}
	mockData.HTTPRequest = httpRequestMock
	httpRequestMock.ResetRuntimeState()

	httpResponseMock := mockData.HTTPResponse
	if httpResponseMock == nil {
		httpResponseMock = &HTTPResponseMock{}
	}
	mockData.HTTPResponse = httpResponseMock
	httpResponseMock.ResetRuntimeState()

	httpClientMock := mockData.HTTPClient
	if httpClientMock != nil {
		httpClientMock.ResetRuntimeState()
		L.PreloadModule("glua_http", LoaderModHTTPClientMock(httpClientMock))
	} else {
		L.PreloadModule("glua_http", gluahttp.NewHttpModule(&stdhttp.Client{}).Loader)
	}

	dnsMock := mockData.DNS
	if dnsMock == nil {
		dnsMock = &DNSMock{}
	}
	mockData.DNS = dnsMock
	dnsMock.ResetRuntimeState()

	otelMock := mockData.OpenTelemetry
	if otelMock == nil {
		otelMock = &OpenTelemetryMock{}
	}
	mockData.OpenTelemetry = otelMock
	otelMock.ResetRuntimeState()

	bruteForceMock := mockData.BruteForce
	if bruteForceMock == nil {
		bruteForceMock = &BruteForceMock{}
	}
	mockData.BruteForce = bruteForceMock
	bruteForceMock.ResetRuntimeState()

	psnetMock := mockData.Psnet
	if psnetMock == nil {
		psnetMock = &PsnetMock{}
	}
	mockData.Psnet = psnetMock
	psnetMock.ResetRuntimeState()

	prometheusMock := mockData.Prometheus
	if prometheusMock == nil {
		prometheusMock = &PrometheusMock{}
	}
	mockData.Prometheus = prometheusMock
	prometheusMock.ResetRuntimeState()

	utilMock := mockData.Util
	if utilMock == nil {
		utilMock = &UtilMock{}
	}
	mockData.Util = utilMock
	utilMock.ResetRuntimeState()

	cacheMock := mockData.Cache
	if cacheMock == nil {
		cacheMock = &CacheMock{}
	}
	mockData.Cache = cacheMock
	cacheMock.ResetRuntimeState()

	miscMock := mockData.Misc
	if miscMock == nil {
		miscMock = &MiscMock{}
	}
	mockData.Misc = miscMock
	miscMock.ResetRuntimeState()

	passwordMock := mockData.Password
	if passwordMock == nil {
		passwordMock = &PasswordMock{}
	}
	mockData.Password = passwordMock
	passwordMock.ResetRuntimeState()

	softWhitelistMock := mockData.SoftWhitelist
	if softWhitelistMock == nil {
		softWhitelistMock = &SoftWhitelistMock{}
	}
	mockData.SoftWhitelist = softWhitelistMock
	softWhitelistMock.ResetRuntimeState()

	mailMock := mockData.Mail
	if mailMock == nil {
		mailMock = &MailMock{}
	}
	mockData.Mail = mailMock
	mailMock.ResetRuntimeState()

	// Create global request environment table
	reqEnv := L.NewTable()
	L.SetGlobal("__NAUTH_REQ_ENV", reqEnv)

	// Create and bind context
	luaCtx := lualib.NewContext()
	if mockData.Context != nil {
		// Set all fields from mock data
		luaCtx.Set(definitions.LuaRequestUsername, mockData.Context.Username)
		luaCtx.Set(definitions.LuaRequestPassword, mockData.Context.Password)
		luaCtx.Set(definitions.LuaRequestClientIP, mockData.Context.ClientIP)
		luaCtx.Set(definitions.LuaRequestClientPort, mockData.Context.ClientPort)
		luaCtx.Set(definitions.LuaRequestClientHost, mockData.Context.ClientHost)
		luaCtx.Set(definitions.LuaRequestClientID, mockData.Context.ClientID)
		luaCtx.Set(definitions.LuaRequestLocalIP, mockData.Context.LocalIP)
		luaCtx.Set(definitions.LuaRequestLocalPort, mockData.Context.LocalPort)
		luaCtx.Set(definitions.LuaRequestService, mockData.Context.Service)
		luaCtx.Set(definitions.LuaRequestProtocol, mockData.Context.Protocol)
		luaCtx.Set(definitions.LuaRequestUserAgent, mockData.Context.UserAgent)
		luaCtx.Set(definitions.LuaRequestSession, mockData.Context.Session)
		luaCtx.Set(definitions.LuaRequestDebug, mockData.Context.Debug)
		luaCtx.Set(definitions.LuaRequestNoAuth, mockData.Context.NoAuth)
		luaCtx.Set(definitions.LuaRequestAuthenticated, mockData.Context.Authenticated)
		luaCtx.Set(definitions.LuaRequestUserFound, mockData.Context.UserFound)
		luaCtx.Set(definitions.LuaRequestAccount, mockData.Context.Account)
		luaCtx.Set(definitions.LuaRequestUniqueUserID, mockData.Context.UniqueUserID)
		luaCtx.Set(definitions.LuaRequestDisplayName, mockData.Context.DisplayName)
		luaCtx.Set(definitions.LuaRequestStatusMessage, mockData.Context.StatusMessage)
		luaCtx.Set(definitions.LuaRequestBruteForceCounter, mockData.Context.BruteForceCount)

		// Set attributes if provided
		if mockData.Context.Attributes != nil {
			for k, v := range mockData.Context.Attributes {
				luaCtx.Set(k, v)
			}
		}
	}

	// Bind context to request environment
	bindRequestValueToEnv(L, reqEnv, luaRequestContextKey, luaCtx)

	// Preload mock modules
	L.PreloadModule(definitions.LuaModContext, LoaderModContextMock(contextMock))
	L.PreloadModule(definitions.LuaModRedis, redisRuntime.Loader(context.Background(), resolveLuaTestConfig(), redisMock))
	L.PreloadModule(definitions.LuaModBackend, LoaderModBackendMock(backendMock))
	L.PreloadModule(definitions.LuaBackendResultTypeName, LoaderModBackendResultMock(backendResultMock))
	L.PreloadModule(definitions.LuaModHTTPRequest, LoaderModHTTPRequestMock(httpRequestMock))
	L.PreloadModule(definitions.LuaModHTTPResponse, LoaderModHTTPResponseMock(httpResponseMock))
	L.PreloadModule(definitions.LuaModLDAP, LoaderModLDAPMock(ldapMock))
	L.PreloadModule(definitions.LuaModDNS, LoaderModDNSMock(dnsMock))
	L.PreloadModule(definitions.LuaModPrometheus, LoaderModPrometheusMock(prometheusMock))
	L.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTELMock(otelMock))
	L.PreloadModule(definitions.LuaModBruteForce, LoaderModBruteForceMock(bruteForceMock))
	L.PreloadModule(definitions.LuaModPsnet, LoaderModPsnetMock(psnetMock))
	L.PreloadModule(definitions.LuaModMisc, LoaderModMiscMock(miscMock))
	L.PreloadModule(definitions.LuaModPassword, LoaderModPasswordMock(passwordMock))
	L.PreloadModule(definitions.LuaModSoftWhitelist, LoaderModSoftWhitelistMock(softWhitelistMock))
	L.PreloadModule(definitions.LuaModMail, LoaderModMailMock(mailMock))
	L.PreloadModule("nauthilus_util", LoaderModUtilMock(utilMock))
	L.PreloadModule("nauthilus_cache", LoaderModCacheMock(cacheMock))

	SetupBuiltinTable(L, logger)

	// Set up global context if needed
	if mockData.Context != nil {
		ctx := context.Background()
		L.SetGlobal("__test_context", convert.GoToLuaValue(L, ctx))
	}

	return cleanup, nil
}
