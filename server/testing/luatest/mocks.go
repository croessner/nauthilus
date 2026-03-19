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
	"encoding/json"
	"fmt"
	stdhttp "net/http"
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
func LoaderModContextMock(_ *ContextMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// Bind context get/set/delete functions using ContextManager
		// which will look up the context from the global request environment
		manager := lualib.NewContextManager()
		L.SetField(mod, definitions.LuaFnCtxSet, L.NewFunction(manager.ContextSet))
		L.SetField(mod, definitions.LuaFnCtxGet, L.NewFunction(manager.ContextGet))
		L.SetField(mod, definitions.LuaFnCtxDelete, L.NewFunction(manager.ContextDelete))

		L.Push(mod)

		return 1
	}
}

// LoaderModRedisMock creates a mock nauthilus_redis module.
func LoaderModRedisMock(mockData *RedisMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		responses := make(map[string]any)
		if mockData != nil && mockData.Responses != nil {
			responses = mockData.Responses
		}

		var toLuaValue func(val any) lua.LValue
		toLuaValue = func(val any) lua.LValue {
			switch v := val.(type) {
			case nil:
				return lua.LNil
			case string:
				return lua.LString(v)
			case float64:
				return lua.LNumber(v)
			case int:
				return lua.LNumber(v)
			case bool:
				return lua.LBool(v)
			case map[string]string:
				tbl := L.NewTable()
				for key, value := range v {
					tbl.RawSetString(key, lua.LString(value))
				}
				return tbl
			case map[string]any:
				tbl := L.NewTable()
				for key, value := range v {
					tbl.RawSetString(key, toLuaValue(value))
				}
				return tbl
			default:
				if jsonBytes, err := json.Marshal(v); err == nil {
					return lua.LString(string(jsonBytes))
				}
				return lua.LNil
			}
		}

		// Mock GET
		L.SetField(mod, "get", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if val, ok := responses[key]; ok {
				L.Push(toLuaValue(val))
			} else {
				L.Push(lua.LNil)
			}

			return 1
		}))

		// Mock SET
		L.SetField(mod, "set", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			value := L.CheckAny(2)
			responses[key] = convert.LuaValueToGo(value)
			L.Push(lua.LBool(true))

			return 1
		}))

		// Mock DEL
		L.SetField(mod, "del", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			_, existed := responses[key]
			delete(responses, key)
			if existed {
				L.Push(lua.LNumber(1))
			} else {
				L.Push(lua.LNumber(0))
			}

			return 1
		}))

		// Mock EXISTS
		L.SetField(mod, "exists", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if _, ok := responses[key]; ok {
				L.Push(lua.LNumber(1))
			} else {
				L.Push(lua.LNumber(0))
			}

			return 1
		}))

		// Mock INCR
		L.SetField(mod, "incr", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			current := 0.0
			if val, ok := responses[key]; ok {
				switch num := val.(type) {
				case float64:
					current = num
				case int:
					current = float64(num)
				case string:
					if parsed, err := strconv.ParseFloat(num, 64); err == nil {
						current = parsed
					}
				}
			}
			current++
			responses[key] = current
			L.Push(lua.LNumber(current))

			return 1
		}))

		// Mock EXPIRE
		L.SetField(mod, "expire", L.NewFunction(func(L *lua.LState) int {
			// In mock mode, just return success
			L.Push(lua.LBool(true))

			return 1
		}))

		L.SetField(mod, definitions.LuaFnRedisGet, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckString(1) // pool
			key := L.CheckString(2)

			if val, ok := responses[key]; ok {
				L.Push(toLuaValue(val))
				L.Push(lua.LNil)
				return 2
			}

			L.Push(lua.LNil)
			L.Push(lua.LString("redis: nil"))
			return 2
		}))

		L.SetField(mod, definitions.LuaFnRedisSet, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckString(1) // pool
			key := L.CheckString(2)
			value := convert.LuaValueToGo(L.CheckAny(3))

			if L.GetTop() >= 4 {
				if options, ok := L.Get(4).(*lua.LTable); ok {
					nxVal := options.RawGetString("nx")
					if lua.LVAsBool(nxVal) {
						if _, exists := responses[key]; exists {
							L.Push(lua.LNil)
							L.Push(lua.LNil)
							return 2
						}
					}
				}
			}

			responses[key] = value
			L.Push(lua.LBool(true))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnRedisExpire, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckString(1) // pool
			_ = L.CheckString(2) // key
			_ = L.CheckInt(3)    // expiration
			L.Push(lua.LBool(true))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnRedisHSet, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckString(1) // pool
			key := L.CheckString(2)

			hash, _ := responses[key].(map[string]any)
			if hash == nil {
				hash = map[string]any{}
			}

			for i := 3; i+1 <= L.GetTop(); i += 2 {
				field := L.CheckString(i)
				hash[field] = convert.LuaValueToGo(L.CheckAny(i + 1))
			}
			responses[key] = hash

			L.Push(lua.LBool(true))
			L.Push(lua.LNil)
			return 2
		}))

		L.SetField(mod, definitions.LuaFnRedisHGetAll, L.NewFunction(func(L *lua.LState) int {
			_ = L.CheckString(1) // pool
			key := L.CheckString(2)

			raw, ok := responses[key]
			if !ok {
				L.Push(lua.LNil)
				L.Push(lua.LString("redis: nil"))
				return 2
			}

			switch v := raw.(type) {
			case map[string]string:
				tbl := L.NewTable()
				for field, value := range v {
					tbl.RawSetString(field, lua.LString(value))
				}
				L.Push(tbl)
				L.Push(lua.LNil)
				return 2
			case map[string]any:
				tbl := L.NewTable()
				for field, value := range v {
					tbl.RawSetString(field, toLuaValue(value))
				}
				L.Push(tbl)
				L.Push(lua.LNil)
				return 2
			default:
				L.Push(lua.LNil)
				L.Push(lua.LString("wrongtype"))
				return 2
			}
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

// LoaderModBackendResultMock creates a mock nauthilus_backend_result module.
func LoaderModBackendResultMock(mockData *BackendResultMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		if mockData == nil {
			mockData = &BackendResultMock{}
		}

		// Create a function that returns mock backend result
		L.SetField(mod, "new", L.NewFunction(func(L *lua.LState) int {
			result := L.NewTable()

			L.SetField(result, definitions.LuaBackendResultAuthenticated, lua.LBool(mockData.Authenticated))
			L.SetField(result, definitions.LuaBackendResultUserFound, lua.LBool(mockData.UserFound))
			L.SetField(result, definitions.LuaBackendResultAccountField, lua.LString(mockData.AccountField))
			L.SetField(result, definitions.LuaBackendResultTOTPSecretField, lua.LString(mockData.TOTPSecret))
			L.SetField(result, "unique_user_id", lua.LString(mockData.UniqueUserID))
			L.SetField(result, definitions.LuaBackendResultDisplayNameField, lua.LString(mockData.DisplayName))

			if mockData.TOTPRecovery != nil {
				recoveryTable := L.NewTable()
				for i, code := range mockData.TOTPRecovery {
					L.RawSetInt(recoveryTable, i+1, lua.LString(code))
				}
				L.SetField(result, definitions.LuaBackendResultTOTPRecoveryField, recoveryTable)
			}

			if mockData.Attributes != nil {
				attrTable := L.NewTable()
				for k, v := range mockData.Attributes {
					L.SetField(attrTable, k, lua.LString(v))
				}
				L.SetField(result, definitions.LuaBackendResultAttributes, attrTable)
			}

			L.Push(result)

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
			L.Push(lua.LString(method))
			return 1
		}))

		L.SetField(mod, "get_http_path", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LString(path))
			return 1
		}))

		L.SetField(mod, "get_http_body", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LString(body))
			return 1
		}))

		L.SetField(mod, "get_http_header", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
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

// LoaderModDNSMock creates a mock nauthilus_dns module.
func LoaderModDNSMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// Mock DNS lookup - returns empty for now
		L.SetField(mod, "lookup", L.NewFunction(func(L *lua.LState) int {
			L.Push(L.NewTable())

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModOTELMock creates a mock nauthilus_opentelemetry module.
func LoaderModOTELMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		newSpan := func() *lua.LTable {
			span := L.NewTable()
			L.SetField(span, "set_attributes", L.NewFunction(func(L *lua.LState) int { return 0 }))
			L.SetField(span, "record_error", L.NewFunction(func(L *lua.LState) int { return 0 }))
			L.SetField(span, "set_status", L.NewFunction(func(L *lua.LState) int { return 0 }))
			L.SetField(span, "finish", L.NewFunction(func(L *lua.LState) int { return 0 }))
			return span
		}

		newTracer := func() *lua.LTable {
			tracer := L.NewTable()
			L.SetField(tracer, "start_span", L.NewFunction(func(L *lua.LState) int {
				L.Push(newSpan())
				return 1
			}))
			return tracer
		}

		L.SetField(mod, "tracer", L.NewFunction(func(L *lua.LState) int {
			_ = L.OptString(1, "")
			L.Push(newTracer())
			return 1
		}))

		L.SetField(mod, "default_tracer", L.NewFunction(func(L *lua.LState) int {
			L.Push(newTracer())
			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModBruteForceMock creates a mock nauthilus_brute_force module.
func LoaderModBruteForceMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// Mock brute force check - always returns not blocked
		L.SetField(mod, "is_blocked", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LBool(false))

			return 1
		}))

		L.SetField(mod, "increment", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LNumber(1))

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModPsnetMock creates a mock nauthilus_psnet module.
func LoaderModPsnetMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// Mock network stats - returns empty stats
		L.SetField(mod, "get_stats", L.NewFunction(func(L *lua.LState) int {
			stats := L.NewTable()
			L.SetField(stats, "connections", lua.LNumber(0))
			L.Push(stats)

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModPrometheusMock creates a no-op nauthilus_prometheus module.
func LoaderModPrometheusMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		noop := L.NewFunction(func(L *lua.LState) int { return 0 })

		L.SetField(mod, "create_summary_vec", noop)
		L.SetField(mod, "create_counter_vec", noop)
		L.SetField(mod, "create_histogram_vec", noop)
		L.SetField(mod, "create_gauge_vec", noop)
		L.SetField(mod, "increment_counter", noop)
		L.SetField(mod, "increment_gauge", noop)
		L.SetField(mod, "decrement_gauge", noop)

		L.SetField(mod, "start_histogram_timer", L.NewFunction(func(L *lua.LState) int {
			timer := L.NewTable()
			L.SetField(timer, "_mock_timer", lua.LBool(true))
			L.Push(timer)
			return 1
		}))

		L.SetField(mod, "start_summary_timer", L.NewFunction(func(L *lua.LState) int {
			timer := L.NewTable()
			L.SetField(timer, "_mock_timer", lua.LBool(true))
			L.Push(timer)
			return 1
		}))

		L.SetField(mod, "stop_timer", noop)

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
			// status := L.CheckInt(1)
			// html := L.CheckString(2)
			// Just accept the call, don't do anything
			return 0
		}))

		L.SetField(mod, "set_http_response_header", L.NewFunction(func(L *lua.LState) int {
			// key := L.CheckString(1)
			// value := L.CheckString(2)
			// Just accept the call
			return 0
		}))

		L.SetField(mod, "json", L.NewFunction(func(L *lua.LState) int {
			// status := L.CheckInt(1)
			// data := L.CheckTable(2)
			// Just accept the call
			return 0
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModUtilMock creates a mock nauthilus_util module.
func LoaderModUtilMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		L.SetField(mod, "getenv", L.NewFunction(func(L *lua.LState) int {
			// name := L.CheckString(1)
			default_val := L.OptString(2, "")
			L.Push(lua.LString(default_val))
			return 1
		}))

		L.SetField(mod, "print_result", L.NewFunction(func(L *lua.LState) int {
			// Just accept the call
			return 0
		}))

		L.SetField(mod, "is_table", L.NewFunction(func(L *lua.LState) int {
			_, ok := L.CheckAny(1).(*lua.LTable)
			L.Push(lua.LBool(ok))
			return 1
		}))

		L.SetField(mod, "table_length", L.NewFunction(func(L *lua.LState) int {
			tbl := L.CheckTable(1)
			length := 0
			tbl.ForEach(func(_ lua.LValue, _ lua.LValue) {
				length++
			})
			L.Push(lua.LNumber(length))
			return 1
		}))

		L.SetField(mod, "is_string", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LBool(L.CheckAny(1).Type() == lua.LTString))
			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// LoaderModCacheMock creates a mock nauthilus_cache module.
func LoaderModCacheMock() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		cache := make(map[string]string)

		L.SetField(mod, "cache_set", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			value := L.CheckString(2)
			// ttl := L.OptInt(3, 0)
			cache[key] = value
			return 0
		}))

		L.SetField(mod, "cache_get", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			if val, ok := cache[key]; ok {
				L.Push(lua.LString(val))
			} else {
				L.Push(lua.LNil)
			}
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
	Logs []string
}

// Log adds a log message.
func (m *MockLogger) Log(msg string) {
	m.Logs = append(m.Logs, msg)
}

// LoaderModLogMock creates a mock logging module that captures output.
func LoaderModLogMock(logger *MockLogger) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		logFunc := func(level string) lua.LGFunction {
			return func(L *lua.LState) int {
				msg := L.CheckString(1)
				logMsg := fmt.Sprintf("[%s] %s", level, msg)
				logger.Log(logMsg)

				return 0
			}
		}

		L.SetField(mod, "debug", L.NewFunction(logFunc("DEBUG")))
		L.SetField(mod, "info", L.NewFunction(logFunc("INFO")))
		L.SetField(mod, "warn", L.NewFunction(logFunc("WARN")))
		L.SetField(mod, "error", L.NewFunction(logFunc("ERROR")))

		L.Push(mod)

		return 1
	}
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

	L.SetGlobal(definitions.LuaDefaultTable, builtin)
}

// SetupMockModules configures all mock modules in the Lua state.
func SetupMockModules(L *lua.LState, mockData *MockData, logger *MockLogger) {
	if mockData == nil {
		mockData = &MockData{}
	}

	// Match production Lua preloads so scripts can use gopher-lua-libs in test mode.
	libs.Preload(L)
	L.PreloadModule("glua_crypto", gluacrypto.Loader)
	L.PreloadModule("glua_http", gluahttp.NewHttpModule(&stdhttp.Client{}).Loader)

	// Always shadow gopher-lua-libs db module in test mode so all DB scripts run
	// against the in-memory mock regardless of driver/DSN.
	dbMock := mockData.DB
	if dbMock == nil {
		dbMock = &DBMock{}
	}
	dbMock.ResetRuntimeState()
	L.PreloadModule("db", LoaderModDBMock(dbMock))

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
	L.PreloadModule(definitions.LuaModContext, LoaderModContextMock(mockData.Context))
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedisMock(mockData.Redis))
	L.PreloadModule(definitions.LuaBackendResultTypeName, LoaderModBackendResultMock(mockData.BackendResult))
	L.PreloadModule(definitions.LuaModHTTPRequest, LoaderModHTTPRequestMock(mockData.HTTPRequest))
	L.PreloadModule(definitions.LuaModHTTPResponse, LoaderModHTTPResponseMock(mockData.HTTPResponse))
	L.PreloadModule(definitions.LuaModLDAP, LoaderModLDAPMock(mockData.LDAP))
	L.PreloadModule(definitions.LuaModDNS, LoaderModDNSMock())
	L.PreloadModule(definitions.LuaModPrometheus, LoaderModPrometheusMock())
	L.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTELMock())
	L.PreloadModule(definitions.LuaModBruteForce, LoaderModBruteForceMock())
	L.PreloadModule(definitions.LuaModPsnet, LoaderModPsnetMock())
	L.PreloadModule("nauthilus_util", LoaderModUtilMock())
	L.PreloadModule("nauthilus_cache", LoaderModCacheMock())

	if logger != nil {
		L.PreloadModule("nauthilus_log", LoaderModLogMock(logger))
	}

	SetupBuiltinTable(L, logger)

	// Set up global context if needed
	if mockData.Context != nil {
		ctx := context.Background()
		L.SetGlobal("__test_context", convert.GoToLuaValue(L, ctx))
	}
}
