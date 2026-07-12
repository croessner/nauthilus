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
	"sort"
	"strconv"
	"strings"

	"github.com/cjoudrey/gluahttp"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/testing/dbmock"
	gluacrypto "github.com/tengattack/gluacrypto/crypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

const (
	luaTestMockMethodClose  = "close"
	luaTestMockMethodExec   = "exec"
	luaTestMockMethodQuery  = "query"
	luaTestMockUniqueUserID = "unique_user_id"
)

type luaMockModuleField struct {
	name     string
	callback lua.LGFunction
}

type luaMockModuleID uint8

type resettableLuaMock interface {
	ResetRuntimeState()
}

type softWhitelistMutation func(current []string, network string) []string

const (
	luaMockModuleHTTPRequest luaMockModuleID = iota
	luaMockModuleHTTPResponse
	luaMockModulePolicy
	luaMockModuleI18N
	luaMockModuleLDAP
	luaMockModuleDNS
	luaMockModulePrometheus
	luaMockModuleOpenTelemetry
	luaMockModuleBruteForce
	luaMockModulePsnet
)

var (
	httpPolicyDirectoryMockModuleIDs = []luaMockModuleID{
		luaMockModuleHTTPRequest,
		luaMockModuleHTTPResponse,
		luaMockModulePolicy,
		luaMockModuleI18N,
		luaMockModuleLDAP,
	}
	observabilityMockModuleIDs = []luaMockModuleID{
		luaMockModuleDNS,
		luaMockModulePrometheus,
		luaMockModuleOpenTelemetry,
		luaMockModuleBruteForce,
		luaMockModulePsnet,
	}
)

// loaderMockModule creates a table-backed Lua mock module from named callbacks.
func loaderMockModule(fields ...luaMockModuleField) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		for _, field := range fields {
			L.SetField(mod, field.name, L.NewFunction(field.callback))
		}

		L.Push(mod)

		return 1
	}
}

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

// LoaderModPolicyMock creates a fixture-aware nauthilus_policy module.
func LoaderModPolicyMock(mockData *PolicyMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			definitions.LuaFnPolicyEmitAttribute: func(L *lua.LState) int {
				return recordLuaTableRegistration(
					L,
					mockData,
					definitions.LuaFnPolicyEmitAttribute,
					policyEmissionFromTable,
					policyEmissionArgs,
					func(emission PolicyEmission) bool { return emission.ID != "" },
					"id must be a non-empty string",
					func(emission PolicyEmission) {
						if mockData != nil {
							mockData.Emitted = append(mockData.Emitted, emission)
						}
					},
				)
			},
		})
		L.Push(mod)

		return 1
	}
}

// recordLuaTableRegistration validates one table-backed Lua mock call and captures fixture state.
func recordLuaTableRegistration[T any](
	L *lua.LState,
	recorder luaCallRecorder,
	method string,
	parse func(*lua.LTable) T,
	formatArgs func(T) string,
	valid func(T) bool,
	validationError string,
	capture func(T),
) int {
	value := parse(L.CheckTable(1))
	if !valid(value) {
		L.ArgError(1, validationError)

		return 0
	}

	if recorder != nil {
		if err := recorder.RecordCall(method, formatArgs(value)); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}
	}

	if capture != nil {
		capture(value)
	}

	return 0
}

func policyEmissionFromTable(table *lua.LTable) PolicyEmission {
	emission := PolicyEmission{
		ID:      strings.TrimSpace(luaValueString(table.RawGetString("id"))),
		Value:   luaValueString(table.RawGetString("value")),
		Details: map[string]string{},
	}

	if detailsTable, ok := table.RawGetString("details").(*lua.LTable); ok {
		detailsTable.ForEach(func(key lua.LValue, value lua.LValue) {
			emission.Details[key.String()] = luaValueString(value)
		})
	}

	if len(emission.Details) == 0 {
		emission.Details = nil
	}

	return emission
}

func policyEmissionArgs(emission PolicyEmission) string {
	return keyedMapArgs([]string{
		"id=" + emission.ID,
		"value=" + emission.Value,
	}, "details.", emission.Details)
}

// LoaderModI18NMock creates a fixture-aware nauthilus_i18n module.
func LoaderModI18NMock(mockData *I18NMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			definitions.LuaFnI18NRegisterCatalog: func(L *lua.LState) int {
				return recordLuaTableRegistration(
					L,
					mockData,
					definitions.LuaFnI18NRegisterCatalog,
					i18NCatalogFromTable,
					i18NCatalogArgs,
					func(registration I18NCatalogRegistration) bool { return registration.Language != "" },
					"language must be a non-empty string",
					func(registration I18NCatalogRegistration) {
						if mockData != nil {
							mockData.Catalogs = append(mockData.Catalogs, registration)
						}
					},
				)
			},
			definitions.LuaFnI18NGetLocalized: func(L *lua.LState) int {
				table := L.CheckTable(1)
				key := strings.TrimSpace(luaValueString(table.RawGetString("i18n_key")))
				fallback := luaValueString(table.RawGetString("fallback"))

				language := strings.TrimSpace(luaValueString(table.RawGetString("language")))
				if language == "" {
					language = "en"
				}

				args := strings.Join([]string{
					"i18n_key=" + key,
					"language=" + language,
					"fallback=" + fallback,
				}, " ")
				if err := mockData.RecordCall(definitions.LuaFnI18NGetLocalized, args); err != nil {
					L.RaiseError("%s", err.Error())

					return 0
				}

				result := L.NewTable()
				L.SetField(result, "message", lua.LString(fallback))
				L.SetField(result, "language", lua.LString(language))
				L.SetField(result, "localized", lua.LBool(false))
				L.SetField(result, "i18n_key", lua.LString(key))
				L.SetField(result, "fallback_used", lua.LBool(true))
				L.Push(result)

				return 1
			},
		})
		L.Push(mod)

		return 1
	}
}

func i18NCatalogFromTable(table *lua.LTable) I18NCatalogRegistration {
	registration := I18NCatalogRegistration{
		Language:  strings.TrimSpace(luaValueString(table.RawGetString("language"))),
		Namespace: strings.TrimSpace(luaValueString(table.RawGetString("namespace"))),
		Entries:   map[string]string{},
	}

	if entriesTable, ok := table.RawGetString("entries").(*lua.LTable); ok {
		entriesTable.ForEach(func(key lua.LValue, value lua.LValue) {
			registration.Entries[key.String()] = luaValueString(value)
		})
	}

	return registration
}

func i18NCatalogArgs(registration I18NCatalogRegistration) string {
	return keyedMapArgs([]string{
		"language=" + registration.Language,
		"namespace=" + registration.Namespace,
	}, "entries.", registration.Entries)
}

// keyedMapArgs appends map-backed key/value arguments in stable key order.
func keyedMapArgs(base []string, prefix string, values map[string]string) string {
	parts := append([]string(nil), base...)

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		parts = append(parts, prefix+key+"="+values[key])
	}

	return strings.Join(parts, " ")
}

func luaValueString(value lua.LValue) string {
	switch typed := value.(type) {
	case lua.LBool:
		return strconv.FormatBool(bool(typed))
	case lua.LNumber:
		return strconv.FormatFloat(float64(typed), 'f', -1, 64)
	case lua.LString:
		return string(typed)
	case *lua.LTable:
		return luaTableString(typed)
	default:
		if value == nil || value == lua.LNil {
			return ""
		}

		return value.String()
	}
}

func luaTableString(table *lua.LTable) string {
	values := make([]string, 0, table.Len())
	table.ForEach(func(_ lua.LValue, value lua.LValue) {
		values = append(values, luaValueString(value))
	})

	return strings.Join(values, ",")
}

// LoaderModLDAPMock creates a mock nauthilus_ldap module.
func LoaderModLDAPMock(mockData *LDAPMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		config := newLDAPMockConfig(mockData)

		L.SetField(mod, definitions.LuaFnLDAPSearch, L.NewFunction(ldapSearchMock(mockData, config)))
		L.SetField(mod, definitions.LuaFnLDAPModify, L.NewFunction(ldapModifyMock(mockData, config)))
		L.SetField(mod, definitions.LuaFnLDAPEndpoint, L.NewFunction(ldapEndpointMock(mockData, config)))

		L.Push(mod)

		return 1
	}
}

type ldapMockConfig struct {
	searchResult  map[string][]string
	searchError   string
	modifyError   string
	endpointHost  string
	endpointError string
	endpointPort  int
	modifyOK      bool
}

// newLDAPMockConfig resolves LDAP mock defaults and overrides.
func newLDAPMockConfig(mockData *LDAPMock) ldapMockConfig {
	config := ldapMockConfig{
		searchResult: map[string][]string{},
		endpointHost: "localhost",
		endpointPort: 389,
		modifyOK:     true,
	}

	if mockData == nil {
		return config
	}

	if mockData.SearchResult != nil {
		config.searchResult = mockData.SearchResult
	}

	config.searchError = mockData.SearchError
	config.modifyError = mockData.ModifyError
	config.endpointError = mockData.EndpointError

	if mockData.ModifyOK != nil {
		config.modifyOK = *mockData.ModifyOK
	}

	if mockData.EndpointHost != "" {
		config.endpointHost = mockData.EndpointHost
	}

	if mockData.EndpointPort > 0 {
		config.endpointPort = mockData.EndpointPort
	}

	return config
}

// ldapSearchMock returns the LDAP search mock callback.
func ldapSearchMock(mockData *LDAPMock, config ldapMockConfig) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaFnLDAPSearch, "search"); err != nil {
			pushLuaNilAndError(L, err.Error())

			return 2
		}

		if config.searchError != "" {
			pushLuaNilAndError(L, config.searchError)

			return 2
		}

		L.Push(ldapSearchResultTable(L, config.searchResult))

		return 1
	}
}

// ldapSearchResultTable converts LDAP attributes into a Lua table.
func ldapSearchResultTable(L *lua.LState, searchResult map[string][]string) *lua.LTable {
	result := L.NewTable()
	for attrName, values := range searchResult {
		result.RawSetString(attrName, stringSliceToLuaTable(L, values))
	}

	return result
}

// ldapModifyMock returns the LDAP modify mock callback.
func ldapModifyMock(mockData *LDAPMock, config ldapMockConfig) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaFnLDAPModify, "modify"); err != nil {
			pushLuaNilAndError(L, err.Error())

			return 2
		}

		if config.modifyError != "" {
			pushLuaNilAndError(L, config.modifyError)

			return 2
		}

		if !config.modifyOK {
			pushLuaNilAndError(L, "mock ldap modify failed")

			return 2
		}

		L.Push(lua.LString("OK"))

		return 1
	}
}

// ldapEndpointMock returns the LDAP endpoint mock callback.
func ldapEndpointMock(mockData *LDAPMock, config ldapMockConfig) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaFnLDAPEndpoint, "endpoint"); err != nil {
			pushLuaEndpointError(L, err.Error())

			return 3
		}

		if config.endpointError != "" {
			pushLuaEndpointError(L, config.endpointError)

			return 3
		}

		L.Push(lua.LString(config.endpointHost))
		L.Push(lua.LNumber(config.endpointPort))
		L.Push(lua.LNil)

		return 3
	}
}

// pushLuaNilAndError pushes a nil/error tuple.
func pushLuaNilAndError(L *lua.LState, message string) {
	L.Push(lua.LNil)
	L.Push(lua.LString(message))
}

// pushLuaEndpointError pushes the LDAP endpoint nil/nil/error tuple.
func pushLuaEndpointError(L *lua.LState, message string) {
	L.Push(lua.LNil)
	L.Push(lua.LNil)
	L.Push(lua.LString(message))
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

type luaCallRecorder interface {
	RecordCall(method, args string) error
}

// withImplicitColumns fills declarative row results with deterministic column names.
func withImplicitColumns(rowsResult dbmock.Rows) dbmock.Rows {
	if len(rowsResult.Columns) > 0 || len(rowsResult.Data) == 0 {
		return rowsResult
	}

	columnCount := len(rowsResult.Data[0])

	columns := make([]string, 0, columnCount)
	for idx := range columnCount {
		columns = append(columns, fmt.Sprintf("col_%d", idx+1))
	}

	filled := dbmock.NewRows(columns...)
	for _, row := range rowsResult.Data {
		filled = filled.AddRow(row...)
	}

	return filled
}

// luaRowsResult converts mock DB rows into the Lua table shape used by db fixtures.
func luaRowsResult(L *lua.LState, result dbmock.Rows) lua.LValue {
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

	return luaResult
}

// luaDBConnectionOperation wraps connection-level exec/query calls with Lua error handling.
func luaDBConnectionOperation(
	mockData *DBMock,
	method string,
	operation func(*mockDBConn, string, []any) (lua.LValue, error),
) lua.LGFunction {
	return func(L *lua.LState) int {
		connUD := L.CheckUserData(1)
		query := strings.TrimSpace(L.CheckString(2))
		args := collectArgs(L, 3)

		if err := mockData.RecordCall(method, query); err != nil {
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

		result, err := operation(conn, query, args)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		L.Push(result)

		return 1
	}
}

// luaDBStatementOperation wraps prepared statement exec/query calls with Lua error handling.
func luaDBStatementOperation(
	mockData *DBMock,
	method string,
	operation func(*mockDBStmt, []any) (lua.LValue, error),
) lua.LGFunction {
	return func(L *lua.LState) int {
		stmtUD := L.CheckUserData(1)

		stmt, ok := stmtUD.Value.(*mockDBStmt)
		if !ok || stmt == nil || stmt.conn == nil || stmt.closed {
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid mock db statement"))

			return 2
		}

		args := collectArgs(L, 2)
		if err := mockData.RecordCall(method, stmt.query); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		result, err := operation(stmt, args)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		L.Push(result)

		return 1
	}
}

// collectArgs converts Lua arguments starting at startIndex into Go values.
func collectArgs(L *lua.LState, startIndex int) []any {
	if L.GetTop() < startIndex {
		return []any{}
	}

	args := make([]any, 0, L.GetTop()-startIndex+1)
	for i := startIndex; i <= L.GetTop(); i++ {
		args = append(args, convert.LuaValueToGo(L.Get(i)))
	}

	return args
}

type dbMockConfig struct {
	openError       string
	execError       string
	queryError      string
	declarativeMode bool
}

// newDBMockConfig resolves DB mock errors and execution mode.
func newDBMockConfig(mockData *DBMock) dbMockConfig {
	if mockData == nil {
		return dbMockConfig{}
	}

	return dbMockConfig{
		openError:       mockData.OpenError,
		execError:       mockData.ExecError,
		queryError:      mockData.QueryError,
		declarativeMode: mockData.DeclarativeMode,
	}
}

type dbMockRuntime struct {
	L             *lua.LState
	mockData      *DBMock
	dbMetatable   *lua.LTable
	stmtMetatable *lua.LTable
	config        dbMockConfig
}

// newDBMockRuntime groups DB mock state for one Lua module load.
func newDBMockRuntime(L *lua.LState, mockData *DBMock, config dbMockConfig) *dbMockRuntime {
	return &dbMockRuntime{
		L:        L,
		mockData: mockData,
		config:   config,
	}
}

// LoaderModDBMock creates a mock db module.
func LoaderModDBMock(mockData *DBMock) lua.LGFunction {
	if mockData == nil {
		mockData = &DBMock{}
	}

	config := newDBMockConfig(mockData)

	return func(L *lua.LState) int {
		runtime := newDBMockRuntime(L, mockData, config)
		registerDBMockMetatables(runtime)

		mod := L.NewTable()
		L.SetField(mod, "open", L.NewFunction(dbOpenMock(runtime)))

		L.Push(mod)

		return 1
	}
}

// registerDBMockMetatables wires connection and statement methods into Lua.
func registerDBMockMetatables(runtime *dbMockRuntime) {
	runtime.dbMetatable = runtime.L.NewTypeMetatable("db_ud_mock")
	runtime.stmtMetatable = runtime.L.NewTypeMetatable("db_stmt_ud_mock")
	runtime.L.SetField(
		runtime.dbMetatable,
		"__index",
		runtime.L.SetFuncs(runtime.L.NewTable(), dbConnectionMockMethods(runtime)),
	)
	runtime.L.SetField(
		runtime.stmtMetatable,
		"__index",
		runtime.L.SetFuncs(runtime.L.NewTable(), dbStatementMockMethods(runtime)),
	)
}

// dbConnectionMockMethods returns Lua methods available on DB connections.
func dbConnectionMockMethods(runtime *dbMockRuntime) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		luaTestMockMethodExec:  luaDBConnectionOperation(runtime.mockData, luaTestMockMethodExec, runtime.execSQL),
		luaTestMockMethodQuery: luaDBConnectionOperation(runtime.mockData, luaTestMockMethodQuery, runtime.querySQL),
		"stmt":                 dbConnectionStatementMock(runtime),
		luaTestMockMethodClose: dbConnectionCloseMock(runtime.mockData),
	}
}

// dbStatementMockMethods returns Lua methods available on prepared statements.
func dbStatementMockMethods(runtime *dbMockRuntime) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		luaTestMockMethodExec:  luaDBStatementOperation(runtime.mockData, luaTestMockMethodExec, runtime.execStmtSQL),
		luaTestMockMethodQuery: luaDBStatementOperation(runtime.mockData, luaTestMockMethodQuery, runtime.queryStmtSQL),
		luaTestMockMethodClose: dbStatementCloseMock(),
	}
}

// execSQL executes or simulates a connection-level exec call.
func (runtime *dbMockRuntime) execSQL(conn *mockDBConn, query string, args []any) (lua.LValue, error) {
	if err := validateMockDBConn(conn); err != nil {
		return lua.LNil, err
	}

	if conn.execError != "" {
		return lua.LNil, fmt.Errorf("%s", conn.execError)
	}

	result := runtime.execResult(conn, query)
	if !runtime.config.declarativeMode {
		conn.mock.ExpectExec(query, args...).WillReturnResult(result.RowsAffected, result.LastInsertID)

		execResult, errExec := conn.conn.Exec(query, args...)
		if errExec != nil {
			return lua.LNil, errExec
		}

		result = execResult
	}

	return luaDBExecResult(runtime.L, result), nil
}

// execStmtSQL executes or simulates a prepared statement exec call.
func (runtime *dbMockRuntime) execStmtSQL(stmt *mockDBStmt, args []any) (lua.LValue, error) {
	if err := validateMockDBStmt(stmt); err != nil {
		return lua.LNil, err
	}

	if stmt.conn.execError != "" {
		return lua.LNil, fmt.Errorf("%s", stmt.conn.execError)
	}

	result := runtime.execResult(stmt.conn, stmt.query)
	if runtime.config.declarativeMode {
		return luaDBExecResult(runtime.L, result), nil
	}

	stmt.prepareExp.ExpectExec(args...).WillReturnResult(result.RowsAffected, result.LastInsertID)

	execResult, errExec := stmt.stmt.Exec(args...)
	if errExec != nil {
		return lua.LNil, errExec
	}

	return luaDBExecResult(runtime.L, execResult), nil
}

// querySQL executes or simulates a connection-level query call.
func (runtime *dbMockRuntime) querySQL(conn *mockDBConn, query string, args []any) (lua.LValue, error) {
	if err := validateMockDBConn(conn); err != nil {
		return lua.LNil, err
	}

	if conn.queryError != "" {
		return lua.LNil, fmt.Errorf("%s", conn.queryError)
	}

	rowsResult := runtime.expectedRowsResult()

	result := rowsResult
	if !runtime.config.declarativeMode {
		conn.mock.ExpectQuery(query, args...).WillReturnRows(rowsResult)

		queryResult, errQuery := conn.conn.Query(query, args...)
		if errQuery != nil {
			return lua.LNil, errQuery
		}

		result = queryResult
	}

	return luaRowsResult(runtime.L, result), nil
}

// queryStmtSQL executes or simulates a prepared statement query call.
func (runtime *dbMockRuntime) queryStmtSQL(stmt *mockDBStmt, args []any) (lua.LValue, error) {
	if err := validateMockDBStmt(stmt); err != nil {
		return lua.LNil, err
	}

	if stmt.conn.queryError != "" {
		return lua.LNil, fmt.Errorf("%s", stmt.conn.queryError)
	}

	rowsResult := runtime.expectedRowsResult()

	result := rowsResult
	if !runtime.config.declarativeMode {
		stmt.prepareExp.ExpectQuery(args...).WillReturnRows(rowsResult)

		queryResult, errQuery := stmt.stmt.Query(args...)
		if errQuery != nil {
			return lua.LNil, errQuery
		}

		result = queryResult
	}

	return luaRowsResult(runtime.L, result), nil
}

// execResult derives the mock DB exec result from query defaults and matched expectations.
func (runtime *dbMockRuntime) execResult(conn *mockDBConn, query string) dbmock.ExecResult {
	result := dbmock.ExecResult{
		RowsAffected: defaultDBRowsAffected(query),
	}

	expected := runtime.mockData.LastMatchedCall()
	if expected != nil && expected.RowsAffected != nil {
		result.RowsAffected = *expected.RowsAffected
	}

	if isDBInsertQuery(query) {
		conn.lastInsert++
		result.LastInsertID = conn.lastInsert
	}

	if expected != nil && expected.LastInsertID != nil {
		result.LastInsertID = *expected.LastInsertID
	}

	return result
}

// expectedRowsResult builds the row set configured by the last matched DB expectation.
func (runtime *dbMockRuntime) expectedRowsResult() dbmock.Rows {
	rowsResult := dbmock.NewRows()

	expected := runtime.mockData.LastMatchedCall()
	if expected == nil {
		return withImplicitColumns(rowsResult)
	}

	if len(expected.Columns) > 0 {
		rowsResult = dbmock.NewRows(expected.Columns...)
	}

	return withImplicitColumns(addDBExpectedRows(rowsResult, expected.Rows))
}

// addDBExpectedRows appends copied fixture rows to a mock DB row set.
func addDBExpectedRows(rowsResult dbmock.Rows, rows [][]any) dbmock.Rows {
	for _, row := range rows {
		rowValues := make([]any, len(row))
		copy(rowValues, row)
		rowsResult = rowsResult.AddRow(rowValues...)
	}

	return rowsResult
}

// defaultDBRowsAffected returns the implicit rows-affected value for a query.
func defaultDBRowsAffected(query string) int64 {
	if strings.HasPrefix(normalizedDBQuery(query), "create ") {
		return 0
	}

	return 1
}

// isDBInsertQuery reports whether a query should advance the mock insert id.
func isDBInsertQuery(query string) bool {
	return strings.HasPrefix(normalizedDBQuery(query), "insert ")
}

// normalizedDBQuery trims and lowercases query text for mock classification.
func normalizedDBQuery(query string) string {
	return strings.ToLower(strings.TrimSpace(query))
}

// luaDBExecResult converts an exec result into the Lua table returned by fixtures.
func luaDBExecResult(L *lua.LState, result dbmock.ExecResult) lua.LValue {
	luaResult := L.NewTable()
	luaResult.RawSetString("rows_affected", lua.LNumber(result.RowsAffected))

	if result.LastInsertID > 0 {
		luaResult.RawSetString("last_insert_id", lua.LNumber(result.LastInsertID))
	}

	return luaResult
}

// validateMockDBConn checks connection state before DB operations.
func validateMockDBConn(conn *mockDBConn) error {
	if conn == nil {
		return fmt.Errorf("invalid mock db connection")
	}

	if conn.closed {
		return fmt.Errorf("mock db connection is closed")
	}

	return nil
}

// validateMockDBStmt checks statement state before DB operations.
func validateMockDBStmt(stmt *mockDBStmt) error {
	if stmt == nil || stmt.conn == nil {
		return fmt.Errorf("invalid mock db statement")
	}

	if stmt.closed {
		return fmt.Errorf("invalid mock db statement")
	}

	return nil
}

// dbConnectionStatementMock prepares a mock statement and returns its userdata.
func dbConnectionStatementMock(runtime *dbMockRuntime) lua.LGFunction {
	return func(L *lua.LState) int {
		connUD := L.CheckUserData(1)
		query := strings.TrimSpace(L.CheckString(2))

		if err := runtime.mockData.RecordCall("stmt", query); err != nil {
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

		return pushDBMockStatement(runtime, conn, query)
	}
}

// pushDBMockStatement pushes prepared-statement userdata for a valid connection.
func pushDBMockStatement(runtime *dbMockRuntime, conn *mockDBConn, query string) int {
	stmt := &mockDBStmt{
		conn:   conn,
		query:  query,
		closed: false,
	}

	if !runtime.config.declarativeMode {
		prepareExp := conn.mock.ExpectPrepare(query)

		preparedStmt, errPrepare := conn.conn.Prepare(query)
		if errPrepare != nil {
			runtime.L.Push(lua.LNil)
			runtime.L.Push(lua.LString(errPrepare.Error()))

			return 2
		}

		stmt.prepareExp = prepareExp
		stmt.stmt = preparedStmt
	}

	stmtUD := runtime.L.NewUserData()
	stmtUD.Value = stmt
	runtime.L.SetMetatable(stmtUD, runtime.stmtMetatable)
	runtime.L.Push(stmtUD)

	return 1
}

// dbConnectionCloseMock marks a mock DB connection as closed.
func dbConnectionCloseMock(mockData *DBMock) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(luaTestMockMethodClose, ""); err != nil {
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
	}
}

// dbStatementCloseMock marks a mock prepared statement as closed.
func dbStatementCloseMock() lua.LGFunction {
	return func(L *lua.LState) int {
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
	}
}

// dbOpenMock opens a mock DB connection and returns its userdata.
func dbOpenMock(runtime *dbMockRuntime) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := runtime.mockData.RecordCall("open", ""); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		_ = L.CheckString(1) // driver

		_ = L.CheckString(2) // connection string
		if L.GetTop() > 2 {
			_ = L.CheckTable(3)
		}

		if runtime.config.openError != "" {
			L.Push(lua.LNil)
			L.Push(lua.LString(runtime.config.openError))

			return 2
		}

		conn := newMockDBConn(runtime.config)
		ud := L.NewUserData()
		ud.Value = conn
		L.SetMetatable(ud, runtime.dbMetatable)
		L.Push(ud)

		return 1
	}
}

// newMockDBConn creates a DB connection backed by the in-memory expectation mock.
func newMockDBConn(config dbMockConfig) *mockDBConn {
	internalMock := dbmock.New()

	return &mockDBConn{
		mock:       internalMock,
		conn:       internalMock.Conn(),
		lastInsert: 0,
		execError:  config.execError,
		queryError: config.queryError,
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

// backendResultBoolAccessor returns a Lua getter/setter for boolean backend-result fields.
func backendResultBoolAccessor(
	mockData *BackendResultMock,
	method string,
	get func(*backendResultMockValue) bool,
	set func(*backendResultMockValue, bool),
) lua.LGFunction {
	return backendResultAccessor(mockData, method, get, set, (*lua.LState).CheckBool, pushLuaBool)
}

// backendResultStringAccessor returns a Lua getter/setter for string backend-result fields.
func backendResultStringAccessor(
	mockData *BackendResultMock,
	method string,
	get func(*backendResultMockValue) string,
	set func(*backendResultMockValue, string),
) lua.LGFunction {
	return backendResultAccessor(mockData, method, get, set, (*lua.LState).CheckString, pushLuaString)
}

// backendResultAccessor shares Lua getter/setter handling for scalar backend-result fields.
func backendResultAccessor[T any](
	mockData *BackendResultMock,
	method string,
	get func(*backendResultMockValue) T,
	set func(*backendResultMockValue, T),
	check func(*lua.LState, int) T,
	push func(*lua.LState, T),
) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(method, ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		value := checkBackendResultMockValue(L)
		if value == nil {
			return 0
		}

		if L.GetTop() == 2 {
			set(value, check(L, 2))

			return 0
		}

		push(L, get(value))

		return 1
	}
}

// pushLuaBool pushes a Go bool as a Lua boolean.
func pushLuaBool(L *lua.LState, value bool) {
	L.Push(lua.LBool(value))
}

// pushLuaString pushes a Go string as a Lua string.
func pushLuaString(L *lua.LState, value string) {
	L.Push(lua.LString(value))
}

// checkBackendResultMockValue reads the backend-result userdata expected by mock methods.
func checkBackendResultMockValue(L *lua.LState) *backendResultMockValue {
	userData := L.CheckUserData(1)

	value, _ := userData.Value.(*backendResultMockValue)
	if value == nil {
		L.ArgError(1, "backend_result expected")

		return nil
	}

	return value
}

// LoaderModBackendMock creates a mock nauthilus_backend module.
func LoaderModBackendMock(mockData *BackendMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		if mockData == nil {
			mockData = &BackendMock{}
		}

		registerBackendServerMetatable(L)
		L.SetField(mod, definitions.LuaFnGetBackendServers, L.NewFunction(backendServersMock(mockData)))
		L.SetField(mod, definitions.LuaFnSelectBackendServer, L.NewFunction(backendSelectServerMock(mockData)))
		L.SetField(mod, definitions.LuaFnApplyBackendResult, L.NewFunction(backendApplyResultMock(mockData)))
		L.SetField(mod, definitions.LuaFnRemoveFromBackendResult, L.NewFunction(backendRemoveResultMock(mockData)))

		L.Push(mod)

		return 1
	}
}

// registerBackendServerMetatable registers backend server field accessors.
func registerBackendServerMetatable(L *lua.LState) {
	mt := L.NewTypeMetatable(definitions.LuaBackendServerTypeName)
	L.SetField(mt, "__index", L.NewFunction(func(L *lua.LState) int {
		userData := L.CheckUserData(1)
		field := L.CheckString(2)

		server, ok := userData.Value.(*BackendServerMock)
		if !ok || server == nil {
			return 0
		}

		value := backendServerFieldValue(server, field)
		if value == lua.LNil {
			return 0
		}

		L.Push(value)

		return 1
	}))
}

// backendServerFieldValue returns a Lua value for one backend server field.
func backendServerFieldValue(server *BackendServerMock, field string) lua.LValue {
	switch field {
	case "protocol":
		return lua.LString(server.Protocol)
	case "host":
		return lua.LString(server.Host)
	case "port":
		return lua.LNumber(server.Port)
	case "request_uri":
		return lua.LString(server.RequestURI)
	case "test_username":
		return lua.LString(server.TestUsername)
	case "test_password":
		return lua.LString(server.TestPassword)
	case "haproxy_v2":
		return lua.LBool(server.HAProxyV2)
	case "tls":
		return lua.LBool(server.TLS)
	case "tls_skip_verify":
		return lua.LBool(server.TLSSkipVerify)
	case "deep_check":
		return lua.LBool(server.DeepCheck)
	default:
		return lua.LNil
	}
}

// backendServersMock returns the get_backend_servers mock callback.
func backendServersMock(mockData *BackendMock) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaFnGetBackendServers, ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		L.Push(backendServersTable(L, mockData.BackendServers))

		return 1
	}
}

// backendServersTable converts backend server fixtures into Lua userdata.
func backendServersTable(L *lua.LState, servers []BackendServerMock) *lua.LTable {
	result := L.NewTable()

	for index := range servers {
		server := servers[index]
		ud := L.NewUserData()
		ud.Value = &server
		L.SetMetatable(ud, L.GetTypeMetatable(definitions.LuaBackendServerTypeName))
		result.Append(ud)
	}

	return result
}

// backendSelectServerMock returns the select_backend_server mock callback.
func backendSelectServerMock(mockData *BackendMock) lua.LGFunction {
	return func(L *lua.LState) int {
		host := L.CheckString(1)

		port := L.CheckInt(2)
		if err := mockData.RecordCall(definitions.LuaFnSelectBackendServer, host); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		mockData.RuntimeSelectedHost = host
		mockData.RuntimeSelectedPort = &port

		return 0
	}
}

// backendApplyResultMock returns the apply_backend_result mock callback.
func backendApplyResultMock(mockData *BackendMock) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaFnApplyBackendResult, ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		if result := backendResultMapFromLuaValue(L.CheckAny(1)); result != nil {
			mockData.RuntimeAppliedBackendResult = result
		}

		return 0
	}
}

// backendResultMapFromLuaValue converts userdata or table backend results to Go maps.
func backendResultMapFromLuaValue(value lua.LValue) map[string]any {
	switch typed := value.(type) {
	case *lua.LUserData:
		return backendResultMapFromUserData(typed)
	case *lua.LTable:
		return stringMapFromLuaTable(typed)
	default:
		return nil
	}
}

// backendResultMapFromUserData converts backend-result userdata into a Go map.
func backendResultMapFromUserData(userData *lua.LUserData) map[string]any {
	br, ok := userData.Value.(*backendResultMockValue)
	if !ok || br == nil {
		return nil
	}

	out := map[string]any{
		definitions.LuaBackendResultAuthenticated:     br.Authenticated,
		definitions.LuaBackendResultUserFound:         br.UserFound,
		definitions.LuaBackendResultAccountField:      br.AccountField,
		definitions.LuaBackendResultTOTPSecretField:   br.TOTPSecretField,
		definitions.LuaBackendResultTOTPRecoveryField: br.TOTPRecoveryField,
		luaTestMockUniqueUserID:                       br.UniqueUserIDField,
		definitions.LuaBackendResultDisplayNameField:  br.DisplayNameField,
	}

	if br.Attributes != nil {
		out[definitions.LuaBackendResultAttributes] = br.Attributes
	}

	if len(br.WebAuthnCredentials) > 0 {
		out[definitions.LuaBackendResultWebAuthnCredentials] = br.WebAuthnCredentials
	}

	return out
}

// stringMapFromLuaTable converts a Lua table into a string-keyed Go map.
func stringMapFromLuaTable(table *lua.LTable) map[string]any {
	converted := convert.LuaValueToGo(table)

	asMap, ok := converted.(map[any]any)
	if !ok {
		return nil
	}

	out := make(map[string]any, len(asMap))
	for key, val := range asMap {
		out[fmt.Sprintf("%v", key)] = val
	}

	return out
}

// backendRemoveResultMock returns the remove_from_backend_result mock callback.
func backendRemoveResultMock(mockData *BackendMock) lua.LGFunction {
	return func(L *lua.LState) int {
		tbl := L.CheckTable(1)
		if err := mockData.RecordCall(definitions.LuaFnRemoveFromBackendResult, ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		mockData.RuntimeRemovedFromAttributes = luaTableValuesAsStrings(tbl)

		return 0
	}
}

// luaTableValuesAsStrings returns table values as strings.
func luaTableValuesAsStrings(tbl *lua.LTable) []string {
	values := make([]string, 0)

	tbl.ForEach(func(_, value lua.LValue) {
		values = append(values, value.String())
	})

	return values
}

// LoaderModBackendResultMock creates a mock nauthilus_backend_result module.
func LoaderModBackendResultMock(mockData *BackendResultMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		if mockData == nil {
			mockData = &BackendResultMock{}
		}

		mt := L.NewTypeMetatable(definitions.LuaBackendResultTypeName)
		L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), backendResultIndexFuncs(mockData)))
		L.SetField(mt, "__newindex", L.NewFunction(backendResultNewIndexMock()))
		L.SetField(mod, "new", L.NewFunction(backendResultNewMock(mockData)))

		L.Push(mod)

		return 1
	}
}

// backendResultIndexFuncs returns backend-result getter/setter accessors.
func backendResultIndexFuncs(mockData *BackendResultMock) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		definitions.LuaBackendResultAuthenticated: backendResultBoolAccessor(
			mockData,
			definitions.LuaBackendResultAuthenticated,
			func(value *backendResultMockValue) bool { return value.Authenticated },
			func(value *backendResultMockValue, fieldValue bool) { value.Authenticated = fieldValue },
		),
		definitions.LuaBackendResultUserFound: backendResultBoolAccessor(
			mockData,
			definitions.LuaBackendResultUserFound,
			func(value *backendResultMockValue) bool { return value.UserFound },
			func(value *backendResultMockValue, fieldValue bool) { value.UserFound = fieldValue },
		),
		definitions.LuaBackendResultAccountField: backendResultStringAccessor(
			mockData,
			definitions.LuaBackendResultAccountField,
			func(value *backendResultMockValue) string { return value.AccountField },
			func(value *backendResultMockValue, fieldValue string) { value.AccountField = fieldValue },
		),
		definitions.LuaBackendResultTOTPSecretField: backendResultStringAccessor(
			mockData,
			definitions.LuaBackendResultTOTPSecretField,
			func(value *backendResultMockValue) string { return value.TOTPSecretField },
			func(value *backendResultMockValue, fieldValue string) { value.TOTPSecretField = fieldValue },
		),
		definitions.LuaBackendResultTOTPRecoveryField: backendResultStringAccessor(
			mockData,
			definitions.LuaBackendResultTOTPRecoveryField,
			func(value *backendResultMockValue) string { return value.TOTPRecoveryField },
			func(value *backendResultMockValue, fieldValue string) { value.TOTPRecoveryField = fieldValue },
		),
		definitions.LuaBAckendResultUniqueUserIDField: backendResultStringAccessor(
			mockData,
			definitions.LuaBAckendResultUniqueUserIDField,
			func(value *backendResultMockValue) string { return value.UniqueUserIDField },
			func(value *backendResultMockValue, fieldValue string) { value.UniqueUserIDField = fieldValue },
		),
		definitions.LuaBackendResultDisplayNameField: backendResultStringAccessor(
			mockData,
			definitions.LuaBackendResultDisplayNameField,
			func(value *backendResultMockValue) string { return value.DisplayNameField },
			func(value *backendResultMockValue, fieldValue string) { value.DisplayNameField = fieldValue },
		),
		definitions.LuaBackendResultWebAuthnCredentials: backendResultWebAuthnAccessor(mockData),
		definitions.LuaBackendResultAttributes:          backendResultAttributesAccessor(mockData),
	}
}

// backendResultWebAuthnAccessor returns the WebAuthn credentials accessor.
func backendResultWebAuthnAccessor(mockData *BackendResultMock) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaBackendResultWebAuthnCredentials, ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		value := checkBackendResultMockValue(L)
		if value == nil {
			return 0
		}

		if L.GetTop() == 2 {
			value.WebAuthnCredentials = luaTableValuesAsStrings(L.CheckTable(2))

			return 0
		}

		L.Push(stringSliceToLuaTable(L, value.WebAuthnCredentials))

		return 1
	}
}

// backendResultAttributesAccessor returns the attributes accessor.
func backendResultAttributesAccessor(mockData *BackendResultMock) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(definitions.LuaBackendResultAttributes, ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		value := checkBackendResultMockValue(L)
		if value == nil {
			return 0
		}

		if L.GetTop() == 2 {
			value.Attributes = luaTableToAnyMap(L.CheckTable(2))

			return 0
		}

		L.Push(convert.GoToLuaValue(L, value.Attributes))

		return 1
	}
}

// luaTableToAnyMap converts a Lua table into a Go map.
func luaTableToAnyMap(table *lua.LTable) map[any]any {
	attrs, ok := convert.LuaValueToGo(table).(map[any]any)
	if !ok {
		return map[any]any{}
	}

	return attrs
}

// backendResultNewIndexMock returns the backend-result __newindex callback.
func backendResultNewIndexMock() lua.LGFunction {
	return func(L *lua.LState) int {
		userData := L.CheckUserData(1)
		field := L.CheckString(2)
		value := L.CheckAny(3)

		br, ok := userData.Value.(*backendResultMockValue)
		if !ok || br == nil {
			L.ArgError(1, "backend_result expected")

			return 0
		}

		setBackendResultField(br, field, value)

		return 0
	}
}

// setBackendResultField updates one backend-result mock field.
func setBackendResultField(br *backendResultMockValue, field string, value lua.LValue) {
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
}

// backendResultNewMock returns the backend-result constructor callback.
func backendResultNewMock(mockData *BackendResultMock) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall("new", ""); err != nil {
			L.RaiseError("%s", err.Error())

			return 0
		}

		userData := L.NewUserData()
		userData.Value = newBackendResultMockValue(mockData)
		L.SetMetatable(userData, L.GetTypeMetatable(definitions.LuaBackendResultTypeName))
		L.Push(userData)

		return 1
	}
}

// newBackendResultMockValue builds the initial backend-result userdata value.
func newBackendResultMockValue(mockData *BackendResultMock) *backendResultMockValue {
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

	for key, value := range mockData.Attributes {
		result.Attributes[key] = value
	}

	return result
}

// LoaderModHTTPRequestMock creates a mock nauthilus_http_request module.
func LoaderModHTTPRequestMock(mockData *HTTPRequestMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		config := newHTTPRequestMockConfig(mockData)

		registerHTTPRequestFields(L, mod, config)
		registerHTTPRequestGetters(L, mod, mockData, config)

		L.Push(mod)

		return 1
	}
}

type httpRequestMockConfig struct {
	headers map[string]string
	method  string
	path    string
	body    string
}

// newHTTPRequestMockConfig resolves HTTP request mock defaults.
func newHTTPRequestMockConfig(mockData *HTTPRequestMock) httpRequestMockConfig {
	config := httpRequestMockConfig{method: "GET", path: "/"}
	if mockData == nil {
		return config
	}

	config.method = mockData.Method
	config.path = mockData.Path
	config.headers = mockData.Headers
	config.body = mockData.Body

	return config
}

// registerHTTPRequestFields registers direct request fields.
func registerHTTPRequestFields(L *lua.LState, mod *lua.LTable, config httpRequestMockConfig) {
	L.SetField(mod, "method", lua.LString(config.method))
	L.SetField(mod, "path", lua.LString(config.path))
	L.SetField(mod, "body", lua.LString(config.body))

	if config.headers != nil {
		L.SetField(mod, "headers", stringMapToLuaTable(L, config.headers))
	}
}

// registerHTTPRequestGetters registers request getter functions.
func registerHTTPRequestGetters(L *lua.LState, mod *lua.LTable, mockData *HTTPRequestMock, config httpRequestMockConfig) {
	L.SetField(mod, "get_http_method", L.NewFunction(httpRequestStringGetter(mockData, "get_http_method", config.method)))
	L.SetField(mod, "get_http_path", L.NewFunction(httpRequestStringGetter(mockData, "get_http_path", config.path)))
	L.SetField(mod, "get_http_body", L.NewFunction(httpRequestStringGetter(mockData, "get_http_body", config.body)))
	L.SetField(mod, definitions.LuaFnGetHTTPQueryParam, L.NewFunction(httpRequestQueryParamGetter(mockData, config.path)))
	L.SetField(mod, "get_http_header", L.NewFunction(httpRequestHeaderGetter(mockData, "get_http_header", config.headers, false)))
	L.SetField(mod, definitions.LuaFnGetHTTPRequestHeader, L.NewFunction(httpRequestHeaderGetter(mockData, definitions.LuaFnGetHTTPRequestHeader, config.headers, true)))
}

// httpRequestStringGetter returns a static string getter callback.
func httpRequestStringGetter(mockData *HTTPRequestMock, methodName string, value string) lua.LGFunction {
	return func(L *lua.LState) int {
		if err := mockData.RecordCall(methodName, ""); err != nil {
			L.Push(lua.LNil)

			return 1
		}

		L.Push(lua.LString(value))

		return 1
	}
}

// httpRequestQueryParamGetter returns a query parameter getter callback.
func httpRequestQueryParamGetter(mockData *HTTPRequestMock, path string) lua.LGFunction {
	return func(L *lua.LState) int {
		param := L.CheckString(1)
		if err := mockData.RecordCall(definitions.LuaFnGetHTTPQueryParam, param); err != nil {
			L.Push(lua.LNil)

			return 1
		}

		L.Push(luaOptionalString(requestQueryParam(path, param)))

		return 1
	}
}

// requestQueryParam returns the selected query parameter or an empty string.
func requestQueryParam(path string, param string) string {
	parsed, err := url.ParseRequestURI(path)
	if err != nil || parsed == nil {
		return ""
	}

	return parsed.Query().Get(param)
}

// httpRequestHeaderGetter returns a header getter callback.
func httpRequestHeaderGetter(mockData *HTTPRequestMock, methodName string, headers map[string]string, tableResult bool) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		if err := mockData.RecordCall(methodName, key); err != nil {
			L.Push(lua.LNil)

			return 1
		}

		value, ok := headers[key]
		pushHTTPRequestHeaderValue(L, value, ok, tableResult)

		return 1
	}
}

// pushHTTPRequestHeaderValue pushes a scalar or table header result.
func pushHTTPRequestHeaderValue(L *lua.LState, value string, found bool, tableResult bool) {
	if !found {
		L.Push(lua.LNil)

		return
	}

	if tableResult {
		result := L.NewTable()
		result.RawSetInt(1, lua.LString(value))
		L.Push(result)

		return
	}

	L.Push(lua.LString(value))
}

// luaOptionalString returns nil for empty strings and a Lua string otherwise.
func luaOptionalString(value string) lua.LValue {
	if value == "" {
		return lua.LNil
	}

	return lua.LString(value)
}

// stringMapToLuaTable converts a string map into a Lua table.
func stringMapToLuaTable(L *lua.LState, values map[string]string) *lua.LTable {
	result := L.NewTable()
	for key, value := range values {
		L.SetField(result, key, lua.LString(value))
	}

	return result
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

		L.SetField(mod, "is_enabled", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("is_enabled", "")

			L.Push(lua.LBool(false))

			return 1
		}))

		L.SetField(mod, "tracer", L.NewFunction(func(L *lua.LState) int {
			_ = L.OptString(1, "")
			_ = mockData.RecordCall("tracer", "")

			L.Push(newOpenTelemetryMockTracer(L, mockData))

			return 1
		}))

		L.SetField(mod, "default_tracer", L.NewFunction(func(L *lua.LState) int {
			_ = mockData.RecordCall("default_tracer", "")

			L.Push(newOpenTelemetryMockTracer(L, mockData))

			return 1
		}))

		L.Push(mod)

		return 1
	}
}

// newOpenTelemetryMockSpan creates a mock span table.
func newOpenTelemetryMockSpan(L *lua.LState, mockData *OpenTelemetryMock) *lua.LTable {
	span := L.NewTable()

	for _, method := range []string{"set_attributes", "record_error", "set_status", "finish"} {
		methodName := method
		L.SetField(span, methodName, L.NewFunction(func(_ *lua.LState) int {
			_ = mockData.RecordCall(methodName, "")

			return 0
		}))
	}

	return span
}

// newOpenTelemetryMockTracer creates a mock tracer table.
func newOpenTelemetryMockTracer(L *lua.LState, mockData *OpenTelemetryMock) *lua.LTable {
	tracer := L.NewTable()
	L.SetField(tracer, "start_span", L.NewFunction(func(L *lua.LState) int {
		_ = mockData.RecordCall("start_span", "")
		L.Push(newOpenTelemetryMockSpan(L, mockData))

		return 1
	}))
	L.SetField(tracer, "with_span", L.NewFunction(func(L *lua.LState) int {
		return callOpenTelemetryWithSpan(L, mockData)
	}))

	return tracer
}

// callOpenTelemetryWithSpan executes a callback with a mock span.
func callOpenTelemetryWithSpan(L *lua.LState, mockData *OpenTelemetryMock) int {
	name := L.OptString(2, "")
	callback := L.CheckFunction(3)
	_ = mockData.RecordCall("with_span", name)

	topBefore := L.GetTop()
	if err := L.CallByParam(lua.P{
		Fn:      callback,
		NRet:    lua.MultRet,
		Protect: true,
	}, newOpenTelemetryMockSpan(L, mockData)); err != nil {
		L.RaiseError("%s", err.Error())

		return 0
	}

	return L.GetTop() - topBefore
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
			return L.NewFunction(func(_ *lua.LState) int {
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
		L.SetField(mod, "set_gauge", noop("set_gauge"))

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
	return loaderMockModule(
		luaMockModuleField{name: definitions.LuaFnGetCountryName, callback: miscCountryNameMock(mockData)},
		luaMockModuleField{name: definitions.LuaFnWaitRandom, callback: miscWaitRandomMock(mockData)},
		luaMockModuleField{name: definitions.LuaFnScopedIP, callback: miscScopedIPMock(mockData)},
	)
}

// miscCountryNameMock returns the get_country_name mock callback.
func miscCountryNameMock(mockData *MiscMock) lua.LGFunction {
	return func(L *lua.LState) int {
		isoCode := L.CheckString(1)
		if err := mockData.RecordCall(definitions.LuaFnGetCountryName, isoCode); err != nil {
			L.Push(lua.LString("Unknown"))
			L.Push(lua.LString(err.Error()))

			return 2
		}

		L.Push(lua.LString("MockCountry"))
		L.Push(lua.LNil)

		return 2
	}
}

// miscWaitRandomMock returns the wait_random mock callback.
func miscWaitRandomMock(mockData *MiscMock) lua.LGFunction {
	return func(L *lua.LState) int {
		minValue := L.CheckInt(1)

		maxValue := L.CheckInt(2)
		if err := mockData.RecordCall(definitions.LuaFnWaitRandom, fmt.Sprintf("%d:%d", minValue, maxValue)); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		if minValue >= maxValue {
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid wait range"))

			return 2
		}

		L.Push(lua.LNumber(minValue))
		L.Push(lua.LNil)

		return 2
	}
}

// miscScopedIPMock returns the scoped_ip mock callback.
func miscScopedIPMock(mockData *MiscMock) lua.LGFunction {
	return func(L *lua.LState) int {
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
	}
}

// LoaderModPasswordMock creates a mock nauthilus_password module.
func LoaderModPasswordMock(mockData *PasswordMock) lua.LGFunction {
	return loaderMockModule(
		luaMockModuleField{name: definitions.LuaFnComparePasswords, callback: passwordCompareMock(mockData)},
		luaMockModuleField{name: definitions.LuaFnCheckPasswordPolicy, callback: passwordPolicyMock(mockData)},
		luaMockModuleField{name: definitions.LuaFnGeneratePasswordHash, callback: passwordHashMock(mockData)},
	)
}

// passwordCompareMock returns the compare_passwords mock callback.
func passwordCompareMock(mockData *PasswordMock) lua.LGFunction {
	return func(L *lua.LState) int {
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
	}
}

// passwordPolicyMock returns the check_password_policy mock callback.
func passwordPolicyMock(mockData *PasswordMock) lua.LGFunction {
	return func(L *lua.LState) int {
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
	}
}

// passwordHashMock returns the generate_password_hash mock callback.
func passwordHashMock(mockData *PasswordMock) lua.LGFunction {
	return func(L *lua.LState) int {
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

		L.SetField(mod, definitions.LuaFnSoftWhitelistSet, L.NewFunction(softWhitelistSetMock(mockData, entries)))
		L.SetField(mod, definitions.LuaFnSoftWhitelistGet, L.NewFunction(softWhitelistGetMock(mockData, entries)))
		L.SetField(mod, definitions.LuaFnSoftWhitelistDelete, L.NewFunction(softWhitelistDeleteMock(mockData, entries)))

		L.Push(mod)

		return 1
	}
}

// softWhitelistSetMock returns the soft-whitelist set callback.
func softWhitelistSetMock(mockData *SoftWhitelistMock, entries map[string][]string) lua.LGFunction {
	return softWhitelistMutationMock(
		mockData,
		entries,
		definitions.LuaFnSoftWhitelistSet,
		func(current []string, network string) []string {
			return append(current, network)
		},
	)
}

// softWhitelistGetMock returns the soft-whitelist get callback.
func softWhitelistGetMock(mockData *SoftWhitelistMock, entries map[string][]string) lua.LGFunction {
	return func(L *lua.LState) int {
		username := L.CheckString(1)

		environmentName := L.CheckString(2)
		if err := mockData.RecordCall(definitions.LuaFnSoftWhitelistGet, username+":"+environmentName); err != nil {
			L.Push(L.NewTable())
			L.Push(lua.LString(err.Error()))

			return 2
		}

		L.Push(stringSliceToLuaTable(L, entries[softWhitelistEntryKey(environmentName, username)]))
		L.Push(lua.LNil)

		return 2
	}
}

// softWhitelistDeleteMock returns the soft-whitelist delete callback.
func softWhitelistDeleteMock(mockData *SoftWhitelistMock, entries map[string][]string) lua.LGFunction {
	return softWhitelistMutationMock(mockData, entries, definitions.LuaFnSoftWhitelistDelete, removeString)
}

// softWhitelistMutationMock applies a set/delete mutation and returns the common Lua response.
func softWhitelistMutationMock(
	mockData *SoftWhitelistMock,
	entries map[string][]string,
	functionName string,
	mutate softWhitelistMutation,
) lua.LGFunction {
	return func(L *lua.LState) int {
		username := L.CheckString(1)
		network := L.CheckString(2)

		environmentName := L.CheckString(3)
		if err := mockData.RecordCall(functionName, username+":"+environmentName); err != nil {
			L.Push(lua.LString(""))
			L.Push(lua.LString(err.Error()))

			return 2
		}

		key := softWhitelistEntryKey(environmentName, username)
		entries[key] = mutate(entries[key], network)

		pushLuaStringAndNil(L, "OK")

		return 2
	}
}

// softWhitelistEntryKey returns the internal key for an environment/user pair.
func softWhitelistEntryKey(environmentName, username string) string {
	return environmentName + ":" + username
}

// stringSliceToLuaTable converts strings into a Lua array table.
func stringSliceToLuaTable(L *lua.LState, values []string) *lua.LTable {
	result := L.NewTable()
	for i, value := range values {
		result.RawSetInt(i+1, lua.LString(value))
	}

	return result
}

// removeString returns values without the selected entry.
func removeString(values []string, remove string) []string {
	next := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			next = append(next, value)
		}
	}

	return next
}

// pushLuaStringAndNil pushes a successful string result tuple.
func pushLuaStringAndNil(L *lua.LState, value string) {
	L.Push(lua.LString(value))
	L.Push(lua.LNil)
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

		L.SetField(mod, "getenv", L.NewFunction(utilGetenvMock(mockData, envs)))
		L.SetField(mod, "log", L.NewFunction(utilLogMock(mockData)))
		registerUtilLogWrappers(L, mod, mockData)
		L.SetField(mod, "get_redis_key", L.NewFunction(utilRedisKeyMock(mockData)))
		L.SetField(mod, "if_error_raise", L.NewFunction(utilIfErrorRaiseMock(mockData)))
		L.SetField(mod, "print_result", L.NewFunction(utilPrintResultMock(mockData)))
		L.SetField(mod, "is_table", L.NewFunction(utilIsTableMock(mockData)))
		L.SetField(mod, "table_length", L.NewFunction(utilTableLengthMock(mockData)))
		L.SetField(mod, "is_string", L.NewFunction(utilIsStringMock(mockData)))

		L.Push(mod)

		return 1
	}
}

// utilGetenvMock returns the getenv mock callback.
func utilGetenvMock(mockData *UtilMock, envs map[string]string) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		defaultVal := L.OptString(2, "")
		_ = mockData.RecordCall("getenv", name)

		if value, ok := envs[name]; ok {
			L.Push(lua.LString(value))

			return 1
		}

		L.Push(lua.LString(defaultVal))

		return 1
	}
}

// utilLogMock returns the generic log mock callback.
func utilLogMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		level := L.OptString(2, "")
		_ = mockData.RecordCall("log", level)

		return 0
	}
}

// registerUtilLogWrappers installs level-specific log wrappers.
func registerUtilLogWrappers(L *lua.LState, mod *lua.LTable, mockData *UtilMock) {
	wrappers := []struct {
		name           string
		level          string
		hasErrorString bool
	}{
		{"log_debug", "debug", false},
		{"log_info", "info", false},
		{"log_notice", "notice", false},
		{"log_warn", "warn", false},
		{"log_error", "error", true},
	}

	for _, wrapper := range wrappers {
		wrapper := wrapper
		L.SetField(mod, wrapper.name, L.NewFunction(utilLogWrapperMock(mockData, wrapper.name, wrapper.level, wrapper.hasErrorString)))
	}
}

// utilLogWrapperMock returns a level-specific log mock callback.
func utilLogWrapperMock(mockData *UtilMock, name, level string, hasErrorString bool) lua.LGFunction {
	return func(L *lua.LState) int {
		arg := level
		if hasErrorString {
			arg = L.OptString(3, "")
		}

		_ = mockData.RecordCall(name, arg)

		return 0
	}
}

// utilRedisKeyMock returns the get_redis_key mock callback.
func utilRedisKeyMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		request := L.CheckAny(1)
		key := L.CheckString(2)
		_ = mockData.RecordCall("get_redis_key", key)

		L.Push(lua.LString(redisKeyPrefix(request) + key))

		return 1
	}
}

// redisKeyPrefix extracts the Redis key prefix from a Lua request table.
func redisKeyPrefix(request lua.LValue) string {
	tbl, ok := request.(*lua.LTable)
	if !ok {
		return ""
	}

	raw := tbl.RawGetString("redis_prefix")
	if raw.Type() != lua.LTString {
		return ""
	}

	return raw.String()
}

// utilIfErrorRaiseMock returns the if_error_raise mock callback.
func utilIfErrorRaiseMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		errValue := L.CheckAny(1)
		_ = mockData.RecordCall("if_error_raise", errValue.String())

		if errValue.Type() != lua.LTNil {
			L.RaiseError("%s", errValue.String())
		}

		return 0
	}
}

// utilPrintResultMock returns the print_result mock callback.
func utilPrintResultMock(mockData *UtilMock) lua.LGFunction {
	return func(_ *lua.LState) int {
		_ = mockData.RecordCall("print_result", "")

		return 0
	}
}

// utilIsTableMock returns the is_table mock callback.
func utilIsTableMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		_ = mockData.RecordCall("is_table", "")
		_, ok := L.CheckAny(1).(*lua.LTable)
		L.Push(lua.LBool(ok))

		return 1
	}
}

// utilTableLengthMock returns the table_length mock callback.
func utilTableLengthMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		_ = mockData.RecordCall("table_length", "")

		L.Push(lua.LNumber(luaTableLength(L.CheckTable(1))))

		return 1
	}
}

// luaTableLength counts entries in a Lua table.
func luaTableLength(tbl *lua.LTable) int {
	length := 0

	tbl.ForEach(func(_ lua.LValue, _ lua.LValue) {
		length++
	})

	return length
}

// utilIsStringMock returns the is_string mock callback.
func utilIsStringMock(mockData *UtilMock) lua.LGFunction {
	return func(L *lua.LState) int {
		_ = mockData.RecordCall("is_string", "")

		L.Push(lua.LBool(L.CheckAny(1).Type() == lua.LTString))

		return 1
	}
}

// LoaderModCacheMock creates a mock nauthilus_cache module.
func LoaderModCacheMock(mockData *CacheMock) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		cache := cacheEntriesForMock(mockData)

		registerCacheMockFunctions(L, mod, mockData, cache)

		L.Push(mod)

		return 1
	}
}

// cacheEntriesForMock returns the mutable cache map used by cache callbacks.
func cacheEntriesForMock(mockData *CacheMock) map[string]any {
	if mockData == nil {
		return map[string]any{}
	}

	if mockData.Entries == nil {
		mockData.Entries = map[string]any{}
	}

	return mockData.Entries
}

// registerCacheMockFunctions registers cache module functions.
func registerCacheMockFunctions(L *lua.LState, mod *lua.LTable, mockData *CacheMock, cache map[string]any) {
	L.SetField(mod, "cache_set", L.NewFunction(cacheSetMock(mockData, cache)))
	L.SetField(mod, "cache_get", L.NewFunction(cacheGetMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCacheDelete, L.NewFunction(cacheDeleteMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCacheExists, L.NewFunction(cacheExistsMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCacheUpdate, L.NewFunction(cacheUpdateMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCacheKeys, L.NewFunction(cacheKeysMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCacheSize, L.NewFunction(cacheSizeMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCacheFlush, L.NewFunction(cacheFlushMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCachePush, L.NewFunction(cachePushMock(mockData, cache)))
	L.SetField(mod, definitions.LuaFnCachePopAll, L.NewFunction(cachePopAllMock(mockData, cache)))
}

// cacheSetMock returns the cache_set mock callback.
func cacheSetMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		value := convert.LuaValueToGo(L.CheckAny(2))
		_ = mockData.RecordCall(definitions.LuaFnCacheSet, key)
		cache[key] = value

		return 0
	}
}

// cacheGetMock returns the cache_get mock callback.
func cacheGetMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		_ = mockData.RecordCall(definitions.LuaFnCacheGet, key)
		L.Push(cacheValueToLua(L, cache[key]))

		return 1
	}
}

// cacheDeleteMock returns the cache delete mock callback.
func cacheDeleteMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		_ = mockData.RecordCall(definitions.LuaFnCacheDelete, key)
		_, existed := cache[key]
		delete(cache, key)
		L.Push(lua.LBool(existed))

		return 1
	}
}

// cacheExistsMock returns the cache exists mock callback.
func cacheExistsMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		_ = mockData.RecordCall(definitions.LuaFnCacheExists, key)
		_, exists := cache[key]
		L.Push(lua.LBool(exists))

		return 1
	}
}

// cacheUpdateMock returns the cache update mock callback.
func cacheUpdateMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		updater := L.CheckFunction(2)
		_ = mockData.RecordCall(definitions.LuaFnCacheUpdate, key)

		if err := L.CallByParam(lua.P{Fn: updater, NRet: 1, Protect: true}, cacheValueToLua(L, cache[key])); err != nil {
			pushLuaNilAndError(L, err.Error())

			return 2
		}

		newValue := L.Get(-1)
		L.Pop(1)

		cache[key] = convert.LuaValueToGo(newValue)
		L.Push(newValue)
		L.Push(lua.LNil)

		return 2
	}
}

// cacheKeysMock returns the cache keys mock callback.
func cacheKeysMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		_ = mockData.RecordCall(definitions.LuaFnCacheKeys, "")
		keys := L.NewTable()

		i := 1
		for key := range cache {
			keys.RawSetInt(i, lua.LString(key))
			i++
		}

		L.Push(keys)

		return 1
	}
}

// cacheSizeMock returns the cache size mock callback.
func cacheSizeMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		_ = mockData.RecordCall(definitions.LuaFnCacheSize, "")

		L.Push(lua.LNumber(len(cache)))

		return 1
	}
}

// cacheFlushMock returns the cache flush mock callback.
func cacheFlushMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(_ *lua.LState) int {
		_ = mockData.RecordCall(definitions.LuaFnCacheFlush, "")

		for key := range cache {
			delete(cache, key)
		}

		return 0
	}
}

// cachePushMock returns the cache push mock callback.
func cachePushMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		value := convert.LuaValueToGo(L.CheckAny(2))
		_ = mockData.RecordCall(definitions.LuaFnCachePush, key)
		list := appendCacheValue(cache[key], value)
		cache[key] = list
		L.Push(lua.LNumber(len(list)))

		return 1
	}
}

// cachePopAllMock returns the cache pop-all mock callback.
func cachePopAllMock(mockData *CacheMock, cache map[string]any) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		_ = mockData.RecordCall(definitions.LuaFnCachePopAll, key)
		current, ok := cache[key]
		delete(cache, key)

		L.Push(cachePopAllResultTable(L, current, ok))

		return 1
	}
}

// cacheValueToLua converts a cache entry into a Lua value.
func cacheValueToLua(L *lua.LState, value any) lua.LValue {
	if value == nil {
		return lua.LNil
	}

	return convert.GoToLuaValue(L, value)
}

// appendCacheValue appends a value to a scalar-or-list cache entry.
func appendCacheValue(current any, value any) []any {
	if current == nil {
		return []any{value}
	}

	list, ok := current.([]any)
	if !ok {
		list = []any{current}
	}

	return append(list, value)
}

// cachePopAllResultTable converts a cache entry into the pop-all result table.
func cachePopAllResultTable(L *lua.LState, current any, ok bool) *lua.LTable {
	result := L.NewTable()
	if !ok {
		return result
	}

	if list, ok := current.([]any); ok {
		for i, value := range list {
			result.RawSetInt(i+1, convert.GoToLuaValue(L, value))
		}

		return result
	}

	result.RawSetInt(1, convert.GoToLuaValue(L, current))

	return result
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

	lualib.SetBuiltinTableForAll(L, func(L *lua.LState) int {
		logKey := L.CheckString(1)
		logValue := L.OptString(2, "")

		if logger != nil {
			logger.Log(fmt.Sprintf("[CUSTOM] %s: %s", logKey, logValue))
		}

		return 0
	}, nil)

	builtin, ok := L.GetGlobal(definitions.LuaDefaultTable).(*lua.LTable)
	if !ok || builtin == nil {
		return
	}

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
	mockData = ensureLuaTestMockData(mockData)

	cleanupFns := make([]func(), 0, 2)
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			if cleanupFns[i] != nil {
				cleanupFns[i]()
			}
		}
	}

	preloadLuaTestBaseModules(L)
	setupDatabaseMock(L, mockData)
	setupBackendAndContextMocks(mockData)

	redisRuntime, err := setupRedisRuntimeMock(mockData)
	if err != nil {
		cleanup()

		return nil, fmt.Errorf("failed to setup miniredis runtime: %w", err)
	}

	cleanupFns = append(cleanupFns, redisRuntime.Close)

	setupPolicyDirectoryAndHTTPMocks(mockData)
	setupNetworkObservabilityMocks(L, mockData)
	setupUtilityMockData(mockData)
	setupLuaTestRequestEnvironment(L, mockData)

	if err = preloadLuaTestMockModules(L, mockData, redisRuntime); err != nil {
		cleanup()

		return nil, err
	}

	SetupBuiltinTable(L, logger)

	setupLuaTestContextGlobal(L, mockData)

	return cleanup, nil
}

// ensureLuaTestMockData returns a writable mock-data container.
func ensureLuaTestMockData(mockData *MockData) *MockData {
	if mockData == nil {
		return &MockData{}
	}

	return mockData
}

// preloadLuaTestBaseModules registers shared third-party Lua modules.
func preloadLuaTestBaseModules(L *lua.LState) {
	libs.Preload(L)
	L.PreloadModule("glua_crypto", gluacrypto.Loader)
}

// setupDatabaseMock prepares the shadow db module.
func setupDatabaseMock(L *lua.LState, mockData *MockData) {
	ensureResetMock(&mockData.DB)
	L.PreloadModule("db", LoaderModDBMock(mockData.DB))
}

// setupBackendAndContextMocks prepares backend and optional context mocks.
func setupBackendAndContextMocks(mockData *MockData) {
	ensureResetMock(&mockData.Backend)

	if mockData.Context != nil {
		mockData.Context.ResetRuntimeState()
	}
}

// setupRedisRuntimeMock prepares Redis mock data and miniredis runtime.
func setupRedisRuntimeMock(mockData *MockData) (*redisRuntime, error) {
	ensureResetMock(&mockData.Redis)

	return newRedisRuntime(mockData.Redis)
}

// setupPolicyDirectoryAndHTTPMocks prepares policy, identity, and HTTP mocks.
func setupPolicyDirectoryAndHTTPMocks(mockData *MockData) {
	ensureResetMock(&mockData.Policy)
	ensureResetMock(&mockData.I18N)
	ensureResetMock(&mockData.LDAP)
	ensureResetMock(&mockData.BackendResult)
	ensureResetMock(&mockData.HTTPRequest)
	ensureResetMock(&mockData.HTTPResponse)
}

// setupNetworkObservabilityMocks prepares network and observability mocks.
func setupNetworkObservabilityMocks(L *lua.LState, mockData *MockData) {
	setupHTTPClientMock(L, mockData)

	ensureResetMock(&mockData.DNS)
	ensureResetMock(&mockData.OpenTelemetry)
	ensureResetMock(&mockData.BruteForce)
	ensureResetMock(&mockData.Psnet)
	ensureResetMock(&mockData.Prometheus)
}

// setupHTTPClientMock prepares the optional HTTP client module shadow.
func setupHTTPClientMock(L *lua.LState, mockData *MockData) {
	if mockData.HTTPClient != nil {
		mockData.HTTPClient.ResetRuntimeState()
		L.PreloadModule("glua_http", LoaderModHTTPClientMock(mockData.HTTPClient))

		return
	}

	L.PreloadModule("glua_http", gluahttp.NewHttpModule(&stdhttp.Client{}).Loader)
}

// setupUtilityMockData prepares utility-oriented mocks.
func setupUtilityMockData(mockData *MockData) {
	ensureResetMock(&mockData.Util)
	ensureResetMock(&mockData.Cache)
	ensureResetMock(&mockData.Misc)
	ensureResetMock(&mockData.Password)
	ensureResetMock(&mockData.SoftWhitelist)
	ensureResetMock(&mockData.Mail)
}

// setupLuaTestRequestEnvironment binds the request context into Lua globals.
func setupLuaTestRequestEnvironment(L *lua.LState, mockData *MockData) {
	reqEnv := L.NewTable()
	L.SetGlobal("__NAUTH_REQ_ENV", reqEnv)

	luaCtx := lualib.NewContext()
	if mockData.Context != nil {
		populateLuaTestContext(luaCtx, mockData.Context)
	}

	bindRequestValueToEnv(L, reqEnv, luaRequestContextKey, luaCtx)
}

// populateLuaTestContext copies fixture request fields into the Lua request context.
func populateLuaTestContext(luaCtx *lualib.Context, contextMock *ContextMock) {
	luaCtx.Set(definitions.LuaRequestUsername, contextMock.Username)
	luaCtx.Set(definitions.LuaRequestPassword, contextMock.Password)
	luaCtx.Set(definitions.LuaRequestClientIP, contextMock.ClientIP)
	luaCtx.Set(definitions.LuaRequestClientPort, contextMock.ClientPort)
	luaCtx.Set(definitions.LuaRequestClientHost, contextMock.ClientHost)
	luaCtx.Set(definitions.LuaRequestClientID, contextMock.ClientID)
	luaCtx.Set(definitions.LuaRequestLocalIP, contextMock.LocalIP)
	luaCtx.Set(definitions.LuaRequestLocalPort, contextMock.LocalPort)
	luaCtx.Set(definitions.LuaRequestService, contextMock.Service)
	luaCtx.Set(definitions.LuaRequestProtocol, contextMock.Protocol)
	luaCtx.Set(definitions.LuaRequestUserAgent, contextMock.UserAgent)
	luaCtx.Set(definitions.LuaRequestSession, contextMock.Session)
	luaCtx.Set(definitions.LuaRequestDebug, contextMock.Debug)
	luaCtx.Set(definitions.LuaRequestNoAuth, contextMock.NoAuth)
	luaCtx.Set(definitions.LuaRequestAuthenticated, contextMock.Authenticated)
	luaCtx.Set(definitions.LuaRequestUserFound, contextMock.UserFound)
	luaCtx.Set(definitions.LuaRequestAccount, contextMock.Account)
	luaCtx.Set(definitions.LuaRequestUniqueUserID, contextMock.UniqueUserID)
	luaCtx.Set(definitions.LuaRequestDisplayName, contextMock.DisplayName)
	luaCtx.Set(definitions.LuaRequestStatusMessage, contextMock.StatusMessage)
	luaCtx.Set(definitions.LuaRequestBruteForceCounter, contextMock.BruteForceCount)

	for key, value := range contextMock.Attributes {
		luaCtx.Set(key, value)
	}
}

// preloadLuaTestMockModules registers all Nauthilus mock modules.
func preloadLuaTestMockModules(L *lua.LState, mockData *MockData, redisRuntime *redisRuntime) error {
	L.PreloadModule(definitions.LuaModContext, LoaderModContextMock(mockData.Context))
	L.PreloadModule(definitions.LuaModRedis, redisRuntime.Loader(context.Background(), resolveLuaTestConfig(), mockData.Redis))
	L.PreloadModule(definitions.LuaModBackend, LoaderModBackendMock(mockData.Backend))

	if err := preloadBackendResultMockModule(L, mockData.BackendResult); err != nil {
		return err
	}

	preloadHTTPPolicyAndDirectoryModules(L, mockData)
	preloadObservabilityModules(L, mockData)
	preloadUtilityModules(L, mockData)

	return nil
}

// preloadBackendResultMockModule registers and exposes backend-result userdata helpers.
func preloadBackendResultMockModule(L *lua.LState, mockData *BackendResultMock) error {
	backendResultLoader := LoaderModBackendResultMock(mockData)
	L.PreloadModule(definitions.LuaBackendResultTypeName, backendResultLoader)

	if err := L.CallByParam(lua.P{
		Fn:      L.NewFunction(backendResultLoader),
		NRet:    1,
		Protect: true,
	}); err != nil {
		return fmt.Errorf("failed to bind backend result test module: %w", err)
	}

	L.SetGlobal(definitions.LuaBackendResultTypeName, L.Get(-1))
	L.Pop(1)

	return nil
}

// preloadHTTPPolicyAndDirectoryModules registers HTTP, policy, and directory mocks.
func preloadHTTPPolicyAndDirectoryModules(L *lua.LState, mockData *MockData) {
	preloadLuaTestMockModuleGroup(L, mockData, httpPolicyDirectoryMockModuleIDs)
}

// preloadObservabilityModules registers network and observability mocks.
func preloadObservabilityModules(L *lua.LState, mockData *MockData) {
	preloadLuaTestMockModuleGroup(L, mockData, observabilityMockModuleIDs)
}

// preloadUtilityModules registers utility mock modules.
func preloadUtilityModules(L *lua.LState, mockData *MockData) {
	L.PreloadModule(definitions.LuaModMisc, LoaderModMiscMock(mockData.Misc))
	L.PreloadModule(definitions.LuaModPassword, LoaderModPasswordMock(mockData.Password))
	L.PreloadModule(definitions.LuaModSoftWhitelist, LoaderModSoftWhitelistMock(mockData.SoftWhitelist))
	L.PreloadModule(definitions.LuaModMail, LoaderModMailMock(mockData.Mail))
	L.PreloadModule("nauthilus_util", LoaderModUtilMock(mockData.Util))
	L.PreloadModule("nauthilus_cache", LoaderModCacheMock(mockData.Cache))
}

// setupLuaTestContextGlobal exposes a background context when context fixtures exist.
func setupLuaTestContextGlobal(L *lua.LState, mockData *MockData) {
	if mockData.Context == nil {
		return
	}

	L.SetGlobal("__test_context", convert.GoToLuaValue(L, context.Background()))
}

// ensureResetMock initializes one mock-data field and resets its runtime state.
func ensureResetMock[T any](slot **T) {
	if *slot == nil {
		*slot = new(T)
	}

	resetter, ok := any(*slot).(resettableLuaMock)
	if !ok {
		panic("mock slot must reset runtime state")
	}

	resetter.ResetRuntimeState()
}

// preloadLuaTestMockModuleGroup registers resolved mock modules on the Lua state.
func preloadLuaTestMockModuleGroup(L *lua.LState, mockData *MockData, moduleIDs []luaMockModuleID) {
	for _, moduleID := range moduleIDs {
		module := resolveLuaTestMockModule(moduleID, mockData)
		L.PreloadModule(module.name, module.callback)
	}
}

// resolveLuaTestMockModule maps stable module IDs to their Lua module names and loaders.
func resolveLuaTestMockModule(moduleID luaMockModuleID, mockData *MockData) luaMockModuleField {
	switch moduleID {
	case luaMockModuleHTTPRequest:
		return luaMockModuleField{name: definitions.LuaModHTTPRequest, callback: LoaderModHTTPRequestMock(mockData.HTTPRequest)}
	case luaMockModuleHTTPResponse:
		return luaMockModuleField{name: definitions.LuaModHTTPResponse, callback: LoaderModHTTPResponseMock(mockData.HTTPResponse)}
	case luaMockModulePolicy:
		return luaMockModuleField{name: definitions.LuaModPolicy, callback: LoaderModPolicyMock(mockData.Policy)}
	case luaMockModuleI18N:
		return luaMockModuleField{name: definitions.LuaModI18N, callback: LoaderModI18NMock(mockData.I18N)}
	case luaMockModuleLDAP:
		return luaMockModuleField{name: definitions.LuaModLDAP, callback: LoaderModLDAPMock(mockData.LDAP)}
	case luaMockModuleDNS:
		return luaMockModuleField{name: definitions.LuaModDNS, callback: LoaderModDNSMock(mockData.DNS)}
	case luaMockModulePrometheus:
		return luaMockModuleField{name: definitions.LuaModPrometheus, callback: LoaderModPrometheusMock(mockData.Prometheus)}
	case luaMockModuleOpenTelemetry:
		return luaMockModuleField{name: definitions.LuaModOpenTelemetry, callback: LoaderModOTELMock(mockData.OpenTelemetry)}
	case luaMockModuleBruteForce:
		return luaMockModuleField{name: definitions.LuaModBruteForce, callback: LoaderModBruteForceMock(mockData.BruteForce)}
	case luaMockModulePsnet:
		return luaMockModuleField{name: definitions.LuaModPsnet, callback: LoaderModPsnetMock(mockData.Psnet)}
	default:
		panic(fmt.Sprintf("unsupported Lua test mock module ID: %d", moduleID))
	}
}
