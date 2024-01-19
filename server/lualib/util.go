package lualib

import (
	"github.com/croessner/nauthilus/server/util"
	"github.com/vadv/gopher-lua-libs/argparse"
	"github.com/vadv/gopher-lua-libs/base64"
	"github.com/vadv/gopher-lua-libs/crypto"
	"github.com/vadv/gopher-lua-libs/db"
	"github.com/vadv/gopher-lua-libs/filepath"
	"github.com/vadv/gopher-lua-libs/http/client"
	"github.com/vadv/gopher-lua-libs/humanize"
	"github.com/vadv/gopher-lua-libs/inspect"
	"github.com/vadv/gopher-lua-libs/ioutil"
	"github.com/vadv/gopher-lua-libs/json"
	"github.com/vadv/gopher-lua-libs/log"
	"github.com/vadv/gopher-lua-libs/pprof"
	"github.com/vadv/gopher-lua-libs/regexp"
	"github.com/vadv/gopher-lua-libs/shellescape"
	"github.com/vadv/gopher-lua-libs/storage"
	"github.com/vadv/gopher-lua-libs/strings"
	"github.com/vadv/gopher-lua-libs/tac"
	"github.com/vadv/gopher-lua-libs/tcp"
	"github.com/vadv/gopher-lua-libs/telegram"
	"github.com/vadv/gopher-lua-libs/template"
	"github.com/vadv/gopher-lua-libs/time"
	"github.com/vadv/gopher-lua-libs/xmlpath"
	"github.com/vadv/gopher-lua-libs/yaml"
	"github.com/yuin/gopher-lua"
)

// LuaTableToMap takes a lua.LTable as input and converts it into a map[any]any.
// The function iterates over each key-value pair in the table and converts the keys and values
// into their corresponding Go types. The converted key-value pairs are then added to a new map, which is
// returned as the result.
// If the input table is nil, the function returns nil.
func LuaTableToMap(table *lua.LTable) map[any]any {
	if table == nil {
		return nil
	}

	result := make(map[any]any)

	table.ForEach(func(key lua.LValue, value lua.LValue) {
		var (
			mapKey   any
			mapValue any
		)

		switch k := key.(type) {
		case lua.LBool:
			mapKey = bool(k)
		case lua.LNumber:
			mapKey = float64(k)
		case lua.LString:
			mapKey = k.String()
		default:
			return
		}

		switch v := value.(type) {
		case lua.LBool:
			mapValue = bool(v)
		case lua.LNumber:
			mapValue = float64(v)
		case *lua.LTable:
			mapValue = LuaTableToMap(v)
		default:
			mapValue = v.String()
		}

		result[mapKey] = mapValue
	})

	return result
}

// MapToLuaTable takes an *lua.LState and a map[any]any as input and converts it into a *lua.LTable.
// The function iterates over each key-value pair in the map and converts the keys and values
// into their corresponding lua.LValue types. The converted key-value pairs are then added to a new *lua.LTable,
// which is returned as the result.
// If the input map is nil, the function returns nil.
func MapToLuaTable(L *lua.LState, table map[any]any) *lua.LTable {
	var (
		key   lua.LValue
		value lua.LValue
	)

	lTable := L.NewTable()

	if table == nil {
		return nil
	}

	for k, v := range table {
		switch mapKey := k.(type) {
		case bool:
			key = lua.LBool(mapKey)
		case float64:
			key = lua.LNumber(mapKey)
		case string:
			key = lua.LString(mapKey)
		default:
			return nil
		}

		switch mapValue := v.(type) {
		case bool:
			value = lua.LBool(mapValue)
		case float64:
			value = lua.LNumber(mapValue)
		case string:
			value = lua.LString(mapValue)
		case map[any]any:
			value = MapToLuaTable(L, mapValue)
		default:
			return nil
		}

		L.RawSet(lTable, key, value)
	}

	return lTable
}

func Loader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exports)

	L.Push(mod)

	return 1
}

var exports = map[string]lua.LGFunction{
	"compare_passwords": comparePasswords,
}

func comparePasswords(L *lua.LState) int {
	if L.GetTop() != 2 {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("wrong number of arguments"))

		return 2
	}

	hashPassword := L.CheckString(1)
	plainPassword := L.CheckString(2)

	passwordsMatched, err := util.ComparePasswords(hashPassword, plainPassword)

	L.Push(lua.LBool(passwordsMatched))

	if err != nil {
		L.Push(lua.LString(err.Error()))
	} else {
		L.Push(lua.LNil)
	}

	return 2
}

// LoadSubset loads a subset of Lua libraries into the Lua state L.
// The function preloads several commonly used libraries including argparse, base64, crypto, db, filepath, http, humanize, inspect, ioutil, json, log, pprof, regexp, shellescape, storage
func LoadSubset(L *lua.LState) {
	argparse.Preload(L)
	base64.Preload(L)
	crypto.Preload(L)
	db.Preload(L)
	filepath.Preload(L)
	http.Preload(L)
	humanize.Preload(L)
	inspect.Preload(L)
	ioutil.Preload(L)
	json.Preload(L)
	log.Preload(L)
	pprof.Preload(L)
	regexp.Preload(L)
	shellescape.Preload(L)
	storage.Preload(L)
	strings.Preload(L)
	tac.Preload(L)
	tcp.Preload(L)
	telegram.Preload(L)
	template.Preload(L)
	time.Preload(L)
	xmlpath.Preload(L)
	yaml.Preload(L)
}
