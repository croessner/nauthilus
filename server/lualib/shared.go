package lualib

import (
	"bufio"
	"os"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// CompileLua reads the passed lua file from disk and compiles it.
func CompileLua(filePath string) (*lua.FunctionProto, error) {
	file, err := os.Open(filePath)

	defer file.Close()

	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)

	chunk, err := parse.Parse(reader, filePath)
	if err != nil {
		return nil, err
	}

	proto, err := lua.Compile(chunk, filePath)
	if err != nil {
		return nil, err
	}

	return proto, nil
}

// DoCompiledFile takes a FunctionProto, as returned by CompileLua, and runs it in the LState. It is equivalent
// to calling DoFile on the LState with the original source file.
func DoCompiledFile(L *lua.LState, proto *lua.FunctionProto) error {
	lfunc := L.NewFunctionFromProto(proto)

	L.Push(lfunc)

	return L.PCall(0, lua.MultRet, nil)
}

// CleanupLTable cleans up the given Lua table by setting all its values to nil.
// It iterates through the key-value pairs of the table and sets each value to nil using the RawSet method.
// This function is typically used to release resources associated with a Lua table and prevent memory leaks.
// Parameters:
// - table: A pointer to the Lua table that needs to be cleaned up.
// Returns: None.
func CleanupLTable(table *lua.LTable) {
	table.ForEach(func(key lua.LValue, value lua.LValue) {
		table.RawSet(key, lua.LNil)
	})
}
