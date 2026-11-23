package lua

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"

	"github.com/yuin/gopher-lua/parse"
)

/* basic functions {{{ */

func OpenBase(L *LState) int {
	if L.is55() {
		return openBase55(L)
	}
	global := L.Get(GlobalsIndex).(*LTable)
	L.SetGlobal("_G", global)
	L.SetGlobal("_VERSION", LString(LuaVersion))
	L.SetGlobal("_GOPHER_LUA_VERSION", LString(PackageName+" "+PackageVersion))
	basemod := L.RegisterModule("_G", baseFuncs)
	global.RawSetString("ipairs", L.NewClosure(baseIpairs, L.NewFunction(ipairsaux)))
	global.RawSetString("pairs", L.NewClosure(basePairs, L.NewFunction(pairsaux)))
	L.Push(basemod)
	return 1
}

var baseFuncs = map[string]LGFunction{
	"assert":         baseAssert,
	"collectgarbage": baseCollectGarbage,
	"dofile":         baseDoFile,
	"error":          baseError,
	"getfenv":        baseGetFEnv,
	"getmetatable":   baseGetMetatable,
	"load":           baseLoad,
	"loadfile":       baseLoadFile,
	"loadstring":     baseLoadString,
	"next":           baseNext,
	"pcall":          basePCall,
	"print":          basePrint,
	"rawequal":       baseRawEqual,
	"rawget":         baseRawGet,
	"rawset":         baseRawSet,
	"select":         baseSelect,
	"_printregs":     base_PrintRegs,
	"setfenv":        baseSetFEnv,
	"setmetatable":   baseSetMetatable,
	"tonumber":       baseToNumber,
	"tostring":       baseToString,
	"type":           baseType,
	"unpack":         baseUnpack,
	"xpcall":         baseXPCall,
	// loadlib
	"module":  loModule,
	"require": loRequire,
	// hidden features
	"newproxy": baseNewProxy,
}

func baseAssert(L *LState) int {
	if !L.ToBool(1) {
		L.RaiseError(L.OptString(2, "assertion failed!"))
		return 0
	}
	return L.GetTop()
}

func baseCollectGarbage(L *LState) int {
	runtime.GC()
	return 0
}

func baseDoFile(L *LState) int {
	src := L.ToString(1)
	top := L.GetTop()
	fn, err := L.LoadFile(src)
	if err != nil {
		L.Push(LString(err.Error()))
		L.Panic(L)
	}
	L.Push(fn)
	L.Call(0, MultRet)
	return L.GetTop() - top
}

func baseError(L *LState) int {
	obj := L.CheckAny(1)
	level := L.OptInt(2, 1)
	L.Error(obj, level)
	return 0
}

func baseGetFEnv(L *LState) int {
	var value LValue
	if L.GetTop() == 0 {
		value = LNumber(1)
	} else {
		value = L.Get(1)
	}

	if fn, ok := value.(*LFunction); ok {
		if !fn.IsG {
			L.Push(fn.Env)
		} else {
			L.Push(L.G.Global)
		}
		return 1
	}

	if number, ok := value.(LNumber); ok {
		level := int(float64(number))
		if level <= 0 {
			L.Push(L.Env)
		} else {
			cf := L.currentFrame
			for i := 0; i < level && cf != nil; i++ {
				cf = cf.Parent
			}
			if cf == nil || cf.Fn.IsG {
				L.Push(L.G.Global)
			} else {
				L.Push(cf.Fn.Env)
			}
		}
		return 1
	}

	L.Push(L.G.Global)
	return 1
}

func baseGetMetatable(L *LState) int {
	L.Push(L.GetMetatable(L.CheckAny(1)))
	return 1
}

func ipairsaux(L *LState) int {
	tb := L.CheckTable(1)
	i := L.CheckInt(2)
	i++
	v := tb.RawGetInt(i)
	if v == LNil {
		return 0
	} else {
		L.Pop(1)
		L.Push(LNumber(i))
		L.Push(LNumber(i))
		L.Push(v)
		return 2
	}
}

func baseIpairs(L *LState) int {
	tb := L.CheckTable(1)
	L.Push(L.Get(UpvalueIndex(1)))
	L.Push(tb)
	L.Push(LNumber(0))
	return 3
}

func loadaux(L *LState, reader io.Reader, chunkname string) int {
	if fn, err := L.Load(reader, chunkname); err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		return 2
	} else {
		L.Push(fn)
		return 1
	}
}

func baseLoad(L *LState) int {
	fn := L.CheckFunction(1)
	chunkname := L.OptString(2, "?")
	top := L.GetTop()
	buf := []string{}
	for {
		L.SetTop(top)
		L.Push(fn)
		L.Call(0, 1)
		ret := L.reg.Pop()
		if ret == LNil {
			break
		} else if LVCanConvToString(ret) {
			str := ret.String()
			if len(str) > 0 {
				buf = append(buf, string(str))
			} else {
				break
			}
		} else {
			L.Push(LNil)
			L.Push(LString("reader function must return a string"))
			return 2
		}
	}
	return loadaux(L, strings.NewReader(strings.Join(buf, "")), chunkname)
}

func baseLoadFile(L *LState) int {
	var reader io.Reader
	var chunkname string
	var err error
	if L.GetTop() < 1 {
		reader = os.Stdin
		chunkname = "<stdin>"
	} else {
		chunkname = L.CheckString(1)
		reader, err = os.Open(chunkname)
		if err != nil {
			L.Push(LNil)
			L.Push(LString(fmt.Sprintf("can not open file: %v", chunkname)))
			return 2
		}
		defer reader.(*os.File).Close()
	}
	return loadaux(L, reader, chunkname)
}

func baseLoadString(L *LState) int {
	return loadaux(L, strings.NewReader(L.CheckString(1)), L.OptString(2, "<string>"))
}

func baseNext(L *LState) int {
	tb := L.CheckTable(1)
	index := LNil
	if L.GetTop() >= 2 {
		index = L.Get(2)
	}
	key, value := tb.Next(index)
	if key == LNil {
		L.Push(LNil)
		return 1
	}
	L.Push(key)
	L.Push(value)
	return 2
}

func pairsaux(L *LState) int {
	tb := L.CheckTable(1)
	key, value := tb.Next(L.Get(2))
	if key == LNil {
		return 0
	} else {
		L.Pop(1)
		L.Push(key)
		L.Push(key)
		L.Push(value)
		return 2
	}
}

func basePairs(L *LState) int {
	tb := L.CheckTable(1)
	L.Push(L.Get(UpvalueIndex(1)))
	L.Push(tb)
	L.Push(LNil)
	return 3
}

func basePCall(L *LState) int {
	L.CheckAny(1)
	v := L.Get(1)
	if v.Type() != LTFunction && L.GetMetaField(v, "__call").Type() != LTFunction {
		L.Push(LFalse)
		L.Push(LString("attempt to call a " + v.Type().String() + " value"))
		return 2
	}
	nargs := L.GetTop() - 1
	if err := L.PCall(nargs, MultRet, nil); err != nil {
		L.Push(LFalse)
		if aerr, ok := err.(*ApiError); ok {
			L.Push(aerr.Object)
		} else {
			L.Push(LString(err.Error()))
		}
		return 2
	} else {
		L.Insert(LTrue, 1)
		return L.GetTop()
	}
}

func basePrint(L *LState) int {
	top := L.GetTop()
	for i := 1; i <= top; i++ {
		fmt.Print(L.ToStringMeta(L.Get(i)).String())
		if i != top {
			fmt.Print("\t")
		}
	}
	fmt.Println("")
	return 0
}

func base_PrintRegs(L *LState) int {
	L.printReg()
	return 0
}

func baseRawEqual(L *LState) int {
	if L.CheckAny(1) == L.CheckAny(2) {
		L.Push(LTrue)
	} else {
		L.Push(LFalse)
	}
	return 1
}

func baseRawGet(L *LState) int {
	L.Push(L.RawGet(L.CheckTable(1), L.CheckAny(2)))
	return 1
}

func baseRawSet(L *LState) int {
	L.RawSet(L.CheckTable(1), L.CheckAny(2), L.CheckAny(3))
	return 0
}

func baseSelect(L *LState) int {
	L.CheckTypes(1, LTNumber, LTString)
	switch lv := L.Get(1).(type) {
	case LNumber:
		idx := int(lv)
		num := L.GetTop()
		if idx < 0 {
			idx = num + idx
		} else if idx > num {
			idx = num
		}
		if 1 > idx {
			L.ArgError(1, "index out of range")
		}
		return num - idx
	case LString:
		if string(lv) != "#" {
			L.ArgError(1, "invalid string '"+string(lv)+"'")
		}
		L.Push(LNumber(L.GetTop() - 1))
		return 1
	}
	return 0
}

func baseSetFEnv(L *LState) int {
	var value LValue
	if L.GetTop() == 0 {
		value = LNumber(1)
	} else {
		value = L.Get(1)
	}
	env := L.CheckTable(2)

	if fn, ok := value.(*LFunction); ok {
		if fn.IsG {
			L.RaiseError("cannot change the environment of given object")
		} else {
			fn.Env = env
			L.Push(fn)
			return 1
		}
	}

	if number, ok := value.(LNumber); ok {
		level := int(float64(number))
		if level <= 0 {
			L.Env = env
			return 0
		}

		cf := L.currentFrame
		for i := 0; i < level && cf != nil; i++ {
			cf = cf.Parent
		}
		if cf == nil || cf.Fn.IsG {
			L.RaiseError("cannot change the environment of given object")
		} else {
			cf.Fn.Env = env
			L.Push(cf.Fn)
			return 1
		}
	}

	L.RaiseError("cannot change the environment of given object")
	return 0
}

func baseSetMetatable(L *LState) int {
	L.CheckTypes(2, LTNil, LTTable)
	obj := L.Get(1)
	if obj == LNil {
		L.RaiseError("cannot set metatable to a nil object.")
	}
	mt := L.Get(2)
	if m := L.metatable(obj, true); m != LNil {
		if tb, ok := m.(*LTable); ok && tb.RawGetString("__metatable") != LNil {
			L.RaiseError("cannot change a protected metatable")
		}
	}
	L.SetMetatable(obj, mt)
	L.SetTop(1)
	return 1
}

func baseToNumber(L *LState) int {
	base := L.OptInt(2, 10)
	noBase := L.Get(2) == LNil

	switch lv := L.CheckAny(1).(type) {
	case LNumber, LInteger: // (integers only get here when Go code injects them)
		L.Push(lv)
	case LString:
		str := strings.Trim(string(lv), " \n\t")
		if strings.Index(str, ".") > -1 {
			if v, err := strconv.ParseFloat(str, LNumberBit); err != nil {
				L.Push(LNil)
			} else {
				L.Push(LNumber(v))
			}
		} else {
			if noBase && strings.HasPrefix(strings.ToLower(str), "0x") {
				base, str = 16, str[2:] // Hex number
			}
			if v, err := strconv.ParseInt(str, base, LNumberBit); err != nil {
				L.Push(LNil)
			} else {
				L.Push(LNumber(v))
			}
		}
	default:
		L.Push(LNil)
	}
	return 1
}

func baseToString(L *LState) int {
	v1 := L.CheckAny(1)
	L.Push(L.ToStringMeta(v1))
	return 1
}

func baseType(L *LState) int {
	L.Push(LString(L.CheckAny(1).Type().String()))
	return 1
}

func baseUnpack(L *LState) int {
	tb := L.CheckTable(1)
	start := L.OptInt(2, 1)
	end := L.OptInt(3, tb.Len())
	for i := start; i <= end; i++ {
		L.Push(tb.RawGetInt(i))
	}
	ret := end - start + 1
	if ret < 0 {
		return 0
	}
	return ret
}

func baseXPCall(L *LState) int {
	fn := L.CheckFunction(1)
	errfunc := L.CheckFunction(2)

	top := L.GetTop()
	L.Push(fn)
	if err := L.PCall(0, MultRet, errfunc); err != nil {
		L.Push(LFalse)
		if aerr, ok := err.(*ApiError); ok {
			L.Push(aerr.Object)
		} else {
			L.Push(LString(err.Error()))
		}
		return 2
	} else {
		L.Insert(LTrue, top+1)
		return L.GetTop() - top
	}
}

/* }}} */

/* load lib {{{ */

func loModule(L *LState) int {
	name := L.CheckString(1)
	loaded := L.GetField(L.Get(RegistryIndex), "_LOADED")
	tb := L.GetField(loaded, name)
	if _, ok := tb.(*LTable); !ok {
		tb = L.FindTable(L.Get(GlobalsIndex).(*LTable), name, 1)
		if tb == LNil {
			L.RaiseError("name conflict for module: %v", name)
		}
		L.SetField(loaded, name, tb)
	}
	if L.GetField(tb, "_NAME") == LNil {
		L.SetField(tb, "_M", tb)
		L.SetField(tb, "_NAME", LString(name))
		names := strings.Split(name, ".")
		pname := ""
		if len(names) > 1 {
			pname = strings.Join(names[:len(names)-1], ".") + "."
		}
		L.SetField(tb, "_PACKAGE", LString(pname))
	}

	caller := L.currentFrame.Parent
	if caller == nil {
		L.RaiseError("no calling stack.")
	} else if caller.Fn.IsG {
		L.RaiseError("module() can not be called from GFunctions.")
	}
	L.SetFEnv(caller.Fn, tb)

	top := L.GetTop()
	for i := 2; i <= top; i++ {
		L.Push(L.Get(i))
		L.Push(tb)
		L.Call(1, 0)
	}
	L.Push(tb)
	return 1
}

var loopdetection = &LUserData{}

func loRequire(L *LState) int {
	name := L.CheckString(1)
	loaded := L.GetField(L.Get(RegistryIndex), "_LOADED")
	lv := L.GetField(loaded, name)
	if LVAsBool(lv) {
		if lv == loopdetection {
			L.RaiseError("loop or previous error loading module: %s", name)
		}
		L.Push(lv)
		return 1
	}
	loaders, ok := L.GetField(L.Get(RegistryIndex), "_LOADERS").(*LTable)
	if !ok {
		L.RaiseError("package.loaders must be a table")
	}
	messages := []string{}
	var modasfunc LValue
	for i := 1; ; i++ {
		loader := L.RawGetInt(loaders, i)
		if loader == LNil {
			L.RaiseError("module %s not found:\n\t%s, ", name, strings.Join(messages, "\n\t"))
		}
		L.Push(loader)
		L.Push(LString(name))
		L.Call(1, 1)
		ret := L.reg.Pop()
		switch retv := ret.(type) {
		case *LFunction:
			modasfunc = retv
			goto loopbreak
		case LString:
			messages = append(messages, string(retv))
		}
	}
loopbreak:
	L.SetField(loaded, name, loopdetection)
	L.Push(modasfunc)
	L.Push(LString(name))
	L.Call(1, 1)
	ret := L.reg.Pop()
	modv := L.GetField(loaded, name)
	if ret != LNil && modv == loopdetection {
		L.SetField(loaded, name, ret)
		L.Push(ret)
	} else if modv == loopdetection {
		L.SetField(loaded, name, LTrue)
		L.Push(LTrue)
	} else {
		L.Push(modv)
	}
	return 1
}

/* }}} */

/* hidden features {{{ */

func baseNewProxy(L *LState) int {
	ud := L.NewUserData()
	L.SetTop(1)
	if L.Get(1) == LTrue {
		L.SetMetatable(ud, L.NewTable())
	} else if d, ok := L.Get(1).(*LUserData); ok {
		L.SetMetatable(ud, L.GetMetatable(d))
	}
	L.Push(ud)
	return 1
}

/* }}} */

/* Lua 5.5 profile {{{ */

// luaVersion55 is the value of _VERSION in the Lua 5.5 profile.
const luaVersion55 = "Lua 5.5"

// base55RegistryKey is the registry key of the per-state settings shared
// by the Lua 5.5 base, coroutine and debug libraries.
const base55RegistryKey = "_BASE55"

// base55NoErrorObject replaces a nil error value delivered to a protected
// call, like the reference implementation does.
const base55NoErrorObject = "<no error object>"

// base55MaxHandlerRetries bounds how often a failing message handler is
// called again with its own error before xpcall gives up.
const base55MaxHandlerRetries = 100

// base55IDSize is the maximum size of a chunk identifier (LUA_IDSIZE).
const base55IDSize = 60

// base55MaxUpvalueIDs bounds the caches of upvalue identifiers and of
// literal chunk names.
const base55MaxUpvalueIDs = 1024

var base55GCOptions = []string{"stop", "restart", "collect", "count", "step", "isrunning", "generational", "incremental", "param"}

var base55GCParams = []string{"minormul", "majorminor", "minormajor", "pause", "stepmul", "stepsize"}

// base55GCDefaults holds the default collector parameters in the order of
// base55GCParams. They are stored and reported only: the Go collector is
// not tunable per Lua state.
var base55GCDefaults = [6]int64{20, 50, 68, 250, 200, 9600}

// base55State holds the per-state settings of the Lua 5.5 base, coroutine
// and debug libraries. It lives in the registry.
type base55State struct {
	// coInfo and coThread describe the coroutine whose main loop is
	// currently executing (see co55MainLoop).
	coInfo   *co55Info
	coThread *LState
	// hook, hookMask and hookCount record the values given to
	// debug.sethook. Hooks are never called.
	hook LValue
	// upvalIDs caches the identifiers handed out by debug.upvalueid.
	upvalIDs map[*Upvalue]*LUserData
	// literalSources holds the identifiers of chunks loaded with a
	// literal ("=name") chunk name, for debug.getinfo.
	literalSources map[string]struct{}
	hookMask       string
	gcMode         string
	gcParams       [6]int64
	hookCount      int64
	warnOn         bool
	warnCont       bool
	gcStopped      bool
}

// base55StateOf returns the per-state settings, creating them on first
// use.
func base55StateOf(L *LState) *base55State {
	if ud, ok := L.G.Registry.RawGetString(base55RegistryKey).(*LUserData); ok {
		if st, ok := ud.Value.(*base55State); ok {
			return st
		}
	}
	st := &base55State{hook: LNil, gcMode: "incremental", gcParams: base55GCDefaults}
	ud := L.NewUserData()
	ud.Value = st
	L.G.Registry.RawSetString(base55RegistryKey, ud)
	return st
}

// openBase55 registers the global functions of the Lua 5.5 profile.
func openBase55(L *LState) int {
	global := L.Get(GlobalsIndex).(*LTable)
	L.SetGlobal("_G", global)
	L.SetGlobal("_VERSION", LString(luaVersion55))
	L.SetGlobal("_GOPHER_LUA_VERSION", LString(PackageName+" "+PackageVersion))
	basemod := L.RegisterModule("_G", baseFuncs55)
	next := L.NewFunction(base55Next)
	global.RawSetString("next", next)
	global.RawSetString("pairs", L.NewClosure(base55Pairs, next))
	global.RawSetString("ipairs", L.NewClosure(base55Ipairs, L.NewFunction(base55IpairsAux)))
	L.Push(basemod)
	return 1
}

var baseFuncs55 = map[string]LGFunction{
	"assert":         base55Assert,
	"collectgarbage": base55CollectGarbage,
	"dofile":         base55DoFile,
	"error":          base55Error,
	"getmetatable":   baseGetMetatable,
	"load":           base55Load,
	"loadfile":       base55LoadFile,
	"pcall":          base55PCall,
	"print":          basePrint,
	"rawequal":       base55RawEqual,
	"rawget":         base55RawGet,
	"rawlen":         base55RawLen,
	"rawset":         base55RawSet,
	"select":         base55Select,
	"_printregs":     base_PrintRegs,
	"setmetatable":   base55SetMetatable,
	"tonumber":       base55ToNumber,
	"tostring":       baseToString,
	"type":           baseType,
	"warn":           base55Warn,
	"xpcall":         base55XPCall,
	// loadlib
	"require": loRequire55,
}

// base55ArgTypeName returns the type name of argument n as used in
// argument error messages ("no value" for an absent argument).
func base55ArgTypeName(L *LState, n int) string {
	if n > L.GetTop() {
		return "no value"
	}
	return L.typeNameOf(L.Get(n))
}

// base55Where returns the "source:line: " prefix of the function running
// at the given call level (0 is the running function), or an empty string
// if that function is not a Lua function. Unlike LState.where it never
// skips Go functions and does not count tail calls as levels, which
// matches luaL_where.
func base55Where(L *LState, level int) string {
	lv, ok := debug55LevelAt(L, L, int64(level))
	if !ok || lv.frame == nil || lv.frame.Fn.IsG {
		return ""
	}
	line := debug55CurrentLine(lv.frame)
	if line <= 0 {
		return ""
	}
	return lv.frame.Fn.Proto.SourceName + ":" + strconv.Itoa(line) + ": "
}

// base55Throw raises v as an error value. String values are prefixed with
// the position of the function at the given call level; a level of zero
// adds no position.
func base55Throw(L *LState, v LValue, level int) {
	if s, ok := v.(LString); ok && level > 0 {
		v = LString(base55Where(L, level) + string(s))
	}
	L.Error(v, 0)
}

// base55Raise raises a formatted error positioned like luaL_error: the
// position of the caller is added only if the caller is a Lua function.
func base55Raise(L *LState, format string, args ...interface{}) {
	base55Throw(L, LString(fmt.Sprintf(format, args...)), 1)
}

// base55ErrorObject returns the Lua error value carried by an error
// returned from a protected call.
func base55ErrorObject(err error) LValue {
	aerr, ok := err.(*ApiError)
	if !ok {
		return LString(err.Error())
	}
	if aerr.Object == nil || aerr.Object == LNil {
		return LString(base55NoErrorObject)
	}
	return aerr.Object
}

// base55Callable reports whether v is a function or has a __call
// metamethod.
func base55Callable(L *LState, v LValue) bool {
	if v.Type() == LTFunction {
		return true
	}
	return L.metaOp1(v, "__call").Type() == LTFunction
}

// base55OptString returns argument n as a string (numbers are converted),
// or d if the argument is absent or nil.
func base55OptString(L *LState, n int, d string) string {
	if L.Get(n) == LNil {
		return d
	}
	return base55CheckString(L, n)
}

// base55CheckString returns argument n as a string; numbers are converted
// using the Lua 5.5 number formatting.
func base55CheckString(L *LState, n int) string {
	switch v := L.Get(n).(type) {
	case LString:
		return string(v)
	case LNumber, LInteger:
		return L.numToString(v)
	}
	L.TypeError(n, LTString)
	return ""
}

// base55CheckOption returns the index of the string argument n in opts.
// An absent argument selects def when def is not empty.
func base55CheckOption(L *LState, n int, def string, opts []string) int {
	var name string
	if def != "" {
		name = base55OptString(L, n, def)
	} else {
		name = base55CheckString(L, n)
	}
	for i, opt := range opts {
		if opt == name {
			return i
		}
	}
	debug55ArgError(L, n, "invalid option '"+name+"'")
	return 0
}

// base55Assert implements assert: it returns its arguments if the first one is true and
// raises the message (default "assertion failed!") otherwise.
func base55Assert(L *LState) int {
	if L.ToBool(1) {
		return L.GetTop()
	}
	L.CheckAny(1)
	var msg LValue = LString("assertion failed!")
	if L.GetTop() >= 2 {
		msg = L.Get(2)
	}
	base55Throw(L, msg, 1)
	return 0
}

// base55MemoryKB returns the size of the live Go heap in kilobytes. It is
// the closest available equivalent of the memory in use by Lua.
func base55MemoryKB() float64 {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return float64(sample[0].Value.Uint64()) / 1024
}

// switchGCMode switches the recorded collector mode and returns the
// previous one.
func (st *base55State) switchGCMode(mode string) string {
	prev := st.gcMode
	st.gcMode = mode
	return prev
}

// base55CollectGarbage implements collectgarbage with the options of Lua 5.5. Only "collect",
// "step" and "count" act on the Go collector; the other options record and
// report their settings.
func base55CollectGarbage(L *LState) int {
	st := base55StateOf(L)
	switch base55GCOptions[base55CheckOption(L, 1, "collect", base55GCOptions)] {
	case "stop":
		st.gcStopped = true
		L.Push(LInteger(0))
	case "restart":
		st.gcStopped = false
		L.Push(LInteger(0))
	case "collect":
		runtime.GC()
		L.Push(LInteger(0))
	case "count":
		L.Push(LNumber(base55MemoryKB()))
	case "step":
		L.OptInt64(2, 0)
		runtime.GC()
		L.Push(LTrue)
	case "isrunning":
		L.Push(LBool(!st.gcStopped))
	case "generational":
		L.Push(LString(st.switchGCMode("generational")))
	case "incremental":
		L.Push(LString(st.switchGCMode("incremental")))
	case "param":
		p := base55CheckOption(L, 2, "", base55GCParams)
		value := L.OptInt64(3, -1)
		L.Push(LInteger(st.gcParams[p]))
		if value >= 0 {
			st.gcParams[p] = value
		}
	}
	return 1
}

// base55Error implements error(message [, level]).
func base55Error(L *LState) int {
	level := L.OptInt(2, 1)
	base55Throw(L, L.Get(1), level)
	return 0
}

// base55IpairsAux is the iterator of ipairs. It honours __index and stops at the first nil.
func base55IpairsAux(L *LState) int {
	i := L.CheckInt64(2) + 1
	var v LValue
	switch obj := L.Get(1).(type) {
	case *LTable:
		if obj.Metatable == LNil {
			v = obj.RawGet(LInteger(i))
		} else {
			v = L.GetTable(obj, LInteger(i))
		}
	default:
		if L.metaOp1(obj, "__index") == LNil {
			base55Raise(L, "attempt to index a %s value", L.typeNameOf(obj))
		}
		v = L.GetTable(obj, LInteger(i))
	}
	if v == LNil {
		L.Push(LNil)
		return 1
	}
	L.Push(LInteger(i))
	L.Push(v)
	return 2
}

// base55Ipairs implements ipairs for any indexable value.
func base55Ipairs(L *LState) int {
	v := L.CheckAny(1)
	L.Push(L.Get(UpvalueIndex(1)))
	L.Push(v)
	L.Push(LInteger(0))
	return 3
}

// base55NextKey validates the key passed to next for tb and returns the
// key the traversal continues from. A key must be nil or a key that is,
// or was during the traversal, present in the table. Float keys with an
// integral value are never valid because tables store them as integers.
func base55NextKey(tb *LTable, key LValue) (LValue, bool) {
	var index int64
	switch k := key.(type) {
	case *LNilType:
		return key, true
	case LInteger:
		index = int64(k)
		if index >= 1 && index <= int64(tb.arrayLen()) {
			return key, true
		}
		if tb.slotGet(int(index-1)) != LNil {
			return key, true
		}
	case LNumber:
		if _, ok := floatToInteger(float64(k)); ok {
			return key, false
		}
	}
	if s, ok := key.(LString); ok {
		if tb.findField(string(s)) >= 0 {
			return key, true
		}
	} else if _, ok := tb.keyIndex(key); ok {
		return key, true
	}
	// An unboxed array part shrinks when its last element is cleared, so
	// the key of an element cleared during the traversal may lie just
	// beyond it. The traversal continues after the remaining elements.
	if alen := int64(tb.arrayLen()); tb.akind != arrayKindGeneric && index == alen+1 {
		if alen > 0 {
			key = LInteger(alen)
		}
		return key, true
	}
	return key, false
}

// base55Next implements next and rejects keys that are not part of the table.
func base55Next(L *LState) int {
	tb := L.CheckTable(1)
	key, ok := base55NextKey(tb, L.Get(2))
	if !ok {
		base55Raise(L, "invalid key to 'next'")
	}
	k, v := tb.Next(key)
	if k == LNil {
		L.Push(LNil)
		return 1
	}
	L.Push(k)
	L.Push(v)
	return 2
}

// base55Pairs implements pairs. It returns four values: the iterator, the state, the
// initial key and a closing value, as produced by __pairs or by default.
func base55Pairs(L *LState) int {
	v := L.CheckAny(1)
	if mm := L.metaOp1(v, "__pairs"); mm != LNil {
		L.Push(mm)
		L.Push(v)
		L.Call(1, 4)
		return 4
	}
	L.Push(L.Get(UpvalueIndex(1)))
	L.Push(v)
	L.Push(LNil)
	L.Push(LNil)
	return 4
}

// base55PCall implements pcall.
func base55PCall(L *LState) int {
	v := L.CheckAny(1)
	if !base55Callable(L, v) {
		L.Push(LFalse)
		L.Push(LString("attempt to call a " + L.typeNameOf(v) + " value"))
		return 2
	}
	if err := L.PCall(L.GetTop()-1, MultRet, nil); err != nil {
		co55Propagate(err)
		L.Push(LFalse)
		L.Push(base55ErrorObject(err))
		return 2
	}
	L.Insert(LTrue, 1)
	return L.GetTop()
}

// base55MsgHandler adapts the message handler of xpcall (upvalue 1). If
// the handler itself fails it is called again with its own error, like the
// reference implementation does, until it succeeds or the retry limit is
// reached.
func base55MsgHandler(L *LState) int {
	handler := L.Get(UpvalueIndex(1))
	errObj := L.Get(1)
	if co55IsCloseSignal(errObj) {
		L.Push(errObj)
		return 1
	}
	for i := 0; i < base55MaxHandlerRetries; i++ {
		L.Push(handler)
		L.Push(errObj)
		err := L.PCall(1, 1, nil)
		if err == nil {
			return 1
		}
		co55Propagate(err)
		if aerr, ok := err.(*ApiError); ok && aerr.Object != nil {
			errObj = aerr.Object
		} else {
			errObj = LString(err.Error())
		}
	}
	L.Push(LString("error in error handling"))
	return 1
}

// base55XPCall implements xpcall(f, msgh, ...).
func base55XPCall(L *LState) int {
	fn := L.Get(1)
	handler := L.NewClosure(base55MsgHandler, L.CheckFunction(2))
	top := L.GetTop()
	if !base55Callable(L, fn) {
		L.Push(handler)
		L.Push(LString("attempt to call a " + L.typeNameOf(fn) + " value"))
		L.Call(1, 1)
		ret := L.Get(-1)
		if ret == LNil {
			ret = LString(base55NoErrorObject)
		}
		L.Push(LFalse)
		L.Push(ret)
		return 2
	}
	L.Push(fn)
	for i := 3; i <= top; i++ {
		L.Push(L.Get(i))
	}
	if err := L.PCall(top-2, MultRet, handler); err != nil {
		co55Propagate(err)
		L.Push(LFalse)
		L.Push(base55ErrorObject(err))
		return 2
	}
	L.Insert(LTrue, top+1)
	return L.GetTop() - top
}

// base55RawEqual implements rawequal.
func base55RawEqual(L *LState) int {
	L.Push(LBool(L.RawEqual(L.CheckAny(1), L.CheckAny(2))))
	return 1
}

// base55RawGet implements rawget.
func base55RawGet(L *LState) int {
	tb := L.CheckTable(1)
	L.Push(tb.RawGet(L.CheckAny(2)))
	return 1
}

// base55RawLen implements rawlen for tables and strings.
func base55RawLen(L *LState) int {
	switch v := L.Get(1).(type) {
	case *LTable:
		L.Push(LInteger(v.Len()))
	case LString:
		L.Push(LInteger(len(v)))
	default:
		debug55ArgError(L, 1, "table or string expected, got "+base55ArgTypeName(L, 1))
	}
	return 1
}

// base55RawSet implements rawset.
func base55RawSet(L *LState) int {
	tb := L.CheckTable(1)
	key := L.CheckAny(2)
	value := L.CheckAny(3)
	if key == LNil {
		base55Raise(L, "table index is nil")
	}
	if n, ok := key.(LNumber); ok && math.IsNaN(float64(n)) {
		base55Raise(L, "table index is NaN")
	}
	tb.RawSet(key, value)
	L.SetTop(1)
	return 1
}

// base55Select implements select with negative indices and the '#' selector.
func base55Select(L *LState) int {
	n := L.GetTop()
	if s, ok := L.Get(1).(LString); ok && len(s) > 0 && s[0] == '#' {
		L.Push(LInteger(n - 1))
		return 1
	}
	i := L.CheckInt64(1)
	if i < 0 {
		i += int64(n)
	} else if i > int64(n) {
		i = int64(n)
	}
	if i < 1 {
		debug55ArgError(L, 1, "index out of range")
	}
	return n - int(i)
}

// base55SetMetatable implements setmetatable for tables, honouring __metatable.
func base55SetMetatable(L *LState) int {
	tb := L.CheckTable(1)
	mt := L.Get(2)
	if L.GetTop() < 2 || (mt != LNil && mt.Type() != LTTable) {
		debug55ArgError(L, 2, "nil or table expected, got "+base55ArgTypeName(L, 2))
	}
	if L.metaOp1(tb, "__metatable") != LNil {
		base55Raise(L, "cannot change a protected metatable")
	}
	tb.Metatable = mt
	L.SetTop(1)
	return 1
}

// base55Str2Int converts s to an integer in the given base (2..36),
// accepting surrounding whitespace and a sign. Overflow wraps around.
func base55Str2Int(s string, base int) (int64, bool) {
	i, n := 0, len(s)
	for i < n && isLuaSpace(s[i]) {
		i++
	}
	neg := false
	if i < n && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	var acc uint64
	start := i
	for ; i < n; i++ {
		c := s[i]
		var digit int
		switch {
		case c >= '0' && c <= '9':
			digit = int(c - '0')
		case c >= 'a' && c <= 'z':
			digit = int(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			digit = int(c-'A') + 10
		default:
			digit = -1
		}
		if digit < 0 {
			break
		}
		if digit >= base {
			return 0, false
		}
		acc = acc*uint64(base) + uint64(digit)
	}
	if i == start {
		return 0, false
	}
	for i < n && isLuaSpace(s[i]) {
		i++
	}
	if i != n {
		return 0, false
	}
	if neg {
		acc = -acc
	}
	return int64(acc), true
}

// base55ToNumber implements tonumber(v [, base]).
func base55ToNumber(L *LState) int {
	if L.Get(2) == LNil {
		switch v := L.Get(1).(type) {
		case LNumber, LInteger:
			L.Push(v)
			return 1
		case LString:
			if n, ok := str2Number55(string(v)); ok {
				L.Push(n)
				return 1
			}
		default:
			L.CheckAny(1)
		}
		L.Push(LNil)
		return 1
	}
	base := L.CheckInt64(2)
	s, ok := L.Get(1).(LString)
	if !ok {
		L.TypeError(1, LTString)
	}
	if base < 2 || base > 36 {
		debug55ArgError(L, 2, "base out of range")
	}
	if n, ok := base55Str2Int(string(s), int(base)); ok {
		L.Push(LInteger(n))
		return 1
	}
	L.Push(LNil)
	return 1
}

// warn processes one piece of a warning message. tocont tells that the
// message continues with another piece. A complete single piece message
// starting with '@' is a control message.
func (st *base55State) warn(w io.Writer, msg string, tocont bool) {
	if !st.warnCont && !tocont && strings.HasPrefix(msg, "@") {
		switch msg[1:] {
		case "off":
			st.warnOn = false
		case "on":
			st.warnOn = true
		}
		return
	}
	if !st.warnOn {
		return
	}
	if !st.warnCont {
		io.WriteString(w, "Lua warning: ")
	}
	io.WriteString(w, msg)
	st.warnCont = tocont
	if !tocont {
		io.WriteString(w, "\n")
	}
}

// base55Warn implements warn: the arguments are the pieces of one message written to
// standard error.
func base55Warn(L *LState) int {
	n := L.GetTop()
	pieces := make([]string, 0, n)
	pieces = append(pieces, base55CheckString(L, 1))
	for i := 2; i <= n; i++ {
		pieces = append(pieces, base55CheckString(L, i))
	}
	st := base55StateOf(L)
	for i, piece := range pieces {
		st.warn(os.Stderr, piece, i < len(pieces)-1)
	}
	return 0
}

/* }}} */

/* Lua 5.5 chunk loading {{{ */

// base55ChunkID renders a chunk name the way the reference implementation
// shows it in messages: "=name" is used literally, "@file" is a file name
// and anything else is quoted as [string "..."].
func base55ChunkID(source string) string {
	switch {
	case strings.HasPrefix(source, "="):
		if len(source) <= base55IDSize {
			return source[1:]
		}
		return source[1:base55IDSize]
	case strings.HasPrefix(source, "@"):
		if len(source) <= base55IDSize {
			return source[1:]
		}
		return "..." + source[len(source)-(base55IDSize-4):]
	}
	const prefix, dots, suffix = "[string \"", "...", "\"]"
	limit := base55IDSize - (len(prefix) + len(dots) + len(suffix)) - 1
	nl := strings.IndexByte(source, '\n')
	if len(source) < limit && nl < 0 {
		return prefix + source + suffix
	}
	if nl >= 0 {
		source = source[:nl]
	}
	if len(source) > limit {
		source = source[:limit]
	}
	return prefix + source + dots + suffix
}

// base55LastLine returns the line number of the end of source, counting
// line breaks like the lexer does.
func base55LastLine(source string) int {
	line := 1
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c != '\n' && c != '\r' {
			continue
		}
		line++
		if i+1 < len(source) && (source[i+1] == '\n' || source[i+1] == '\r') && source[i+1] != c {
			i++
		}
	}
	return line
}

// base55SyntaxWording maps messages of the parser and the compiler to the
// wording of the reference implementation.
var base55SyntaxWording = map[string]string{
	"unterminated string":           "unfinished string",
	"unterminated multiline string": "unfinished long string",
	"invalid multiline comment":     "unfinished long comment",
	"Invalid token":                 "unexpected symbol",
	"no loop to break":              "break outside loop near 'break'",
	"'<eof>' expected":              "<eof> expected",
}

// base55SyntaxMessage builds the Lua style message of an error returned
// by LState.Load: "chunkid:line: message near 'token'".
func base55SyntaxMessage(err error, chunkid string, source string) string {
	var aerr *ApiError
	if !errors.As(err, &aerr) {
		return err.Error()
	}
	switch cause := aerr.Cause.(type) {
	case *parse.Error:
		line := cause.Pos.Line
		token := "'" + cause.Token + "'"
		if len(cause.Token) == 1 && (cause.Token[0] < ' ' || cause.Token[0] >= 0x7f) {
			token = fmt.Sprintf("'<\\%d>'", cause.Token[0])
		}
		if line == parse.EOF || line <= 0 {
			line = base55LastLine(source)
			token = "<eof>"
		}
		if cause.Token == "<eof>" {
			token = "<eof>"
		}
		msg := cause.Message
		if wording, ok := base55SyntaxWording[msg]; ok {
			msg = wording
		}
		if i := strings.LastIndex(msg, " (to close "); i >= 0 && strings.HasSuffix(msg, fmt.Sprintf(" at line %d)", line)) {
			msg = msg[:i]
		}
		if strings.HasPrefix(msg, "unknown attribute") {
			return fmt.Sprintf("%s:%d: %s", chunkid, line, msg)
		}
		return fmt.Sprintf("%s:%d: %s near %s", chunkid, line, msg, token)
	case *CompileError:
		msg := cause.Message
		if wording, ok := base55SyntaxWording[msg]; ok {
			msg = wording
		}
		return fmt.Sprintf("%s:%d: %s", chunkid, cause.Line, msg)
	}
	return aerr.Object.String()
}

// noteLiteralSource remembers that chunkid names a chunk loaded with a
// literal chunk name. The set is bounded; it is reset when full.
func (st *base55State) noteLiteralSource(chunkid string) {
	if st.literalSources == nil || len(st.literalSources) >= base55MaxUpvalueIDs {
		st.literalSources = make(map[string]struct{})
	}
	st.literalSources[chunkid] = struct{}{}
}

// base55Compile compiles the source of a chunk. It returns the function,
// or nil and the error message.
func base55Compile(L *LState, source string, chunkname string, mode string) (*LFunction, LValue) {
	kind := "text"
	if strings.HasPrefix(source, "\x1b") {
		kind = "binary"
	}
	if !strings.Contains(mode, kind[:1]) {
		return nil, LString(fmt.Sprintf("attempt to load a %s chunk (mode is '%s')", kind, mode))
	}
	chunkid := base55ChunkID(chunkname)
	if strings.HasPrefix(chunkname, "=") {
		base55StateOf(L).noteLiteralSource(chunkid)
	}
	if kind == "binary" {
		return nil, LString(chunkid + ": bad binary format (precompiled chunks are not supported)")
	}
	fn, err := L.Load(strings.NewReader(source), chunkid)
	if err != nil {
		return nil, LString(base55SyntaxMessage(err, chunkid, source))
	}
	return fn, LNil
}

// base55SetEnv replaces the _ENV upvalue of a loaded chunk.
func base55SetEnv(fn *LFunction, env LValue) {
	if idx := int(fn.Proto.EnvUpvalue); idx >= 0 && idx < len(fn.Upvalues) {
		fn.Upvalues[idx] = &Upvalue{value: env, closed: true}
	}
}

// base55LoadResult pushes the results of load and loadfile: the function
// (with the environment given as argument envIdx, if present), or nil and
// the error message.
func base55LoadResult(L *LState, fn *LFunction, msg LValue, envIdx int) int {
	if fn == nil {
		L.Push(LNil)
		L.Push(msg)
		return 2
	}
	if envIdx <= L.GetTop() {
		base55SetEnv(fn, L.Get(envIdx))
	}
	L.Push(fn)
	return 1
}

// base55ReadChunk collects the pieces returned by the reader function of
// load. It returns false and the error value if the reader fails.
func base55ReadChunk(L *LState, reader *LFunction) (string, LValue, bool) {
	var buf strings.Builder
	for {
		L.Push(reader)
		if err := L.PCall(0, 1, nil); err != nil {
			co55Propagate(err)
			return "", base55ErrorObject(err), false
		}
		piece := L.Get(-1)
		L.Pop(1)
		switch v := piece.(type) {
		case *LNilType:
			return buf.String(), LNil, true
		case LString:
			if len(v) == 0 {
				return buf.String(), LNil, true
			}
			buf.WriteString(string(v))
		case LNumber, LInteger:
			buf.WriteString(L.numToString(v))
		default:
			return "", LString("reader function must return a string"), false
		}
	}
}

// base55Load implements load(chunk [, chunkname [, mode [, env]]]).
func base55Load(L *LState) int {
	mode := base55OptString(L, 3, "bt")
	var source, chunkname string
	switch v := L.Get(1).(type) {
	case LString, LNumber, LInteger:
		source = L.valueToString(v)
		chunkname = base55OptString(L, 2, source)
	default:
		chunkname = base55OptString(L, 2, "=(load)")
		text, errObj, ok := base55ReadChunk(L, L.CheckFunction(1))
		if !ok {
			return base55LoadResult(L, nil, errObj, 4)
		}
		source = text
	}
	fn, msg := base55Compile(L, source, chunkname, mode)
	return base55LoadResult(L, fn, msg, 4)
}

// base55FileError formats the failure of a file operation the way the C
// library reports it: "cannot <what> <filename>: <reason>".
func base55FileError(what, filename string, err error) LValue {
	reason := err.Error()
	var perr *os.PathError
	if errors.As(err, &perr) {
		reason = perr.Err.Error()
	}
	if len(reason) > 0 {
		reason = strings.ToUpper(reason[:1]) + reason[1:]
	}
	return LString(fmt.Sprintf("cannot %s %s: %s", what, filename, reason))
}

// base55CompileFile loads a chunk from a file (standard input if filename
// is empty). A leading byte order mark and a first line starting with '#'
// are skipped.
func base55CompileFile(L *LState, filename string, mode string) (*LFunction, LValue) {
	var data []byte
	var err error
	chunkname := "=stdin"
	if filename == "" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		chunkname = "@" + filename
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		what := "read"
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			what = "open"
		}
		return nil, base55FileError(what, filename, err)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(data) > 0 && data[0] == '#' {
		if nl := bytes.IndexByte(data, '\n'); nl >= 0 {
			data = data[nl:]
		} else {
			data = nil
		}
	}
	return base55Compile(L, string(data), chunkname, mode)
}

// base55LoadFile implements loadfile([filename [, mode [, env]]]).
func base55LoadFile(L *LState) int {
	filename := base55OptString(L, 1, "")
	mode := base55OptString(L, 2, "bt")
	fn, msg := base55CompileFile(L, filename, mode)
	return base55LoadResult(L, fn, msg, 3)
}

// base55DoFile implements dofile([filename]).
func base55DoFile(L *LState) int {
	filename := base55OptString(L, 1, "")
	L.SetTop(1)
	fn, msg := base55CompileFile(L, filename, "bt")
	if fn == nil {
		L.Error(msg, 0)
	}
	L.Push(fn)
	L.Call(0, MultRet)
	return L.GetTop() - 1
}

/* }}} */

//
