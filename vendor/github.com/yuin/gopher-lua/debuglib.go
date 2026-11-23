package lua

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strings"
)

func OpenDebug(L *LState) int {
	funcs := debugFuncs
	if L.is55() {
		funcs = debugFuncs55
	}
	dbgmod := L.RegisterModule(DebugLibName, funcs)
	L.Push(dbgmod)
	return 1
}

var debugFuncs = map[string]LGFunction{
	"getfenv":      debugGetFEnv,
	"getinfo":      debugGetInfo,
	"getlocal":     debugGetLocal,
	"getmetatable": debugGetMetatable,
	"getupvalue":   debugGetUpvalue,
	"setfenv":      debugSetFEnv,
	"setlocal":     debugSetLocal,
	"setmetatable": debugSetMetatable,
	"setupvalue":   debugSetUpvalue,
	"traceback":    debugTraceback,
}

func debugGetFEnv(L *LState) int {
	L.Push(L.GetFEnv(L.CheckAny(1)))
	return 1
}

func debugGetInfo(L *LState) int {
	L.CheckTypes(1, LTFunction, LTNumber)
	arg1 := L.Get(1)
	what := L.OptString(2, "Slunf")
	var dbg *Debug
	var fn LValue
	var err error
	var ok bool
	switch lv := arg1.(type) {
	case *LFunction:
		dbg = &Debug{}
		fn, err = L.GetInfo(">"+what, dbg, lv)
	case LNumber:
		dbg, ok = L.GetStack(int(lv))
		if !ok {
			L.Push(LNil)
			return 1
		}
		fn, err = L.GetInfo(what, dbg, LNil)
	}

	if err != nil {
		L.Push(LNil)
		return 1
	}
	tbl := L.NewTable()
	if len(dbg.Name) > 0 {
		tbl.RawSetString("name", LString(dbg.Name))
	} else {
		tbl.RawSetString("name", LNil)
	}
	tbl.RawSetString("what", LString(dbg.What))
	tbl.RawSetString("source", LString(dbg.Source))
	tbl.RawSetString("currentline", LNumber(dbg.CurrentLine))
	tbl.RawSetString("nups", LNumber(dbg.NUpvalues))
	tbl.RawSetString("linedefined", LNumber(dbg.LineDefined))
	tbl.RawSetString("lastlinedefined", LNumber(dbg.LastLineDefined))
	tbl.RawSetString("func", fn)
	L.Push(tbl)
	return 1
}

func debugGetLocal(L *LState) int {
	level := L.CheckInt(1)
	idx := L.CheckInt(2)
	dbg, ok := L.GetStack(level)
	if !ok {
		L.ArgError(1, "level out of range")
	}
	name, value := L.GetLocal(dbg, idx)
	if len(name) > 0 {
		L.Push(LString(name))
		L.Push(value)
		return 2
	}
	L.Push(LNil)
	return 1
}

func debugGetMetatable(L *LState) int {
	L.Push(L.GetMetatable(L.CheckAny(1)))
	return 1
}

func debugGetUpvalue(L *LState) int {
	fn := L.CheckFunction(1)
	idx := L.CheckInt(2)
	name, value := L.GetUpvalue(fn, idx)
	if len(name) > 0 {
		L.Push(LString(name))
		L.Push(value)
		return 2
	}
	L.Push(LNil)
	return 1
}

func debugSetFEnv(L *LState) int {
	L.SetFEnv(L.CheckAny(1), L.CheckAny(2))
	return 0
}

func debugSetLocal(L *LState) int {
	level := L.CheckInt(1)
	idx := L.CheckInt(2)
	value := L.CheckAny(3)
	dbg, ok := L.GetStack(level)
	if !ok {
		L.ArgError(1, "level out of range")
	}
	name := L.SetLocal(dbg, idx, value)
	if len(name) > 0 {
		L.Push(LString(name))
	} else {
		L.Push(LNil)
	}
	return 1
}

func debugSetMetatable(L *LState) int {
	L.CheckTypes(2, LTNil, LTTable)
	obj := L.Get(1)
	mt := L.Get(2)
	L.SetMetatable(obj, mt)
	L.SetTop(1)
	return 1
}

func debugSetUpvalue(L *LState) int {
	fn := L.CheckFunction(1)
	idx := L.CheckInt(2)
	value := L.CheckAny(3)
	name := L.SetUpvalue(fn, idx, value)
	if len(name) > 0 {
		L.Push(LString(name))
	} else {
		L.Push(LNil)
	}
	return 1
}

func debugTraceback(L *LState) int {
	msg := ""
	level := L.OptInt(2, 1)
	ls := L
	if L.GetTop() > 0 {
		if s, ok := L.Get(1).(LString); ok {
			msg = string(s)
		}
		if l, ok := L.Get(1).(*LState); ok {
			ls = l
			msg = ""
		}
	}

	traceback := strings.TrimSpace(ls.stackTrace(level))
	if len(msg) > 0 {
		traceback = fmt.Sprintf("%s\n%s", msg, traceback)
	}
	L.Push(LString(traceback))
	return 1
}

/* Lua 5.5 profile {{{ */

// Number of stack levels shown at the top and at the bottom of a long
// traceback (LEVELS1 and LEVELS2 of the reference implementation).
const (
	debug55TraceTop    = 10
	debug55TraceBottom = 11
)

// debug55GetInfoOptions lists the option letters accepted by
// debug.getinfo.
const debug55GetInfoOptions = "SlnrutLf"

var debugFuncs55 = map[string]LGFunction{
	"debug":        debug55Debug,
	"gethook":      debug55GetHook,
	"getinfo":      debug55GetInfo,
	"getlocal":     debug55GetLocal,
	"getmetatable": debug55GetMetatable,
	"getregistry":  debug55GetRegistry,
	"getupvalue":   debug55GetUpvalue,
	"getuservalue": debug55GetUserValue,
	"sethook":      debug55SetHook,
	"setlocal":     debug55SetLocal,
	"setmetatable": debug55SetMetatable,
	"setupvalue":   debug55SetUpvalue,
	"setuservalue": debug55SetUserValue,
	"traceback":    debug55Traceback,
	"upvalueid":    debug55UpvalueID,
	"upvaluejoin":  debug55UpvalueJoin,
}

// debug55Metamethods maps the opcodes that may call a metamethod to the
// event name reported for the called function.
var debug55Metamethods = map[int]string{
	OP_GETTABLE: "index", OP_GETTABLEKS: "index", OP_SELF: "index", OP_GETGLOBAL: "index", OP_GETENV: "index",
	OP_SETTABLE: "newindex", OP_SETTABLEKS: "newindex", OP_SETGLOBAL: "newindex", OP_SETENV: "newindex",
	OP_ADD: "add", OP_SUB: "sub", OP_MUL: "mul", OP_DIV: "div", OP_MOD: "mod", OP_POW: "pow", OP_IDIV: "idiv",
	OP_BAND: "band", OP_BOR: "bor", OP_BXOR: "bxor", OP_SHL: "shl", OP_SHR: "shr", OP_BNOT: "bnot",
	OP_UNM: "unm", OP_LEN: "len", OP_CONCAT: "concat", OP_EQ: "eq", OP_LT: "lt", OP_LE: "le",
	OP_RETURN: "close", OP_CLOSE: "close",
}

// debug55Level is one level of the call stack of a thread. A suspended
// coroutine has a synthetic top level standing for the yield function,
// which the VM has already removed from the call stack.
type debug55Level struct {
	// frame is the call frame, nil for the synthetic level.
	frame *callFrame
	// caller is the frame of the function that called this level.
	caller *callFrame
}

// fn returns the function running at the level (nil for the synthetic
// level).
func (lv debug55Level) fn() *LFunction {
	if lv.frame == nil {
		return nil
	}
	return lv.frame.Fn
}

// debug55Thread returns the thread a debug function operates on and the
// offset of its remaining arguments.
func debug55Thread(L *LState) (*LState, int) {
	if th, ok := L.Get(1).(*LState); ok {
		return th, 1
	}
	return L, 0
}

// debug55EachLevel calls visit for the stack levels of L1, starting with
// the running function, until visit returns false.
func debug55EachLevel(L *LState, L1 *LState, visit func(debug55Level) bool) {
	top := L1.currentFrame
	if top == nil {
		return
	}
	if L1 != L && co55Status(L, L1) == co55Suspended {
		if !visit(debug55Level{caller: top}) {
			return
		}
	}
	for cf := top; cf != nil; cf = cf.Parent {
		if debug55Hidden(cf) {
			continue
		}
		if !visit(debug55Level{frame: cf, caller: cf.Parent}) {
			return
		}
	}
}

// debug55MsgHandlerPC identifies the Go function that adapts the message
// handler of xpcall.
var debug55MsgHandlerPC = reflect.ValueOf(base55MsgHandler).Pointer()

// debug55Hidden reports whether a frame is an implementation detail that
// must not show up as a stack level: the adapter that xpcall puts between
// the point of an error and the message handler.
func debug55Hidden(cf *callFrame) bool {
	return cf.Fn.IsG && reflect.ValueOf(cf.Fn.GFunction).Pointer() == debug55MsgHandlerPC
}

// debug55LevelAt returns the stack level n of L1.
func debug55LevelAt(L *LState, L1 *LState, n int64) (debug55Level, bool) {
	var found debug55Level
	ok := false
	if n < 0 {
		return found, false
	}
	debug55EachLevel(L, L1, func(lv debug55Level) bool {
		if n == 0 {
			found, ok = lv, true
			return false
		}
		n--
		return true
	})
	return found, ok
}

// debug55Constant returns the string constant referenced by an RK or Bx
// operand, or "?" if the operand is not a string constant.
func debug55Constant(proto *FunctionProto, idx int) string {
	if idx >= 0 && idx < len(proto.Constants) {
		if s, ok := proto.Constants[idx].(LString); ok {
			return string(s)
		}
	}
	return "?"
}

// debug55RegisterName describes how register reg of fn was loaded before
// instruction pc. It returns the name and its kind ("local", "upvalue",
// "global", "field" or "method"), or empty strings if unknown.
func debug55RegisterName(fn *LFunction, pc int, reg int) (string, string) {
	proto := fn.Proto
	for i := pc - 1; i >= 0; i-- {
		inst := proto.Code[i]
		op, a := opGetOpCode(inst), opGetArgA(inst)
		switch op {
		case OP_CALL, OP_VARARG, OP_LOADNIL, OP_TFORLOOP:
			if a <= reg {
				return "", ""
			}
			continue
		case OP_SELF:
			if a == reg || a+1 == reg {
				return debug55RKName(proto, opGetArgC(inst), a == reg, "method")
			}
			continue
		case OP_JMP, OP_SETGLOBAL, OP_SETENV, OP_SETUPVAL, OP_SETTABLE, OP_SETTABLEKS, OP_SETLIST,
			OP_EQ, OP_LT, OP_LE, OP_TEST, OP_RETURN, OP_CLOSE, OP_NOP, OP_TBC, OP_ERRNNIL, OP_FORLOOP, OP_FORPREP:
			continue
		}
		if a != reg {
			continue
		}
		switch op {
		case OP_MOVE, OP_MOVEN:
			if name, ok := fn.LocalName(opGetArgB(inst)+1, pc); ok {
				return name, "local"
			}
		case OP_GETUPVAL:
			if b := opGetArgB(inst); b < len(proto.DbgUpvalues) {
				return proto.DbgUpvalues[b], "upvalue"
			}
		case OP_GETGLOBAL, OP_GETENV:
			return debug55Constant(proto, opGetArgBx(inst)), "global"
		case OP_GETTABLE, OP_GETTABLEKS:
			return debug55RKName(proto, opGetArgC(inst), true, "field")
		}
		return "", ""
	}
	return "", ""
}

// debug55RKName returns the name held by the RK operand of a table access
// if it is a string constant; found tells whether the access loaded the
// register of interest.
func debug55RKName(proto *FunctionProto, rk int, found bool, kind string) (string, string) {
	if !found {
		return "", ""
	}
	if !opIsK(rk) {
		return "?", kind
	}
	return debug55Constant(proto, opIndexK(rk)), kind
}

// debug55CalleeName derives the name and the kind of the function that
// the Lua function in frame caller is currently calling, from the
// instruction being executed.
func debug55CalleeName(caller *callFrame) (string, string) {
	if caller == nil || caller.Fn.IsG {
		return "", ""
	}
	proto := caller.Fn.Proto
	pc := caller.Pc - 1
	if pc < 0 || pc >= len(proto.Code) {
		return "", ""
	}
	inst := proto.Code[pc]
	switch op := opGetOpCode(inst); op {
	case OP_CALL, OP_TAILCALL:
		return debug55RegisterName(caller.Fn, pc, opGetArgA(inst))
	case OP_TFORLOOP:
		return "for iterator", "for iterator"
	default:
		if event, ok := debug55Metamethods[op]; ok {
			return event, "metamethod"
		}
	}
	return "", ""
}

// debug55LevelName returns the name and the kind of the function at a
// stack level.
func debug55LevelName(lv debug55Level) (string, string) {
	if lv.frame != nil && !lv.frame.Fn.IsG && lv.frame.TailCall > 0 {
		return "", ""
	}
	return debug55CalleeName(lv.caller)
}

// debug55CurrentLine returns the line being executed in frame, or -1.
func debug55CurrentLine(frame *callFrame) int {
	if frame == nil || frame.Fn.IsG {
		return -1
	}
	positions := frame.Fn.Proto.DbgSourcePositions
	if pc := frame.Pc - 1; pc >= 0 && pc < len(positions) {
		return positions[pc]
	}
	return -1
}

// debug55Source returns the source and short_src fields of a function.
func debug55Source(L *LState, fn *LFunction) (string, string) {
	if fn == nil || fn.IsG {
		return "=[C]", "[C]"
	}
	short := fn.Proto.SourceName
	if _, literal := base55StateOf(L).literalSources[short]; literal || strings.HasPrefix(short, "[string \"") {
		return "=" + short, short
	}
	return "@" + short, short
}

// debug55What classifies a function as "C", "main" or "Lua".
func debug55What(fn *LFunction) string {
	switch {
	case fn == nil || fn.IsG:
		return "C"
	case fn.Proto.LineDefined == 0:
		return "main"
	}
	return "Lua"
}

// debug55ActiveLines returns the set of lines of a Lua function that
// carry code.
func debug55ActiveLines(L *LState, fn *LFunction) LValue {
	if fn == nil || fn.IsG {
		return LNil
	}
	lines := L.NewTable()
	for _, line := range fn.Proto.DbgSourcePositions {
		if line > 0 {
			lines.RawSetInt(line, LTrue)
		}
	}
	return lines
}

// debug55FillInfo stores the fields selected by what into tb.
func debug55FillInfo(L *LState, tb *LTable, what string, fn *LFunction, lv debug55Level) {
	for _, opt := range what {
		switch opt {
		case 'S':
			source, short := debug55Source(L, fn)
			tb.RawSetString("source", LString(source))
			tb.RawSetString("short_src", LString(short))
			linedefined, lastlinedefined := -1, -1
			if fn != nil && !fn.IsG {
				linedefined, lastlinedefined = fn.Proto.LineDefined, fn.Proto.LastLineDefined
				if linedefined == 0 {
					lastlinedefined = 0
				}
			}
			tb.RawSetString("linedefined", LInteger(linedefined))
			tb.RawSetString("lastlinedefined", LInteger(lastlinedefined))
			tb.RawSetString("what", LString(debug55What(fn)))
		case 'l':
			tb.RawSetString("currentline", LInteger(debug55CurrentLine(lv.frame)))
		case 'u':
			nups, nparams, isvararg := 0, 0, true
			if fn != nil {
				nups = len(fn.Upvalues)
				if !fn.IsG {
					nparams = int(fn.Proto.NumParameters)
					isvararg = fn.Proto.IsVarArg != 0
				}
			}
			tb.RawSetString("nups", LInteger(nups))
			tb.RawSetString("nparams", LInteger(nparams))
			tb.RawSetString("isvararg", LBool(isvararg))
		case 'n':
			name, namewhat := debug55LevelName(lv)
			if namewhat != "" {
				tb.RawSetString("name", LString(name))
			}
			tb.RawSetString("namewhat", LString(namewhat))
		case 'r':
			tb.RawSetString("ftransfer", LInteger(0))
			tb.RawSetString("ntransfer", LInteger(0))
		case 't':
			tb.RawSetString("istailcall", LBool(lv.frame != nil && !lv.frame.Fn.IsG && lv.frame.TailCall > 0))
			tb.RawSetString("extraargs", LInteger(0))
		case 'L':
			tb.RawSetString("activelines", debug55ActiveLines(L, fn))
		case 'f':
			if fn != nil {
				tb.RawSetString("func", fn)
			}
		}
	}
}

// debug55GetInfo implements debug.getinfo([thread,] f [, what]).
func debug55GetInfo(L *LState) int {
	L1, arg := debug55Thread(L)
	what := base55OptString(L, arg+2, "flnSrtu")
	if strings.HasPrefix(what, ">") {
		debug55ArgError(L, arg+2, "invalid option '>'")
	}
	var lv debug55Level
	fn, isfn := L.Get(arg + 1).(*LFunction)
	if !isfn {
		var ok bool
		if lv, ok = debug55LevelAt(L, L1, L.CheckInt64(arg+1)); !ok {
			L.Push(LNil)
			return 1
		}
		fn = lv.fn()
	}
	if strings.Trim(what, debug55GetInfoOptions) != "" {
		debug55ArgError(L, arg+2, "invalid option")
	}
	tb := L.NewTable()
	debug55FillInfo(L, tb, what, fn, lv)
	L.Push(tb)
	return 1
}

// debug55Local returns the name and the registry index of local variable
// n of a stack level. Negative numbers select the extra arguments of a
// vararg function.
func debug55Local(L1 *LState, lv debug55Level, n int) (string, int, bool) {
	frame := lv.frame
	if frame == nil || n == 0 {
		return "", 0, false
	}
	if n < 0 {
		if frame.Fn.IsG || frame.Fn.Proto.IsVarArg == 0 {
			return "", 0, false
		}
		nparams := int(frame.Fn.Proto.NumParameters)
		if -n > frame.NArgs-nparams {
			return "", 0, false
		}
		return "(vararg)", frame.Base + nparams - n, true
	}
	name := L1.findLocal(frame, n)
	switch {
	case name == "":
		return "", 0, false
	case name != "(*temporary)":
	case frame.Fn.IsG:
		name = "(C temporary)"
	default:
		name = "(temporary)"
	}
	return name, frame.LocalBase + n - 1, true
}

// debug55ParamName returns the name of parameter n of a Lua function.
func debug55ParamName(fn *LFunction, n int) (string, bool) {
	if fn.IsG || n < 1 || n > int(fn.Proto.NumParameters) || n > len(fn.Proto.DbgLocals) {
		return "", false
	}
	return fn.Proto.DbgLocals[n-1].Name, true
}

// debug55GetLocal implements debug.getlocal([thread,] f, local).
func debug55GetLocal(L *LState) int {
	L1, arg := debug55Thread(L)
	n := L.CheckInt(arg + 2)
	if fn, ok := L.Get(arg + 1).(*LFunction); ok {
		if name, ok := debug55ParamName(fn, n); ok {
			L.Push(LString(name))
		} else {
			L.Push(LNil)
		}
		return 1
	}
	lv, ok := debug55LevelAt(L, L1, L.CheckInt64(arg+1))
	if !ok {
		debug55ArgError(L, arg+1, "level out of range")
	}
	name, reg, ok := debug55Local(L1, lv, n)
	if !ok {
		L.Push(LNil)
		return 1
	}
	L.Push(LString(name))
	L.Push(L1.reg.Get(reg))
	return 2
}

// debug55SetLocal implements debug.setlocal([thread,] level, local, value).
func debug55SetLocal(L *LState) int {
	L1, arg := debug55Thread(L)
	level := L.CheckInt64(arg + 1)
	n := L.CheckInt(arg + 2)
	lv, ok := debug55LevelAt(L, L1, level)
	if !ok {
		debug55ArgError(L, arg+1, "level out of range")
	}
	value := L.CheckAny(arg + 3)
	name, reg, ok := debug55Local(L1, lv, n)
	if !ok {
		L.Push(LNil)
		return 1
	}
	L1.reg.Set(reg, value)
	L1.jitLocalChanged()
	L.Push(LString(name))
	return 1
}

// debug55GetMetatable implements debug.getmetatable, ignoring __metatable.
func debug55GetMetatable(L *LState) int {
	L.Push(L.metatable(L.CheckAny(1), true))
	return 1
}

// debug55SetMetatable implements debug.setmetatable for values of any type.
func debug55SetMetatable(L *LState) int {
	mt := L.Get(2)
	if L.GetTop() < 2 || (mt != LNil && mt.Type() != LTTable) {
		debug55ArgError(L, 2, "nil or table expected, got "+base55ArgTypeName(L, 2))
	}
	L.SetMetatable(L.Get(1), mt)
	L.SetTop(1)
	return 1
}

// debug55GetRegistry implements debug.getregistry.
func debug55GetRegistry(L *LState) int {
	L.Push(L.Get(RegistryIndex))
	return 1
}

// debug55Upvalue returns upvalue n of fn and its name. Upvalues of Go
// functions have an empty name.
func debug55Upvalue(fn *LFunction, n int) (*Upvalue, string, bool) {
	if n < 1 || n > len(fn.Upvalues) || fn.Upvalues[n-1] == nil {
		return nil, "", false
	}
	name := ""
	if !fn.IsG && n <= len(fn.Proto.DbgUpvalues) {
		name = fn.Proto.DbgUpvalues[n-1]
	}
	return fn.Upvalues[n-1], name, true
}

// debug55GetUpvalue implements debug.getupvalue. It returns nothing for an invalid index.
func debug55GetUpvalue(L *LState) int {
	n := L.CheckInt(2)
	uv, name, ok := debug55Upvalue(L.CheckFunction(1), n)
	if !ok {
		return 0
	}
	L.Push(LString(name))
	L.Push(uv.Value())
	return 2
}

// debug55SetUpvalue implements debug.setupvalue. It returns nothing for an invalid index.
func debug55SetUpvalue(L *LState) int {
	value := L.CheckAny(3)
	n := L.CheckInt(2)
	uv, name, ok := debug55Upvalue(L.CheckFunction(1), n)
	if !ok {
		return 0
	}
	uv.SetValue(value)
	L.Push(LString(name))
	return 1
}

// debug55CheckUpvalue returns the upvalue selected by the function
// argument argf and the index argument argn.
func debug55CheckUpvalue(L *LState, argf, argn int) (*LFunction, int, *Upvalue) {
	n := L.CheckInt(argn)
	fn := L.CheckFunction(argf)
	uv, _, _ := debug55Upvalue(fn, n)
	return fn, n, uv
}

// debug55UpvalueID implements debug.upvalueid. Identifiers are cached so that the same
// upvalue yields the same userdata; the cache is bounded and reset when
// full.
func debug55UpvalueID(L *LState) int {
	_, _, uv := debug55CheckUpvalue(L, 1, 2)
	if uv == nil {
		L.Push(LNil)
		return 1
	}
	st := base55StateOf(L)
	id, ok := st.upvalIDs[uv]
	if !ok {
		if st.upvalIDs == nil || len(st.upvalIDs) >= base55MaxUpvalueIDs {
			st.upvalIDs = make(map[*Upvalue]*LUserData)
		}
		id = &LUserData{Value: uv, Metatable: LNil}
		st.upvalIDs[uv] = id
	}
	L.Push(id)
	return 1
}

// debug55UpvalueJoin implements debug.upvaluejoin(f1, n1, f2, n2).
func debug55UpvalueJoin(L *LState) int {
	fn1, n1, uv1 := debug55CheckUpvalue(L, 1, 2)
	if uv1 == nil {
		debug55ArgError(L, 2, "invalid upvalue index")
	}
	fn2, _, uv2 := debug55CheckUpvalue(L, 3, 4)
	if uv2 == nil {
		debug55ArgError(L, 4, "invalid upvalue index")
	}
	if fn1.IsG {
		debug55ArgError(L, 1, "Lua function expected")
	}
	if fn2.IsG {
		debug55ArgError(L, 3, "Lua function expected")
	}
	fn1.Upvalues[n1-1] = uv2
	return 0
}

// debug55GetUserValue implements debug.getuservalue. Userdata have no user values here, so the
// result is always nil.
func debug55GetUserValue(L *LState) int {
	L.OptInt(2, 1)
	L.Push(LNil)
	return 1
}

// debug55SetUserValue implements debug.setuservalue. Userdata have no user values here, so the
// call fails by returning nil.
func debug55SetUserValue(L *LState) int {
	L.OptInt(3, 1)
	L.CheckUserData(1)
	L.CheckAny(2)
	L.Push(LNil)
	return 1
}

// debug55HookMask keeps the event letters of a hook mask in canonical
// order.
func debug55HookMask(mask string) string {
	var b strings.Builder
	for _, c := range "crl" {
		if strings.ContainsRune(mask, c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// debug55SetHook records the hook. Hooks are not supported by the VM and
// are never called.
func debug55SetHook(L *LState) int {
	_, arg := debug55Thread(L)
	st := base55StateOf(L)
	if L.Get(arg+1) == LNil {
		st.hook, st.hookMask, st.hookCount = LNil, "", 0
		return 0
	}
	mask := base55CheckString(L, arg+2)
	hook := L.CheckFunction(arg + 1)
	st.hook, st.hookMask, st.hookCount = hook, debug55HookMask(mask), L.OptInt64(arg+3, 0)
	return 0
}

// debug55GetHook implements debug.gethook: it reports the values recorded by
// debug55SetHook.
func debug55GetHook(L *LState) int {
	st := base55StateOf(L)
	if st.hook == LNil {
		L.Push(LNil)
		return 1
	}
	L.Push(st.hook)
	L.Push(LString(st.hookMask))
	L.Push(LInteger(st.hookCount))
	return 3
}

// debug55Debug is a minimal interactive console: it runs each line read
// from standard input until a line containing only "cont".
func debug55Debug(L *LState) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, "lua_debug> ")
		line, err := reader.ReadString('\n')
		if strings.TrimRight(line, "\r\n") == "cont" || (err != nil && line == "") {
			return 0
		}
		fn, msg := base55Compile(L, line, "=(debug command)", "t")
		if fn == nil {
			fmt.Fprintln(os.Stderr, msg.String())
			continue
		}
		L.Push(fn)
		if err := L.PCall(0, 0, nil); err != nil {
			co55Propagate(err)
			fmt.Fprintln(os.Stderr, L.ToStringMeta(base55ErrorObject(err)).String())
		}
	}
}

// debug55GlobalFuncName searches the loaded modules for fn and returns
// its qualified name ("string.rep", "print", ...).
func debug55GlobalFuncName(L *LState, fn *LFunction) (string, bool) {
	loaded, ok := L.G.Registry.RawGetString("_LOADED").(*LTable)
	if !ok {
		return "", false
	}
	name, found := "", false
	loaded.ForEach(func(modname, mod LValue) {
		tb, ok := mod.(*LTable)
		if !ok || found {
			return
		}
		tb.ForEach(func(key, value LValue) {
			if key.Type() != LTString || found || value != LValue(fn) {
				return
			}
			name, found = modname.String()+"."+key.String(), true
		})
	})
	return strings.TrimPrefix(name, "_G."), found
}

// debug55ArgError raises the error for a bad argument n of the running Go
// function. The function is named like luaL_argerror does: by the name
// used at the call site if there is one, else by its qualified name in the
// loaded modules. The implicit self argument of a method call is not
// counted.
func debug55ArgError(L *LState, n int, message string) {
	frame := L.currentFrame
	name, namewhat := debug55LevelName(debug55Level{frame: frame, caller: frame.Parent})
	if namewhat == "method" {
		n--
		if n == 0 {
			base55Raise(L, "calling '%s' on bad self (%s)", name, message)
		}
	}
	if namewhat == "" {
		name = "?"
		if global, ok := debug55GlobalFuncName(L, frame.Fn); ok {
			name = global
		}
	}
	base55Raise(L, "bad argument #%d to '%s' (%s)", n, name, message)
}

// debug55FuncDescription describes the function of a stack level for a
// traceback line.
func debug55FuncDescription(L *LState, lv debug55Level) string {
	fn := lv.fn()
	if name, namewhat := debug55LevelName(lv); namewhat != "" {
		return namewhat + " '" + name + "'"
	}
	switch debug55What(fn) {
	case "main":
		return "main chunk"
	case "Lua":
		return fmt.Sprintf("function <%s:%d>", fn.Proto.SourceName, fn.Proto.LineDefined)
	}
	if fn != nil {
		if name, ok := debug55GlobalFuncName(L, fn); ok {
			return "function '" + name + "'"
		}
	}
	return "?"
}

// debug55BuildTraceback renders the call stack of L1 from the given level
// in the layout of luaL_traceback.
func debug55BuildTraceback(L *LState, L1 *LState, msg string, hasMsg bool, level int) string {
	var levels []debug55Level
	debug55EachLevel(L, L1, func(lv debug55Level) bool {
		levels = append(levels, lv)
		return true
	})
	var b strings.Builder
	if hasMsg {
		b.WriteString(msg)
		b.WriteByte('\n')
	}
	b.WriteString("stack traceback:")
	if level < 0 {
		return b.String()
	}
	last := len(levels) - 1
	limit := -1
	if last-level > debug55TraceTop+debug55TraceBottom {
		limit = debug55TraceTop
	}
	for i := level; i < len(levels); i++ {
		if limit == 0 {
			skip := last - i - debug55TraceBottom
			fmt.Fprintf(&b, "\n\t...\t(skipping %d levels)", skip)
			i += skip
			limit--
			continue
		}
		limit--
		lv := levels[i]
		_, short := debug55Source(L, lv.fn())
		if line := debug55CurrentLine(lv.frame); line > 0 {
			fmt.Fprintf(&b, "\n\t%s:%d: in ", short, line)
		} else {
			fmt.Fprintf(&b, "\n\t%s: in ", short)
		}
		b.WriteString(debug55FuncDescription(L, lv))
		if lv.frame != nil && !lv.frame.Fn.IsG && lv.frame.TailCall > 0 {
			b.WriteString("\n\t(...tail calls...)")
		}
	}
	return b.String()
}

// debug55Traceback implements debug.traceback([thread,] [message [, level]]).
func debug55Traceback(L *LState) int {
	L1, arg := debug55Thread(L)
	msg, hasMsg := "", false
	switch v := L.Get(arg + 1).(type) {
	case LString:
		msg, hasMsg = string(v), true
	case LNumber, LInteger:
		msg, hasMsg = L.numToString(v), true
	case *LNilType:
	default:
		L.Push(v)
		return 1
	}
	level := 0
	if L1 == L {
		level = 1
	}
	level = L.OptInt(arg+2, level)
	L.Push(LString(debug55BuildTraceback(L, L1, msg, hasMsg, level)))
	return 1
}

/* }}} */
