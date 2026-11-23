package lua

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

/* checkType {{{ */

func (ls *LState) CheckAny(n int) LValue {
	if n > ls.GetTop() {
		ls.ArgError(n, "value expected")
	}
	return ls.Get(n)
}

// argInteger converts an argument value to an integer following the
// language profile: Lua 5.1 truncates floats, Lua 5.5 requires an exact
// integer representation and coerces numeric strings.
func (ls *LState) argInteger(n int, v LValue) (int64, bool) {
	switch iv := v.(type) {
	case LInteger:
		return int64(iv), true
	case LNumber:
		if !ls.lang55 {
			return int64(iv), true
		}
		if i, ok := floatToInteger(float64(iv)); ok {
			return i, true
		}
		ls.ArgError(n, "number has no integer representation")
	case LString:
		if ls.lang55 {
			if num, ok := str2Number55(string(iv)); ok {
				return ls.argInteger(n, num)
			}
		}
	}
	return 0, false
}

func (ls *LState) CheckInt(n int) int {
	if i, ok := ls.argInteger(n, ls.Get(n)); ok {
		return int(i)
	}
	ls.TypeError(n, LTNumber)
	return 0
}

// CheckInteger checks that argument n is a number with an integer
// representation and returns it as an LInteger.
func (ls *LState) CheckInteger(n int) LInteger {
	if i, ok := ls.argInteger(n, ls.Get(n)); ok {
		return LInteger(i)
	}
	ls.TypeError(n, LTNumber)
	return 0
}

// OptInteger returns argument n as an LInteger, or d if it is absent.
func (ls *LState) OptInteger(n int, d LInteger) LInteger {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if i, ok := ls.argInteger(n, v); ok {
		return LInteger(i)
	}
	ls.TypeError(n, LTNumber)
	return 0
}

// ToInteger converts the value at index n to an LInteger. The second
// result is false if the value is not a number with an exact integer
// representation.
func (ls *LState) ToInteger(n int) (LInteger, bool) {
	i, ok := LVAsInteger(ls.Get(n))
	return LInteger(i), ok
}

func (ls *LState) CheckInt64(n int) int64 {
	if i, ok := ls.argInteger(n, ls.Get(n)); ok {
		return i
	}
	ls.TypeError(n, LTNumber)
	return 0
}

func (ls *LState) CheckNumber(n int) LNumber {
	v := ls.Get(n)
	if lv, ok := v.(LNumber); ok {
		return lv
	}
	if lv, ok := v.(LInteger); ok {
		return LNumber(lv)
	}
	if lv, ok := v.(LString); ok {
		if num, ok := ls.strToNumber(string(lv)); ok {
			return LVAsNumber(num)
		}
	}
	ls.TypeError(n, LTNumber)
	return 0
}

// CheckNumberValue checks that argument n is a number (or a string
// convertible to a number) and returns it preserving its subtype
// (LInteger or LNumber).
func (ls *LState) CheckNumberValue(n int) LValue {
	if num, ok := ls.toNumberValue(ls.Get(n)); ok {
		return num
	}
	ls.TypeError(n, LTNumber)
	return LNil
}

func (ls *LState) CheckString(n int) string {
	v := ls.Get(n)
	if lv, ok := v.(LString); ok {
		return string(lv)
	} else if LVCanConvToString(v) {
		return ls.valueToString(v)
	}
	ls.TypeError(n, LTString)
	return ""
}

func (ls *LState) CheckBool(n int) bool {
	v := ls.Get(n)
	if lv, ok := v.(LBool); ok {
		return bool(lv)
	}
	ls.TypeError(n, LTBool)
	return false
}

func (ls *LState) CheckTable(n int) *LTable {
	v := ls.Get(n)
	if lv, ok := v.(*LTable); ok {
		return lv
	}
	ls.TypeError(n, LTTable)
	return nil
}

func (ls *LState) CheckFunction(n int) *LFunction {
	v := ls.Get(n)
	if lv, ok := v.(*LFunction); ok {
		return lv
	}
	ls.TypeError(n, LTFunction)
	return nil
}

func (ls *LState) CheckUserData(n int) *LUserData {
	v := ls.Get(n)
	if lv, ok := v.(*LUserData); ok {
		return lv
	}
	ls.TypeError(n, LTUserData)
	return nil
}

func (ls *LState) CheckThread(n int) *LState {
	v := ls.Get(n)
	if lv, ok := v.(*LState); ok {
		return lv
	}
	ls.TypeError(n, LTThread)
	return nil
}

func (ls *LState) CheckType(n int, typ LValueType) {
	v := ls.Get(n)
	if v.Type() != typ {
		ls.TypeError(n, typ)
	}
}

func (ls *LState) CheckTypes(n int, typs ...LValueType) {
	vt := ls.Get(n).Type()
	for _, typ := range typs {
		if vt == typ {
			return
		}
	}
	buf := []string{}
	for _, typ := range typs {
		buf = append(buf, typ.String())
	}
	ls.ArgError(n, strings.Join(buf, " or ")+" expected, got "+ls.Get(n).Type().String())
}

func (ls *LState) CheckOption(n int, options []string) int {
	str := ls.CheckString(n)
	for i, v := range options {
		if v == str {
			return i
		}
	}
	if ls.lang55 {
		ls.ArgError(n, fmt.Sprintf("invalid option '%s'", str))
	}
	ls.ArgError(n, fmt.Sprintf("invalid option: %s (must be one of %s)", str, strings.Join(options, ",")))
	return 0
}

/* }}} */

/* optType {{{ */

func (ls *LState) OptInt(n int, d int) int {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if i, ok := ls.argInteger(n, v); ok {
		return int(i)
	}
	ls.TypeError(n, LTNumber)
	return 0
}

func (ls *LState) OptInt64(n int, d int64) int64 {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if i, ok := ls.argInteger(n, v); ok {
		return i
	}
	ls.TypeError(n, LTNumber)
	return 0
}

func (ls *LState) OptNumber(n int, d LNumber) LNumber {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if lv, ok := v.(LNumber); ok {
		return lv
	}
	if lv, ok := v.(LInteger); ok {
		return LNumber(lv)
	}
	ls.TypeError(n, LTNumber)
	return 0
}

func (ls *LState) OptString(n int, d string) string {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if lv, ok := v.(LString); ok {
		return string(lv)
	}
	if ls.lang55 && LVCanConvToString(v) {
		return ls.valueToString(v)
	}
	ls.TypeError(n, LTString)
	return ""
}

func (ls *LState) OptBool(n int, d bool) bool {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if lv, ok := v.(LBool); ok {
		return bool(lv)
	}
	ls.TypeError(n, LTBool)
	return false
}

func (ls *LState) OptTable(n int, d *LTable) *LTable {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if lv, ok := v.(*LTable); ok {
		return lv
	}
	ls.TypeError(n, LTTable)
	return nil
}

func (ls *LState) OptFunction(n int, d *LFunction) *LFunction {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if lv, ok := v.(*LFunction); ok {
		return lv
	}
	ls.TypeError(n, LTFunction)
	return nil
}

func (ls *LState) OptUserData(n int, d *LUserData) *LUserData {
	v := ls.Get(n)
	if v == LNil {
		return d
	}
	if lv, ok := v.(*LUserData); ok {
		return lv
	}
	ls.TypeError(n, LTUserData)
	return nil
}

/* }}} */

/* error operations {{{ */

func (ls *LState) ArgError(n int, message string) {
	if ls.lang55 {
		debug55ArgError(ls, n, message)
	}
	ls.RaiseError("bad argument #%v to %v (%v)", n, ls.rawFrameFuncName(ls.currentFrame), message)
}

func (ls *LState) TypeError(n int, typ LValueType) {
	if ls.lang55 {
		got := "no value"
		if n <= ls.GetTop() {
			got = ls.typeNameOf(ls.Get(n))
		}
		debug55ArgError(ls, n, fmt.Sprintf("%v expected, got %v", typ.String(), got))
	}
	ls.RaiseError("bad argument #%v to %v (%v expected, got %v)", n, ls.rawFrameFuncName(ls.currentFrame), typ.String(), ls.Get(n).Type().String())
}

/* }}} */

/* debug operations {{{ */

func (ls *LState) Where(level int) string {
	return ls.where(level, false)
}

/* }}} */

/* table operations {{{ */

func (ls *LState) FindTable(obj *LTable, n string, size int) LValue {
	names := strings.Split(n, ".")
	curobj := obj
	for _, name := range names {
		if curobj.Type() != LTTable {
			return LNil
		}
		nextobj := ls.RawGet(curobj, LString(name))
		if nextobj == LNil {
			tb := ls.CreateTable(0, size)
			ls.RawSet(curobj, LString(name), tb)
			curobj = tb
		} else if nextobj.Type() != LTTable {
			return LNil
		} else {
			curobj = nextobj.(*LTable)
		}
	}
	return curobj
}

/* }}} */

/* register operations {{{ */

func (ls *LState) RegisterModule(name string, funcs map[string]LGFunction) LValue {
	tb := ls.FindTable(ls.Get(RegistryIndex).(*LTable), "_LOADED", 1)
	mod := ls.GetField(tb, name)
	if mod.Type() != LTTable {
		newmod := ls.FindTable(ls.Get(GlobalsIndex).(*LTable), name, len(funcs))
		if newmodtb, ok := newmod.(*LTable); !ok {
			ls.RaiseError("name conflict for module(%v)", name)
		} else {
			for fname, fn := range funcs {
				newmodtb.RawSetString(fname, ls.NewFunction(fn))
			}
			ls.SetField(tb, name, newmodtb)
			return newmodtb
		}
	}
	return mod
}

func (ls *LState) SetFuncs(tb *LTable, funcs map[string]LGFunction, upvalues ...LValue) *LTable {
	tb.reserveFields(len(funcs))
	for fname, fn := range funcs {
		tb.RawSetString(fname, ls.NewClosure(fn, upvalues...))
	}
	return tb
}

/* }}} */

/* metatable operations {{{ */

func (ls *LState) NewTypeMetatable(typ string) *LTable {
	regtable := ls.Get(RegistryIndex)
	mt := ls.GetField(regtable, typ)
	if tb, ok := mt.(*LTable); ok {
		return tb
	}
	mtnew := ls.NewTable()
	ls.SetField(regtable, typ, mtnew)
	return mtnew
}

func (ls *LState) GetMetaField(obj LValue, event string) LValue {
	return ls.metaOp1(obj, event)
}

func (ls *LState) GetTypeMetatable(typ string) LValue {
	return ls.GetField(ls.Get(RegistryIndex), typ)
}

func (ls *LState) CallMeta(obj LValue, event string) LValue {
	op := ls.metaOp1(obj, event)
	if op.Type() == LTFunction {
		ls.reg.Push(op)
		ls.reg.Push(obj)
		ls.Call(1, 1)
		return ls.reg.Pop()
	}
	return LNil
}

/* }}} */

/* load and function call operations {{{ */

func (ls *LState) LoadFile(path string) (*LFunction, error) {
	var file *os.File
	var err error
	if len(path) == 0 {
		file = os.Stdin
	} else {
		file, err = os.Open(path)
		defer file.Close()
		if err != nil {
			return nil, newApiErrorE(ApiErrorFile, err)
		}
	}

	reader := bufio.NewReader(file)
	// get the first character.
	c, err := reader.ReadByte()
	if err != nil && err != io.EOF {
		return nil, newApiErrorE(ApiErrorFile, err)
	}
	if c == byte('#') {
		// Unix exec. file?
		// skip first line
		_, err, _ = readBufioLine(reader)
		if err != nil {
			return nil, newApiErrorE(ApiErrorFile, err)
		}
	}

	if err != io.EOF {
		// if the file is not empty,
		// unread the first character of the file or newline character(readBufioLine's last byte).
		err = reader.UnreadByte()
		if err != nil {
			return nil, newApiErrorE(ApiErrorFile, err)
		}
	}

	return ls.Load(reader, path)
}

func (ls *LState) LoadString(source string) (*LFunction, error) {
	return ls.Load(strings.NewReader(source), "<string>")
}

func (ls *LState) DoFile(path string) error {
	if fn, err := ls.LoadFile(path); err != nil {
		return err
	} else {
		ls.Push(fn)
		return ls.PCall(0, MultRet, nil)
	}
}

func (ls *LState) DoString(source string) error {
	if fn, err := ls.LoadString(source); err != nil {
		return err
	} else {
		ls.Push(fn)
		return ls.PCall(0, MultRet, nil)
	}
}

/* }}} */

/* GopherLua original APIs {{{ */

// ToStringMeta returns string representation of given LValue.
// This method calls the `__tostring` meta method if defined.
func (ls *LState) ToStringMeta(lv LValue) LValue {
	if fn, ok := ls.metaOp1(lv, "__tostring").(*LFunction); ok {
		ls.Push(fn)
		ls.Push(lv)
		ls.Call(1, 1)
		ret := ls.reg.Pop()
		if ls.lang55 {
			switch ret.(type) {
			case LString:
			case LNumber, LInteger:
				return LString(ls.numToString(ret))
			default:
				ls.RaiseError("'__tostring' must return a string")
			}
		}
		return ret
	}
	switch v := lv.(type) {
	case LNumber, LInteger:
		return LString(ls.numToString(v))
	case *LTable, *LUserData:
		if ls.lang55 {
			if mt, ok := ls.metatable(lv, true).(*LTable); ok {
				if name, ok := mt.RawGetString("__name").(LString); ok {
					return LString(fmt.Sprintf("%s: %p", string(name), lv))
				}
			}
		}
	}
	return LString(lv.String())
}

// Set a module loader to the package.preload table.
func (ls *LState) PreloadModule(name string, loader LGFunction) {
	preload := ls.GetField(ls.GetField(ls.Get(EnvironIndex), "package"), "preload")
	if _, ok := preload.(*LTable); !ok {
		ls.RaiseError("package.preload must be a table")
	}
	ls.SetField(preload, name, ls.NewFunction(loader))
}

// Checks whether the given index is an LChannel and returns this channel.
func (ls *LState) CheckChannel(n int) chan LValue {
	v := ls.Get(n)
	if ch, ok := v.(LChannel); ok {
		return (chan LValue)(ch)
	}
	ls.TypeError(n, LTChannel)
	return nil
}

// If the given index is a LChannel, returns this channel. If this argument is absent or is nil, returns ch. Otherwise, raises an error.
func (ls *LState) OptChannel(n int, ch chan LValue) chan LValue {
	v := ls.Get(n)
	if v == LNil {
		return ch
	}
	if ch, ok := v.(LChannel); ok {
		return (chan LValue)(ch)
	}
	ls.TypeError(n, LTChannel)
	return nil
}

/* }}} */

//
