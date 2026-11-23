package lua

import (
	"context"
	"fmt"
	"os"
)

type LValueType int

const (
	LTNil LValueType = iota
	LTBool
	LTNumber
	LTString
	LTFunction
	LTUserData
	LTThread
	LTTable
	LTChannel
)

var lValueNames = [9]string{"nil", "boolean", "number", "string", "function", "userdata", "thread", "table", "channel"}

func (vt LValueType) String() string {
	return lValueNames[int(vt)]
}

type LValue interface {
	String() string
	Type() LValueType
}

// LVIsFalse returns true if a given LValue is a nil or false otherwise false.
func LVIsFalse(v LValue) bool { return v == LNil || v == LFalse }

// LVIsFalse returns false if a given LValue is a nil or false otherwise true.
func LVAsBool(v LValue) bool { return v != LNil && v != LFalse }

// LVAsString returns string representation of a given LValue
// if the LValue is a string or number, otherwise an empty string.
func LVAsString(v LValue) string {
	switch sn := v.(type) {
	case LString, LNumber, LInteger:
		return sn.String()
	default:
		return ""
	}
}

// LVCanConvToString returns true if a given LValue is a string or number
// otherwise false.
func LVCanConvToString(v LValue) bool {
	switch v.(type) {
	case LString, LNumber, LInteger:
		return true
	default:
		return false
	}
}

// LVAsNumber tries to convert a given LValue to a number.
func LVAsNumber(v LValue) LNumber {
	switch lv := v.(type) {
	case LNumber:
		return lv
	case LInteger:
		return LNumber(lv)
	case LString:
		if num, err := parseNumber(string(lv)); err == nil {
			return num
		}
	}
	return LNumber(0)
}

type LNilType struct{}

func (nl *LNilType) String() string   { return "nil" }
func (nl *LNilType) Type() LValueType { return LTNil }

var LNil = LValue(&LNilType{})

type LBool bool

func (bl LBool) String() string {
	if bool(bl) {
		return "true"
	}
	return "false"
}
func (bl LBool) Type() LValueType { return LTBool }

var LTrue = LBool(true)
var LFalse = LBool(false)

type LString string

func (st LString) String() string   { return string(st) }
func (st LString) Type() LValueType { return LTString }

// fmt.Formatter interface
func (st LString) Format(f fmt.State, c rune) {
	switch c {
	case 'd', 'i':
		if nm, err := parseNumber(string(st)); err != nil {
			defaultFormat(nm, f, 'd')
		} else {
			defaultFormat(string(st), f, 's')
		}
	default:
		defaultFormat(string(st), f, c)
	}
}

func (nm LNumber) String() string {
	if isInteger(nm) {
		return fmt.Sprint(int64(nm))
	}
	return fmt.Sprint(float64(nm))
}

func (nm LNumber) Type() LValueType { return LTNumber }

// fmt.Formatter interface
func (nm LNumber) Format(f fmt.State, c rune) {
	switch c {
	case 'q', 's':
		defaultFormat(nm.String(), f, c)
	case 'b', 'c', 'd', 'o', 'x', 'X', 'U':
		defaultFormat(int64(nm), f, c)
	case 'e', 'E', 'f', 'F', 'g', 'G':
		defaultFormat(float64(nm), f, c)
	case 'i':
		defaultFormat(int64(nm), f, 'd')
	default:
		if isInteger(nm) {
			defaultFormat(int64(nm), f, c)
		} else {
			defaultFormat(float64(nm), f, c)
		}
	}
}

type LTable struct {
	Metatable LValue

	array []LValue
	// fields holds the string-keyed entries in insertion order and
	// fieldIndex locates them once there are too many for a linear
	// search (see table.go). nums holds the unboxed numbers of the
	// entries: one fieldNum per entry that fields has room for, or nil
	// as long as no entry has held a number.
	fields     []tableField
	nums       *fieldNum
	fieldIndex []uint32

	// iarr and farr are the unboxed array parts used when akind is
	// arrayKindInt or arrayKindFloat (see table.go).
	iarr []int64
	farr []float64
	// tail is the number of nil slots that GopherLua's array part would
	// hold behind the stored elements: assigning nil to the last element
	// leaves its slot behind, and so does assigning nil beyond the end.
	// The slots are not stored, but table.insert and table.remove of the
	// Lua 5.1 profile count them (see table.go).
	tail int
	// sparse holds the elements of the array part that lie in the nil
	// slots behind the stored elements (see table_sparse.go). It is nil
	// if there are none, which is what compiled code checks.
	sparse *tableSparse
	// extra holds the parts that most tables do not have: the entries
	// with other keys than strings and array indexes, and the keys kept
	// for traversals. It is nil until one of them is needed.
	extra *tableExtra
	// akind is the representation of the array part.
	akind uint8
	// typedOK allows the array part to use the unboxed representations.
	typedOK bool
	// watched is set once JIT compiled code depends on the version field.
	// watchedKeys is set if that code also relies on string keys being
	// absent (a method that is found further up a chain of classes).
	watched     bool
	watchedKeys bool
	// intKeys is set for tables created by a Lua 5.5 profile state:
	// integral number keys are reported as LInteger instead of LNumber.
	intKeys bool
	// walked is set by the first traversal of the table (see beginWalk).
	walked bool
	// version is bumped whenever a string-keyed entry holding a function or
	// a table is replaced or removed. JIT compiled code uses it to guard
	// speculated lookups of functions and library tables.
	version uint32
}

// tableExtra holds the parts of a table that most tables do not have.
type tableExtra struct {
	// dict holds the entries whose keys are neither strings nor array
	// indexes; keys and k2i keep the order in which they were added.
	dict map[LValue]LValue
	keys []LValue
	k2i  map[LValue]int
	// fieldKeys caches the keys of the fields as Lua values, by position,
	// for traversals (converting a string to a Lua value allocates). It
	// is nil until the table is traversed a second time, so that a table
	// that is traversed once pays nothing.
	fieldKeys []LValue
}

// tableSparse holds the elements of the array part of a table that lie
// behind the stored elements, by 0-based slot index. keys caches the
// indexes in ascending order (nil: to be rebuilt) and top the largest one
// (valid if topOK is set).
type tableSparse struct {
	elems map[int]LValue
	keys  []int
	top   int
	topOK bool
}

func (tb *LTable) String() string   { return fmt.Sprintf("table: %p", tb) }
func (tb *LTable) Type() LValueType { return LTTable }

type LFunction struct {
	IsG       bool
	Env       *LTable
	Proto     *FunctionProto
	GFunction LGFunction
	Upvalues  []*Upvalue

	// jitp caches the JIT state of the prototype for the owning state.
	jitp *jitProto
}
type LGFunction func(*LState) int

func (fn *LFunction) String() string   { return fmt.Sprintf("function: %p", fn) }
func (fn *LFunction) Type() LValueType { return LTFunction }

type Global struct {
	MainThread    *LState
	CurrentThread *LState
	Registry      *LTable
	Global        *LTable

	builtinMts map[int]LValue
	// builtinMtGen changes whenever the metatable of a basic type is
	// set: compiled code that resolved a string method depends on it.
	builtinMtGen uint64
	tempFiles    []*os.File
	gccount      int32

	// jit is the JIT compiler state shared by all threads of this state
	// (nil when the JIT is disabled or unsupported on this platform).
	jit *jitState
}

type LState struct {
	G       *Global
	Parent  *LState
	Env     *LTable
	Panic   func(*LState)
	Dead    bool
	Options Options

	stop         int32
	reg          *registry
	stack        callFrameStack
	alloc        *allocator
	currentFrame *callFrame
	wrapped      bool
	uvcache      *Upvalue
	hasErrorFunc bool
	mainLoop     func(*LState, *callFrame)
	ctx          context.Context
	ctxCancelFn  context.CancelFunc

	// lang55 caches Options.LanguageVersion == Lua55.
	lang55 bool
	// typedArrays enables unboxed int/float array parts for new tables.
	typedArrays bool
	// jitOn is true if this thread runs with the JIT enabled main loop.
	jitOn bool
	// jitOwner is true for the state that created the JIT state (the one
	// returned by NewState): closing it releases the native code.
	jitOwner bool

	// nny counts the nested interpreter loops started by Go code on this
	// thread; the thread cannot yield while it is non-zero.
	nny int
	// tbc is the list of to-be-closed variables (registry indices) of this
	// thread, in ascending order.
	tbc []tbcEntry
	// jit is the per-thread JIT execution state (nil when the JIT is off).
	jit *jitThread
}

func (ls *LState) String() string   { return fmt.Sprintf("thread: %p", ls) }
func (ls *LState) Type() LValueType { return LTThread }

type LUserData struct {
	Value     interface{}
	Env       *LTable
	Metatable LValue
}

func (ud *LUserData) String() string   { return fmt.Sprintf("userdata: %p", ud) }
func (ud *LUserData) Type() LValueType { return LTUserData }

type LChannel chan LValue

func (ch LChannel) String() string   { return fmt.Sprintf("channel: %p", ch) }
func (ch LChannel) Type() LValueType { return LTChannel }

// setBuiltinMetatable sets the metatable shared by all values of a
// basic type.
func (g *Global) setBuiltinMetatable(typ LValueType, mt LValue) {
	g.builtinMts[int(typ)] = mt
	g.builtinMtGen++
}
