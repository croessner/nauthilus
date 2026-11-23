package lua

import (
	"fmt"
	"io"
	"runtime"
	"sync"

	"time"
	"unsafe"

	"github.com/yuin/gopher-lua/internal/jit"
	"github.com/yuin/gopher-lua/internal/jit/codecache"
)

// JITOptions configures the native just-in-time compiler of a LState.
//
// The JIT compiles hot loops to machine code for amd64 and arm64 on Linux
// and macOS. On other platforms, or when executable memory cannot be
// obtained, the option is ignored and the interpreter is used.
type JITOptions struct {
	// Enabled turns the JIT compiler on.
	Enabled bool
	// Threshold is the number of iterations after which a loop is
	// compiled. Zero selects the default (50).
	Threshold int
	// MaxCodeBytes bounds the executable memory mapped for one state
	// (shared by its coroutines). When the limit is reached all compiled
	// code of the state is discarded and compilation starts over; a loop
	// whose code alone exceeds the limit is left to the interpreter. Zero
	// or a negative value selects the default (16 MiB).
	MaxCodeBytes int
	// SafePointInterval is the number of loop iterations native code may
	// execute before it returns to Go to honor garbage collection,
	// preemption and context cancellation. Zero or a negative value
	// selects the default (65536); values above 2^24 are reduced to 2^24.
	SafePointInterval int
	// Log, if not nil, receives one line per JIT event (compilation,
	// invalidation, blacklisting). It is meant for diagnostics.
	Log io.Writer
}

// JITStats reports the activity of the JIT compiler of a state.
type JITStats struct {
	// Enabled is true if the JIT is active for the state.
	Enabled bool
	// Supported is true if the platform has a native backend.
	Supported bool
	// Compiled is the number of successfully compiled units.
	Compiled int
	// CompileFailed counts compilation attempts that were rejected.
	CompileFailed int
	// Invalidated counts compiled units that were discarded.
	Invalidated int
	// Blacklisted counts loops that are permanently interpreted.
	Blacklisted int
	// CacheFlushes counts how often the code cache limit was hit.
	CacheFlushes int
	// LiveUnits is the number of compiled units currently installed.
	LiveUnits int
	// CodeBytes is the executable memory currently mapped for the state.
	CodeBytes int
	// MaxCodeBytes is the configured code cache limit.
	MaxCodeBytes int
	// Entries counts transitions from the interpreter into native code.
	Entries uint64
	// Deopts counts exits from native code back to the interpreter.
	Deopts uint64
	// Callouts counts runtime services executed on behalf of native code.
	Callouts uint64
	// SafePoints counts safe point exits.
	SafePoints uint64
	// CompileTime is the total time spent compiling.
	CompileTime time.Duration
}

func (s JITStats) String() string {
	if !s.Enabled {
		return fmt.Sprintf("jit: disabled (supported=%v)", s.Supported)
	}
	return fmt.Sprintf("jit: units=%d live=%d failed=%d invalidated=%d blacklisted=%d flushes=%d code=%dB/%dB entries=%d deopts=%d callouts=%d safepoints=%d compile=%v",
		s.Compiled, s.LiveUnits, s.CompileFailed, s.Invalidated, s.Blacklisted, s.CacheFlushes,
		s.CodeBytes, s.MaxCodeBytes, s.Entries, s.Deopts, s.Callouts, s.SafePoints, s.CompileTime)
}

const (
	jitDefaultThreshold = 50
	jitDefaultMaxCode   = 16 << 20
	jitDefaultFuel      = 1 << 16
	// jitMaxFuel bounds the safe point interval: native code must return
	// to the Go runtime regularly, whatever the configuration says.
	jitMaxFuel = 1 << 24

	// jitMaxCompiles is the number of times one loop may be compiled
	// before it is blacklisted.
	jitMaxCompiles = 6
	// jitHotExit is the number of times a guard may fail before the unit
	// is recompiled with the collected type feedback.
	jitHotExit = 8
	// jitMinIterations is the number of loop iterations native code has
	// to execute per exit of one kind for the unit to be kept: below it
	// the transitions between interpreter and native code cost more than
	// the native iterations save (measured break-even: between four and
	// eight iterations of a small loop body).
	jitMinIterations = 8
	// jitMaxFlushes is the number of code cache flushes after which the
	// JIT stops compiling for the state.
	jitMaxFlushes = 8
	// jitMaxRegion bounds the number of instructions of a compiled region.
	jitMaxRegion = 3000
	// jitMaxDepth bounds the nesting of native activations of a thread.
	jitMaxDepth = 64
)

// jitState is the JIT compiler state of a Lua state. It is shared by all
// threads (coroutines) of the state and must only be used by the
// goroutine that owns the state.
type jitState struct {
	threshold int32
	maxCode   int
	fuel      uint64
	log       io.Writer

	protos    map[*FunctionProto]*jitProto
	units     map[*jitUnit]struct{}
	mem       *jitMemory
	codeBytes int
	flushes   int
	// localGen changes whenever a debugger modifies a local variable;
	// native code then hands its frame back to the interpreter.
	localGen uint32
	stopped  bool // no further compilation
	stats    JITStats
}

// jitMemory owns the executable memory of a state. It deliberately holds
// no reference back to the state, so that a finalizer can release the
// memory of a state that is dropped without Close.
type jitMemory struct {
	blocks map[*codecache.Block]struct{}
}

// newJITMemory returns an empty memory set that frees itself when it
// becomes unreachable.
func newJITMemory() *jitMemory {
	m := &jitMemory{blocks: make(map[*codecache.Block]struct{})}
	runtime.SetFinalizer(m, (*jitMemory).freeAll)
	return m
}

// alloc maps code as a new executable block.
func (m *jitMemory) alloc(code []byte) (*codecache.Block, error) {
	b, err := codecache.Alloc(code)
	if err == nil {
		m.blocks[b] = struct{}{}
	}
	return b, err
}

// free unmaps a block.
func (m *jitMemory) free(b *codecache.Block) {
	delete(m.blocks, b)
	b.Free()
}

// freeAll unmaps every block that is still mapped.
func (m *jitMemory) freeAll() {
	for b := range m.blocks {
		b.Free()
	}
	m.blocks = nil
}

// jitProto is the per-state compilation state of a function prototype.
type jitProto struct {
	// js is the state the compiled code belongs to.
	js    *jitState
	proto *FunctionProto
	// loops is indexed by the pc of the loop header.
	loops []*jitLoop
	// feedback records value kinds observed at failed guards.
	feedback map[feedbackKey]uint8
}

// jitLoop is the compilation state of one loop.
type jitLoop struct {
	pc          int
	count       int32
	compiles    int
	blacklisted bool
	unit        *jitUnit
}

// feedbackKey identifies a speculation site.
type feedbackKey struct {
	pc   int32
	slot int16
	what uint8
}

// Kinds of feedback.
const (
	fbValue uint8 = iota // kind of the value in a register
	fbArray              // array representation of the table in a register
)

// jitUnit is a piece of compiled code.
type jitUnit struct {
	block  *codecache.Block
	addr   uintptr
	code   *jit.Code
	loop   *jitLoop
	jp     *jitProto
	meta   []exitMeta
	consts []LValue
	nslots int

	// env is the globals table the code was specialized for (nil if it
	// does not depend on one); keep holds the tables whose version word
	// is read by the code, so that they stay alive.
	env  *LTable
	keep []*LTable
	// nativeOps is the number of native operations of the unit, used to
	// judge whether callouts dominate its run time.
	nativeOps int
	callouts  uint64

	exitCounts []uint32
	entries    uint64
	iterations uint64 // loop iterations executed natively
	active     int    // number of running activations
	dead       bool   // invalidated; freed when no activation is left
}

// jitThread is the per-thread native execution state.
type jitThread struct {
	// frames are context frames reused by nesting depth.
	frames [][]uint64
	// acts is the stack of running native activations.
	acts []*jitUnit
}

var jitTables struct {
	once  sync.Once
	table [opCodeMax + 1]instFunc
}

// jitJumpTable returns the instruction table used when the JIT is on: it
// is the interpreter table with loop back-edges instrumented.
func jitJumpTable() *[opCodeMax + 1]instFunc {
	jitTables.once.Do(func() {
		jitTables.table = jumpTable
		jitTables.table[OP_FORLOOP] = opForLoopJIT
		jitTables.table[OP_JMP] = opJmpJIT
	})
	return &jitTables.table
}

// jitSupported reports whether the JIT can run in this process.
func jitSupported() bool {
	return codecache.Supported && jit.HostSupported() && jitLayoutOK
}

// initJIT enables the JIT for a new state if requested and possible.
func (ls *LState) initJIT() {
	opts := ls.Options.JIT
	if !opts.Enabled || !jitSupported() {
		return
	}
	js := &jitState{
		threshold: int32(opts.Threshold),
		maxCode:   opts.MaxCodeBytes,
		fuel:      jitDefaultFuel,
		log:       opts.Log,
		protos:    make(map[*FunctionProto]*jitProto),
		units:     make(map[*jitUnit]struct{}),
		mem:       newJITMemory(),
	}
	if js.threshold <= 0 {
		js.threshold = jitDefaultThreshold
	}
	if js.maxCode <= 0 {
		js.maxCode = jitDefaultMaxCode
	}
	if n := opts.SafePointInterval; n > 0 {
		js.fuel = uint64(intMin(n, jitMaxFuel))
	}
	ls.G.jit = js
	ls.jitOn = true
	ls.jitOwner = true

	ls.typedArrays = true
	ls.G.Registry.typedOK = true
	ls.G.Global.typedOK = true
	jitJumpTable()
	ls.mainLoop = selectMainLoop(true, ls.ctx != nil)
}

// closeJIT releases the native code of the state and stops compilation.
// It is called when the state that was created with NewState is closed;
// closing one of its threads has no effect. Threads that are used after
// that fall back to the interpreter. Code that is executing right now
// (Close was called from inside a loop) is released when it returns.
func (ls *LState) closeJIT() {
	js := ls.G.jit
	if js == nil || !ls.jitOwner {
		return
	}
	js.stopped = true
	for u := range js.units {
		js.discard(u)
	}
}

// jitLocalChanged tells the JIT that a debugger wrote a local variable
// into the registry: native code that runs further down the call stack
// must not go on with its unboxed copy of the variable.
func (ls *LState) jitLocalChanged() {
	if js := ls.G.jit; js != nil {
		js.localGen++
	}
}

// JITStats returns a snapshot of the JIT statistics of this state.
func (ls *LState) JITStats() JITStats {
	js := ls.G.jit
	if js == nil {
		return JITStats{Supported: jitSupported()}
	}
	s := js.stats
	s.Enabled = true
	s.Supported = true
	s.LiveUnits = len(js.units)
	s.CodeBytes = js.codeBytes
	s.MaxCodeBytes = js.maxCode
	return s
}

// JITFlush discards all compiled code of the state. Compilation starts
// over as code becomes hot again.
func (ls *LState) JITFlush() {
	if js := ls.G.jit; js != nil {
		js.flushAll("requested")
	}
}

func (js *jitState) logf(format string, args ...interface{}) {
	if js.log != nil {
		fmt.Fprintf(js.log, "jit: "+format+"\n", args...)
	}
}

// protoFor returns the compilation state of a prototype.
func (js *jitState) protoFor(p *FunctionProto) *jitProto {
	jp := js.protos[p]
	if jp == nil {
		jp = &jitProto{js: js, proto: p, loops: make([]*jitLoop, len(p.Code)+1), feedback: make(map[feedbackKey]uint8)}
		js.protos[p] = jp
	}
	return jp
}

// discard removes a unit from the code cache. Its memory is released
// immediately if the unit is not running, else when its last activation
// ends.
func (js *jitState) discard(u *jitUnit) {
	if u.dead {
		return
	}
	u.dead = true
	delete(js.units, u)
	if u.loop != nil && u.loop.unit == u {
		u.loop.unit = nil
	}
	js.stats.Invalidated++
	if u.active == 0 {
		js.release(u)
	}
}

// release frees the executable memory of a dead unit.
func (js *jitState) release(u *jitUnit) {
	if u.block != nil {
		js.codeBytes -= u.block.Size()
		js.mem.free(u.block)
		u.block = nil
	}
}

// flushAll discards every compiled unit of the state.
func (js *jitState) flushAll(reason string) {
	js.logf("flush code cache (%s): %d units, %d bytes", reason, len(js.units), js.codeBytes)
	for u := range js.units {
		js.discard(u)
	}
	js.stats.CacheFlushes++
	js.flushes++
	if js.flushes >= jitMaxFlushes && reason != "requested" {
		js.stopped = true
		js.logf("compilation stopped after %d cache flushes", js.flushes)
	}
}

/* layout of Go data structures read by native code {{{ */

// itabOf returns the first word of the interface value v, which
// identifies its dynamic type.
func itabOf(v LValue) uintptr {
	return (*[2]uintptr)(unsafe.Pointer(&v))[0]
}

// dataOf returns the data word of the interface value v.
func dataOf(v LValue) unsafe.Pointer {
	return (*[2]unsafe.Pointer)(unsafe.Pointer(&v))[1]
}

var (
	itabInteger = itabOf(LInteger(12345))
	itabNumber  = itabOf(LNumber(1.5))
	itabNil     = itabOf(LNil)
	itabBool    = itabOf(LTrue)
	itabTable   = itabOf(&LTable{})

	offTableAkind     = unsafe.Offsetof(LTable{}.akind)
	offTableArray     = unsafe.Offsetof(LTable{}.array)
	offTableIarr      = unsafe.Offsetof(LTable{}.iarr)
	offTableFarr      = unsafe.Offsetof(LTable{}.farr)
	offTableMetatable = unsafe.Offsetof(LTable{}.Metatable)

	// jitLayoutOK is false if the Go runtime does not lay out interface
	// values and slices the way the native code expects.
	jitLayoutOK = checkJITLayout()
)

const (
	sliceOffData = 0
	sliceOffLen  = 8
	sliceOffCap  = 16
	lvalueSize   = 16
)

// checkJITLayout verifies the assumptions native code makes about the
// memory layout of interface values, slices and boxed numbers.
func checkJITLayout() bool {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(LValue(nil)) != lvalueSize {
		return false
	}
	var lv LValue = LInteger(0x1122334455667788)
	if *(*int64)(dataOf(lv)) != 0x1122334455667788 {
		return false
	}
	lv = LNumber(2.5)
	if *(*float64)(dataOf(lv)) != 2.5 {
		return false
	}
	if *(*byte)(dataOf(LTrue)) != 1 || *(*byte)(dataOf(LFalse)) != 0 {
		return false
	}
	tb := &LTable{}
	lv = tb
	if dataOf(lv) != unsafe.Pointer(tb) {
		return false
	}
	s := make([]float64, 3, 7)
	hdr := (*[3]uintptr)(unsafe.Pointer(&s))
	if hdr[0] != uintptr(unsafe.Pointer(&s[0])) || hdr[1] != 3 || hdr[2] != 7 {
		return false
	}
	arr := make([]LValue, 2)
	if uintptr(unsafe.Pointer(&arr[1]))-uintptr(unsafe.Pointer(&arr[0])) != lvalueSize {
		return false
	}
	if itabInteger == itabNumber || itabNil == 0 || itabTable == itabNil || itabBool == itabNil {
		return false
	}
	return true
}

/* }}} */
