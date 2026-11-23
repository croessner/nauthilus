package lua

import (
	"fmt"
	"unsafe"

	"github.com/yuin/gopher-lua/internal/jit"
)

// This file contains the JIT front end: it translates the bytecode
// reachable from a hot loop header into typed SSA form.
//
// Model. The interpreter keeps every Lua register boxed in the registry
// ("home" slot). Native code never writes the registry. Instead it keeps
// numbers unboxed in SSA values and remembers per register whether the
// home slot is stale ("dirty"). Whenever control leaves native code - at
// a failed guard (deoptimization), at a callout (an instruction executed
// by the interpreter on behalf of native code) or at a safe point - the
// Go driver writes the dirty registers back using the snapshot attached
// to the exit. Values that are not numbers stay in their home slot and
// are only inspected (never copied) by native code; a boxed move is
// recorded as an alias and materialized by the next snapshot.

// slotKind describes how native code holds a Lua register.
type slotKind uint8

const (
	skHome  slotKind = iota // boxed value in its home slot, up to date
	skInt                   // unboxed integer in an SSA value
	skFloat                 // unboxed float in an SSA value
	skBool                  // unboxed boolean (0 or 1) in an SSA value
	skNil                   // the constant nil
	skAlias                 // boxed copy of the home slot src
	skConst                 // boxed constant (index src of the unit pool)
	// skRef is a boxed copy of a value inside a table: val is the address
	// of the value (an element of the array part or the value of a
	// string-keyed entry). The address is only used until Go code runs
	// again, which may move or change the table's storage: the copy is
	// written to the home slot at every callout. src is the register the
	// value was loaded into first; what the interpreter left there last
	// time predicts what the value is.
	skRef
)

// slotState is the abstract state of one Lua register.
type slotState struct {
	kind  slotKind
	dirty bool // only for skInt, skFloat, skBool: home slot is stale
	val   *jit.Value
	src   int32
}

// stale reports whether the home slot does not hold the current value.
func (s *slotState) stale() bool {
	switch s.kind {
	case skHome:
		return false
	case skInt, skFloat, skBool:
		return s.dirty
	}
	return true
}

// Tags of snapshot entries interpreted by the driver.
const (
	tagInt uint8 = iota + 1
	tagFloat
	tagBool
	tagNil
	tagAlias // boxed copy of another register (constant: source register)
	tagConst // boxed constant of the unit pool (constant: index)
	tagRef   // boxed copy of the value at an address
)

// tagLate marks an entry of a callout that is written back only if the
// interpreter keeps the frame after the instruction (see calloutInst).
const tagLate uint8 = 0x80

// Kinds of exits as seen by the driver.
const (
	emDeopt       uint8 = iota // failed guard or unsupported code
	emInst                     // callout: execute the instruction at PC
	emFlush                    // callout: only write back the snapshot
	emFuel                     // safe point
	emUnsupported              // instruction without a native translation
	emLoopExit                 // control leaves the compiled loop
)

// exitMeta is the front end data of an exit (indexed by Exit.Data).
type exitMeta struct {
	kind uint8
	// fbSlot is the register whose kind is recorded as feedback when the
	// exit is a failed guard (-1 for none); fbWhat selects what to record.
	fbSlot int16
	fbWhat uint8
	// fbPC identifies the instruction in feedback keys (it differs from
	// the bytecode position for instructions of inlined functions).
	fbPC int32
	// inl is the inlined call the exit lies in (index into the inlined
	// calls of the unit plus one, zero for none): the interpreter resumes
	// in a frame of the callee that has to be created first.
	inl int16
	// expected marks a guard whose failure is part of normal operation
	// (an array that has to grow) rather than a wrong speculation: it
	// does not count against the unit.
	expected bool
	// top is the register behind the last value of an open result list
	// that the instruction at the exit consumes (-1 for none): the
	// interpreter finds the end of such a list through the registry top.
	top int16
	// entry marks the checks of the entry block, which belong to no
	// instruction.
	entry bool
	// late marks a callout whose snapshot has entries that are only
	// written back when native code is not resumed (tagLate).
	late bool
}

// Value kinds used for speculation and feedback.
const (
	vkUnknown uint8 = iota
	vkInt
	vkFloat
	vkNil
	vkBool
	vkTable
	vkString
	vkLFunction
	vkGFunction
	vkOther
)

// valueKind classifies a Lua value for speculation.
func valueKind(v LValue) uint8 {
	switch x := v.(type) {
	case LInteger:
		return vkInt
	case LNumber:
		return vkFloat
	case *LNilType:
		return vkNil
	case LBool:
		return vkBool
	case *LTable:
		return vkTable
	case LString:
		return vkString
	case *LFunction:
		if x.IsG {
			return vkGFunction
		}
		return vkLFunction
	case nil:
		return vkUnknown
	}
	return vkOther
}

// feBlock is the front end view of a bytecode basic block.
type feBlock struct {
	pc      int
	ir      *jit.Block
	npreds  int // predecessors inside the compiled region
	started bool
	// entry is the state at the start of a block with several
	// predecessors; later edges must conform to it.
	entry    []slotState
	incoming []feEdge
}

// feEdge is a control flow edge waiting for its target block.
type feEdge struct {
	from *jit.Block
	st   []slotState
}

// demoteKey identifies a register that must stay boxed at a block entry.
type demoteKey struct {
	pc   int
	slot int
}

// errJITUnsupported aborts a compilation attempt.
type errJITUnsupported string

func (e errJITUnsupported) Error() string { return string(e) }

// jitFrontend holds the state of one translation.
type jitFrontend struct {
	L     *LState
	jp    *jitProto
	fn    *LFunction
	proto *FunctionProto
	info  *bcInfo
	// env is the table global accesses of the function resolve in (nil
	// if unknown); usesEnv is set once the code depends on its identity.
	env     *LTable
	usesEnv bool
	// keep lists the tables whose version word the code reads.
	keep []*LTable
	// frame gives access to the live registers of the function for type
	// prediction.
	frame   []LValue
	entryPC int
	nslots  int
	// base is the registry index of the function's first register in
	// the activation the code is compiled for.
	base int

	f      *jit.Func
	blocks map[int]*feBlock
	order  []int
	cur    *jit.Block
	st     []slotState
	pc     int
	meta   []exitMeta
	consts []LValue

	demoted map[demoteKey]bool
	// forcedDirty marks registers whose home slot must be assumed stale
	// at a block entry because a later edge delivers them modified.
	forcedDirty map[demoteKey]bool
	// needPhi marks registers that need a phi at a block entry although
	// no instruction of the region seems to modify them.
	needPhi map[demoteKey]bool
	// succs and preds are the control flow edges between the blocks of
	// the region; writes holds the registers each block may modify and
	// loopWrites caches the registers modified inside the loop of a
	// header block.
	succs      map[int][]int
	preds      map[int][]int
	writes     map[int]*regSet
	loopWrites map[int]*regSet
	restart    bool
	// openTop is the register behind the last value of an open result
	// list produced by the previous instruction (-1 if there is none).
	// While the consumer of the list is translated it is kept in
	// pendingTop, so that every hand-over to the interpreter at that
	// instruction restores the registry top.
	openTop    int
	pendingTop int

	// inlined lists the calls whose callee was translated in place; inl
	// is the innermost one being translated right now (index plus one,
	// zero while the code of the compiled function itself is translated).
	// scope is the closure whose code is being translated, slotBase the
	// slot of its register 0 and fbBase the prefix of its feedback keys.
	inlined  []inlineCall
	inl      int
	scope    *LFunction
	slotBase int
	fbBase   int32
	// refPeek holds, by the register a reference was loaded into, a
	// value like the ones the reference will see (an element of the
	// array or the value of the field it was loaded from).
	refPeek map[int32]LValue
	// fieldSample is the value of the field fieldRef located last.
	fieldSample LValue
	// edges collects the control flow edges inside the inlined callee
	// that is being translated, by target position (see inlineBody).
	edges map[int][]feEdge

	// twins holds the integer twins of float values (see jit_narrow.go);
	// loopBits is the bound of the control values of the narrowed numeric
	// for loops, by the position of the loop body. noTwin marks the
	// registers that get no twin at a block entry because an edge
	// delivers them without one; indexRegs caches indexRegisters.
	// envConst is the index of the environment table in the constant
	// pool once the code accesses a global through it (-1 before).
	envConst int32

	twins     map[*jit.Value]intTwin
	loopBits  map[int]uint8
	noTwin    map[demoteKey]bool
	indexRegs *regSet

	// statistics for the profitability check: IR operations emitted,
	// instructions translated and how many of them became callouts
	nativeOps int
	insts     int
	callouts  int
}

// inlineCall describes a call whose callee is translated in place. It is
// what the interpreter needs to continue inside the callee: the frame of
// an inlined call only exists once an exit creates it.
type inlineCall struct {
	callee *LFunction
	callPC int // position of the call in the calling code
	ra     int // slot of the function value
	nargs  int
	nret   int // number of results the caller expects (-1: all)
	// tail marks a tail call: its frame takes the place of the frame of
	// the calling function, which is the previous entry of the chain.
	tail   bool
	parent int // enclosing inlined call (index plus one), zero for none
	// live are the slots written back at exits inside the callee: what
	// the callers still need and the whole frame of the callee.
	live regSet
	// site is the feedback key that stops inlining at this call.
	site feedbackKey
}

// compileLoopIR translates the region starting at the loop header entryPC
// into IR. frame is the register window of the running function.
func compileLoopIR(L *LState, jp *jitProto, fn *LFunction, frame []LValue, base, entryPC int) (*jit.Func, *jitFrontend, error) {
	fe := &jitFrontend{
		base: base,
		L:    L, jp: jp, fn: fn, scope: fn, proto: jp.proto, info: jp.proto.analysis(),
		env:   functionEnv(fn),
		frame: frame, entryPC: entryPC, nslots: jp.proto.analysis().nslots,
		demoted:     make(map[demoteKey]bool),
		forcedDirty: make(map[demoteKey]bool),
		needPhi:     make(map[demoteKey]bool),
		noTwin:      make(map[demoteKey]bool),
	}
	if fe.nslots > len(frame) {
		return nil, nil, errJITUnsupported("register window too small")
	}
	for attempt := 0; attempt < 64; attempt++ {
		fe.restart = false
		if err := fe.translate(); err != nil {
			return nil, nil, err
		}
		if !fe.restart {
			return fe.f, fe, nil
		}
	}
	return nil, nil, errJITUnsupported("type inference did not converge")
}

// fail aborts the translation.
func (fe *jitFrontend) fail(format string, args ...interface{}) {
	panic(errJITUnsupported(fmt.Sprintf(format, args...)))
}

// translate runs one translation attempt.
func (fe *jitFrontend) translate() (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(errJITUnsupported); ok {
				err = e
				return
			}
			panic(r)
		}
	}()
	fe.f = jit.NewFunc(fmt.Sprintf("%s:%d@%d", fe.proto.SourceName, fe.proto.LineDefined, fe.entryPC))
	fe.openTop = -1
	fe.pendingTop = -1
	fe.inlined = fe.inlined[:0]
	fe.refPeek = make(map[int32]LValue)
	fe.twins = make(map[*jit.Value]intTwin)
	fe.loopBits = make(map[int]uint8)
	fe.meta = fe.meta[:0]
	fe.consts = fe.consts[:0]
	fe.keep = fe.keep[:0]
	fe.usesEnv = false
	fe.envConst = -1
	fe.nativeOps, fe.insts, fe.callouts = 0, 0, 0
	fe.discoverRegion()

	// entry block: unbox the numeric registers that are live at the loop
	// header, speculating on the types they have right now
	fe.cur = fe.f.Entry
	fe.pc = fe.entryPC
	fe.st = make([]slotState, fe.nslots)
	live := &fe.info.liveIn[fe.entryPC]
	for slot := 0; slot < fe.nslots; slot++ {
		if !live.has(slot) || fe.info.escaped.has(slot) {
			continue
		}
		switch valueKind(fe.frame[slot]) {
		case vkInt:
			fe.unbox(slot, skInt)
		case vkFloat:
			fe.unbox(slot, skFloat)

		}
	}
	fe.speculateLoopStep()
	fe.narrowEntry()
	fe.connect(fe.cur, fe.entryPC, fe.st)

	for _, pc := range fe.order {
		tb := fe.blocks[pc]
		if !fe.startBlock(tb) {
			continue
		}
		fe.openTop, fe.pendingTop = -1, -1

		for p := pc; ; {
			fe.pc = p
			next, ended := fe.inst(p)
			if ended {
				break
			}
			p = next
			if fe.info.leader[p] {
				fe.connect(fe.cur, p, fe.st)
				break
			}
		}
		if fe.restart {
			return nil
		}
	}
	return nil
}

// discoverRegion finds the basic blocks reachable from the entry and
// orders them in reverse postorder.
func (fe *jitFrontend) discoverRegion() {
	fe.blocks = make(map[int]*feBlock)
	n := len(fe.proto.Code)
	var post []int
	seen := make(map[int]bool)
	// blockSuccs returns the successor leaders of the block starting at pc.
	blockSuccs := func(pc int) []int {
		for p := pc; p < n; {
			e := &fe.info.effects[p]
			fall := e.nsucc == 1 && e.succs[0] > p && !fe.info.leader[e.succs[0]]
			if !fall {
				out := make([]int, 0, 2)
				for i := 0; i < e.nsucc; i++ {
					if s := e.succs[i]; s >= 0 && s < n {
						out = append(out, s)
					}
				}
				return out
			}
			p = e.succs[0]
		}
		return nil
	}
	count := 0
	var visit func(pc int)
	visit = func(pc int) {
		seen[pc] = true
		count++
		if count > jitMaxRegion {
			fe.fail("region too large")
		}
		fe.blocks[pc] = &feBlock{pc: pc}
		for _, s := range blockSuccs(pc) {
			if !seen[s] {
				visit(s)
			}
		}
		post = append(post, pc)
	}
	visit(fe.entryPC)
	fe.order = fe.order[:0]
	for i := len(post) - 1; i >= 0; i-- {
		fe.order = append(fe.order, post[i])
	}
	fe.succs = make(map[int][]int)
	fe.preds = make(map[int][]int)
	fe.writes = make(map[int]*regSet)
	fe.loopWrites = make(map[int]*regSet)
	for _, pc := range fe.order {
		ss := blockSuccs(pc)
		fe.succs[pc] = ss
		for _, s := range ss {
			fe.blocks[s].npreds++
			fe.preds[s] = append(fe.preds[s], pc)
		}
		w := &regSet{}
		fe.writes[pc] = w
		for p := pc; p < n; {
			fe.noteWrites(w, p)
			e := &fe.info.effects[p]
			if !(e.nsucc == 1 && e.succs[0] > p && !fe.info.leader[e.succs[0]]) {
				break
			}
			p = e.succs[0]
		}
	}
	// the compiled region is the loop itself: the blocks on a path from
	// the header back to the header. Control leaving the loop returns to
	// the interpreter, so that code behind the loop (and later loops) is
	// compiled separately with the types it has then.
	inLoop := fe.naturalLoop(fe.entryPC)
	order := fe.order[:0]
	for _, pc := range fe.order {
		if inLoop[pc] {
			order = append(order, pc)
		} else {
			delete(fe.blocks, pc)
		}
	}
	fe.order = order
	for _, pc := range fe.order {
		tb := fe.blocks[pc]
		tb.npreds = 0
		for _, p := range fe.preds[pc] {
			if inLoop[p] {
				tb.npreds++
			}
		}
		tb.ir = fe.f.NewBlock()
	}
	fe.blocks[fe.entryPC].npreds++ // the edge from the entry block
}

// noteWrites adds the registers the instruction at pc may modify to w
// (a superset of the definite writes used for liveness).
func (fe *jitFrontend) noteWrites(w *regSet, pc int) {
	inst := fe.proto.Code[pc]
	a := opGetArgA(inst)
	e := &fe.info.effects[pc]
	w.union(&e.writes)
	switch opGetOpCode(inst) {
	case OP_TESTSET, OP_SELF:
		w.add(a)
		w.add(a + 1)
	case OP_FORPREP:
		for r := a; r <= a+3; r++ {
			w.add(r)
		}
	case OP_FORLOOP:
		w.add(a)
		w.add(a + 3)
	case OP_CALL, OP_TAILCALL, OP_VARARG, OP_TFORLOOP, OP_SETLIST:
		w.addFrom(a)
	}
}

// writtenInLoop returns the registers that may be modified on a path from
// the block at header back to itself.
func (fe *jitFrontend) writtenInLoop(header int) *regSet {
	if w, ok := fe.loopWrites[header]; ok {
		return w
	}
	w := &regSet{}
	for pc := range fe.naturalLoop(header) {
		if ws := fe.writes[pc]; ws != nil {
			w.union(ws)
		}
	}
	fe.loopWrites[header] = w
	return w
}

// naturalLoop returns the blocks of the loop with the given header: the
// header plus every block that reaches a back-edge into the header
// without passing through the header. Back-edges are the edges into the
// header that jump backward in the bytecode.
func (fe *jitFrontend) naturalLoop(header int) map[int]bool {
	loop := map[int]bool{header: true}
	// Back-edges come from the loop body, which lies behind the header.
	// (Edges from before the header belong to an enclosing loop.) The
	// header of a generic for loop is its last instruction: its body
	// lies between the jump target of that instruction and the header.
	lo, hi := header, len(fe.proto.Code)
	if opGetOpCode(fe.proto.Code[header]) == OP_TFORLOOP {
		lo, hi = fe.info.effects[header].succs[0], header
	}
	var work []int
	for _, p := range fe.preds[header] {
		if p >= lo && p < hi || p == header {
			work = append(work, p)
		}
	}
	for len(work) > 0 {
		pc := work[len(work)-1]
		work = work[:len(work)-1]
		if loop[pc] {
			continue
		}
		loop[pc] = true
		work = append(work, fe.preds[pc]...)
	}
	return loop
}

// speculateLoopStep specializes the compiled code on the current step of
// the numeric for loop that is being entered, which makes the direction
// of the loop a compile time constant.
func (fe *jitFrontend) speculateLoopStep() {
	a, ok := fe.entryForLoop()
	if !ok {
		return
	}
	// A step of one (the usual case) is treated as a constant; any
	// other step may differ on the next entry (for j = i, n, i), so
	// only its sign is assumed where the loop is translated.
	slot := a + 2
	s := &fe.st[slot]
	switch s.kind {
	case skInt:
		if v := int64(fe.frame[slot].(LInteger)); v == 1 || v == -1 {
			c := fe.f.ConstInt(fe.cur, v)
			fe.guard(fe.f.NewValue(fe.cur, jit.OpEq, jit.TInt, 0, s.val, c), -1, 0)
			s.val = c
		}
	case skFloat:
		if v := float64(fe.frame[slot].(LNumber)); v == 1 || v == -1 {
			c := fe.f.ConstFloat(fe.cur, v)
			fe.guard(fe.f.NewValue(fe.cur, jit.OpFEq, jit.TInt, 0, s.val, c), -1, 0)
			s.val = c
		}
	}
}

/* exits and snapshots {{{ */

// newExit creates an exit with front end data.
func (fe *jitFrontend) newExit(kind jit.ExitKind, pc int, m exitMeta) *jit.Exit {
	m.top = -1
	m.fbPC = fe.fbBase + int32(pc)
	m.inl = int16(fe.inl)
	m.entry = fe.cur == fe.f.Entry
	if fe.pendingTop >= 0 && pc == fe.pc && (m.kind == emDeopt || m.kind == emUnsupported || m.kind == emInst) {
		m.top = int16(fe.pendingTop)
	}
	x := fe.f.NewExit(kind, pc)

	x.Data = len(fe.meta)
	fe.meta = append(fe.meta, m)
	return x
}

// snapshot describes the registers that must be written back when the
// interpreter takes over at pc with the state st. If only is not nil it
// selects the registers to include; pending aliases are always included
// because they must be materialized before their source is overwritten.
func (fe *jitFrontend) snapshot(b *jit.Block, st []slotState, pc int, only func(slot int) bool) []jit.SnapEntry {
	var snap []jit.SnapEntry
	live := &fe.info.liveIn[pc]
	if fe.inl != 0 {
		live = &fe.inlined[fe.inl-1].live
	}
	for slot := range st {
		s := &st[slot]
		if !s.stale() || !live.has(slot) {
			continue
		}
		if only != nil && s.kind != skAlias && s.kind != skRef && !only(slot) {
			continue
		}
		e := jit.SnapEntry{Slot: slot}
		switch s.kind {
		case skInt:
			e.Tag, e.Val = tagInt, s.val
		case skFloat:
			e.Tag, e.Val = tagFloat, s.val
		case skBool:
			e.Tag, e.Val = tagBool, s.val
		case skNil:
			e.Tag, e.Val = tagNil, fe.f.ConstInt(b, 0)
		case skAlias:
			e.Tag, e.Val = tagAlias, fe.f.ConstInt(b, int64(s.src))
		case skConst:
			e.Tag, e.Val = tagConst, fe.f.ConstInt(b, int64(s.src))
		case skRef:
			e.Tag, e.Val = tagRef, s.val
		}
		snap = append(snap, e)
	}
	return snap
}

// guard emits a guard on cond that deoptimizes to the current
// instruction. fbSlot, if >= 0, is the register whose kind is recorded
// when the guard fails.
func (fe *jitFrontend) guard(cond *jit.Value, fbSlot int, fbWhat uint8) {
	if fbSlot >= 0 {
		fbSlot = locSlot(fbSlot)
	}
	x := fe.newExit(jit.ExitDeopt, fe.pc, exitMeta{kind: emDeopt, fbSlot: int16(fbSlot), fbWhat: fbWhat})
	x.Snap = fe.snapshot(fe.cur, fe.st, fe.pc, nil)
	g := fe.f.NewValue(fe.cur, jit.OpGuard, jit.TInt, 0, cond)
	g.Exit = x
}

// guardExpected emits a guard whose failure is an ordinary event that the
// interpreter handles (see exitMeta.expected).
func (fe *jitFrontend) guardExpected(cond *jit.Value) {
	fe.guard(cond, -1, 0)
	fe.meta[len(fe.meta)-1].expected = true
}

// unsupported ends the current block at an instruction that has no
// native translation.
func (fe *jitFrontend) unsupported() {
	fe.exitBlockKind(emUnsupported)
}

// exitBlock ends the current block by handing over to the interpreter at
// the current instruction.
func (fe *jitFrontend) exitBlock() {
	fe.exitBlockKind(emDeopt)
}

func (fe *jitFrontend) exitBlockKind(kind uint8) {
	x := fe.newExit(jit.ExitDeopt, fe.pc, exitMeta{kind: kind, fbSlot: -1})
	x.Snap = fe.snapshot(fe.cur, fe.st, fe.pc, nil)
	fe.cur.Kind = jit.BlockExit
	fe.cur.Exit = x
}

// markFlushed updates st after the registers of snap were written back.
func markFlushed(st []slotState, snap []jit.SnapEntry) {
	for _, e := range snap {
		if e.Tag&tagLate != 0 {
			continue // not written back: still stale
		}
		s := &st[e.Slot]
		switch s.kind {
		case skInt, skFloat, skBool:
			s.dirty = false
		default:
			*s = slotState{}
		}
	}
}

// flushOn emits a callout into block b that writes back the selected
// stale registers of st (and all pending aliases).
func (fe *jitFrontend) flushOn(b *jit.Block, st []slotState, pc int, only func(slot int) bool) {
	snap := fe.snapshot(b, st, pc, only)
	if len(snap) == 0 {
		return
	}
	x := fe.newExit(jit.ExitCallout, pc, exitMeta{kind: emFlush, fbSlot: -1})
	x.Snap = snap
	fe.f.NewValue(b, jit.OpCallout, jit.TInt, 0).Exit = x
	markFlushed(st, snap)
	fe.callouts++
}

// calloutInst lets the interpreter execute the current instruction. All
// stale live registers are written back first so that the interpreter
// could also take over completely.
func (fe *jitFrontend) calloutInst() {
	if fe.inl != 0 {
		panic("jit: callout inside an inlined call")
	}
	x := fe.newExit(jit.ExitCallout, fe.pc, exitMeta{kind: emInst, fbSlot: -1})
	x.Snap = fe.snapshot(fe.cur, fe.st, fe.pc, nil)
	// Writing an unboxed number back allocates. The instruction only
	// sees its operands, and native code keeps its own copies, so the
	// numbers in registers that the instruction neither reads nor
	// writes are written back only if the interpreter ends up with the
	// frame: when the instruction does not return here, or when a
	// debugger looks at the registers while it runs. (A register that a
	// closure captured can be read by any function the instruction
	// calls.)
	e := &fe.info.effects[fe.pc]
	for i := range x.Snap {
		s := &x.Snap[i]
		if (s.Tag == tagInt || s.Tag == tagFloat || s.Tag == tagBool) &&
			!e.reads.has(s.Slot) && !e.writes.has(s.Slot) && !fe.info.escaped.has(s.Slot) {
			s.Tag |= tagLate
			fe.meta[x.Data].late = true
		}
	}
	fe.f.NewValue(fe.cur, jit.OpCallout, jit.TInt, 0).Exit = x
	markFlushed(fe.st, x.Snap)
	fe.callouts++
	// whatever the instruction wrote is now boxed in its home slot, and
	// references into tables that were not written back are dead: the
	// interpreter may have changed the tables
	for slot := range fe.st {
		if e.writes.has(slot) || fe.info.escaped.has(slot) || fe.st[slot].kind == skRef {
			fe.st[slot] = slotState{}
		}
	}
}

/* }}} */

/* control flow {{{ */

// cloneState copies a register state.
func cloneState(st []slotState) []slotState {
	return append([]slotState(nil), st...)
}

// connect adds a control flow edge from the IR block from (which must not
// have a terminator yet) to the bytecode block at pc, carrying state st.
func (fe *jitFrontend) connect(from *jit.Block, pc int, st []slotState) {
	if fe.inl != 0 {
		// inside an inlined callee: its blocks are joined by inlineBody
		fe.edges[pc] = append(fe.edges[pc], feEdge{from, cloneState(st)})
		return
	}
	tb := fe.blocks[pc]
	if tb == nil {
		// the edge leaves the loop: the interpreter continues at pc
		x := fe.newExit(jit.ExitDeopt, pc, exitMeta{kind: emLoopExit, fbSlot: -1})
		x.Snap = fe.snapshot(from, st, pc, nil)
		from.Kind = jit.BlockExit
		from.Exit = x
		return
	}
	st = cloneState(st)
	if pc <= fe.pc && from != fe.f.Entry {
		// loop back-edge: safe point
		x := fe.newExit(jit.ExitFuel, pc, exitMeta{kind: emFuel, fbSlot: -1})
		x.Snap = fe.snapshot(from, st, pc, nil)
		fe.f.NewValue(from, jit.OpFuel, jit.TInt, 0).Exit = x
	}
	if !tb.started {
		tb.incoming = append(tb.incoming, feEdge{from, st})
		return
	}
	fe.conform(from, tb, st)
	from.Kind = jit.BlockJump
	jit.AddEdge(from, tb.ir)
}

// conform makes the state st of an edge into the already started block tb
// match the entry state of tb: it appends phi arguments and writes back
// registers that tb expects in their home slot.
func (fe *jitFrontend) conform(from *jit.Block, tb *feBlock, st []slotState) {
	live := &fe.info.liveIn[tb.pc]
	needFlush := false
	for slot := range st {
		if !live.has(slot) {
			continue
		}
		want, have := &tb.entry[slot], &st[slot]
		switch want.kind {
		case skInt, skFloat, skBool:
			if have.kind != want.kind {
				fe.demote(tb.pc, slot)
			} else if have.dirty && !want.dirty {
				fe.forcedDirty[demoteKey{tb.pc, slot}] = true
				fe.restart = true
			} else if !(want.val.Op == jit.OpPhi && want.val.Block == tb.ir) && have.val != want.val {
				fe.needPhi[demoteKey{tb.pc, slot}] = true
				fe.restart = true
			} else if want.kind == skFloat && !fe.twinConforms(from, tb, want.val, have.val) {
				fe.noTwin[demoteKey{tb.pc, slot}] = true
				fe.restart = true
			}
		case skNil:
			if have.kind != skNil {
				fe.demote(tb.pc, slot)
			}
		case skRef:
			// any boxed value that is in memory can be referred to
			switch have.kind {
			case skRef:
			case skHome:
				*have = fe.refHome(from, slot)
			case skAlias:
				*have = fe.refHome(from, int(have.src))
			default:
				fe.demote(tb.pc, slot)
				continue
			}
			if !(want.val.Op == jit.OpPhi && want.val.Block == tb.ir) && have.val != want.val {
				fe.needPhi[demoteKey{tb.pc, slot}] = true
				fe.restart = true
			}
		default:
			if have.stale() {
				needFlush = true
			}
		}
	}
	if fe.restart {
		return
	}
	if needFlush {
		fe.flushOn(from, st, tb.pc, func(slot int) bool { return tb.entry[slot].kind == skHome })
	}
	for slot := range st {
		want := &tb.entry[slot]
		if !live.has(slot) || want.val == nil || want.val.Op != jit.OpPhi || want.val.Block != tb.ir {
			continue
		}
		want.val.Args = append(want.val.Args, st[slot].val)
		if want.kind == skFloat {
			fe.addTwinArg(from, tb, want.val, st[slot].val)
		}
	}
}

// unboxLoopCarried prepares the entry of a loop that lies inside the
// compiled region. A register that the loop modifies and that arrives
// boxed, but holds a number right now, is unboxed on the entering edges:
// the loop then carries it in a machine register instead of writing it
// back on every iteration. (The registers of the compiled loop itself
// are unboxed in the entry block.)
func (fe *jitFrontend) unboxLoopCarried(tb *feBlock, live *regSet) {
	written := fe.writtenInLoop(tb.pc)
	cur, st, pc := fe.cur, fe.st, fe.pc
	fe.pc = tb.pc
	for i := range tb.incoming {
		in := &tb.incoming[i]
		for slot := 0; slot < fe.info.nslots; slot++ {
			if in.st[slot].kind != skHome || !live.has(slot) || !written.has(slot) ||
				fe.info.escaped.has(slot) || fe.demoted[demoteKey{tb.pc, slot}] {
				continue
			}
			fe.cur, fe.st = in.from, in.st
			switch fe.predictKind(slot) {
			case vkInt:
				fe.unbox(slot, skInt)
			case vkFloat:
				fe.unbox(slot, skFloat)
			}
		}
	}
	fe.cur, fe.st, fe.pc = cur, st, pc
}

// joinBoxed handles a register that holds a boxed value in memory on all
// edges into the block tb (in its home slot, in another one, or inside a
// table). If the edges disagree, or the block is the header of a loop
// that replaces the value (node = node.next), the register becomes a
// reference whose address is a phi over the places the value is in. It
// reports whether it set the state of the slot.
func (fe *jitFrontend) joinBoxed(tb *feBlock, slot int, pending bool, st []slotState) bool {
	if fe.info.escaped.has(slot) {
		return false
	}
	first := &tb.incoming[0].st[slot]
	same, hasRef := true, false
	for i := range tb.incoming {
		s := &tb.incoming[i].st[slot]
		switch s.kind {
		case skRef:
			hasRef = true
		case skHome, skAlias:
		default:
			return false
		}
		same = same && *s == *first
	}
	replaced := pending && (fe.needPhi[demoteKey{tb.pc, slot}] || fe.writtenInLoop(tb.pc).has(slot))
	switch {
	case same && !replaced:
		// one place on all edges, and nothing changes that
		if first.kind != skRef {
			return false
		}
		st[slot] = *first
		return true
	case !hasRef && (!replaced || slot >= len(fe.frame) || fe.frame[slot] == nil):
		return false
	case !hasRef:
		// only worth it for values that are not numbers: those are
		// unboxed on entry instead
		if k := fe.predictKind(slot); k == vkInt || k == vkFloat {
			return false
		}
	}
	phi := fe.f.NewPhi(tb.ir, jit.TInt)
	// what the reference will see is predicted from a value that one of
	// the edges delivers: the register itself may hold something else
	// right now (nil after the loop it controls has ended)
	var sample LValue
	note := func(v LValue) {
		if sample == nil && v != nil && v != LNil {
			sample = v
		}
	}
	for i := range tb.incoming {
		in := &tb.incoming[i]
		s := &in.st[slot]
		switch s.kind {
		case skRef:
			phi.Args = append(phi.Args, s.val)
			note(fe.refPeek[s.src])
		case skAlias:
			phi.Args = append(phi.Args, fe.refHome(in.from, int(s.src)).val)
			note(fe.frame[s.src])
		default:
			phi.Args = append(phi.Args, fe.refHome(in.from, slot).val)
			note(fe.frame[slot])
		}
	}
	if sample != nil {
		fe.refPeek[int32(slot)] = sample
	}
	st[slot] = slotState{kind: skRef, val: phi, src: int32(slot)}
	return true
}

// refHome returns the state of a register that refers to the boxed value
// in the home slot of the register slot (the address is computed in the
// block blk).
func (fe *jitFrontend) refHome(blk *jit.Block, slot int) slotState {
	addr := fe.f.NewValue(blk, jit.OpAdd, jit.TInt, 0, fe.f.RegBase(), fe.f.ConstInt(blk, int64(slot)*lvalueSize))
	return slotState{kind: skRef, val: addr, src: int32(slot)}
}

// demote forces a register to stay boxed at the entry of a block and
// requests a new translation attempt.
func (fe *jitFrontend) demote(pc, slot int) {
	fe.demoted[demoteKey{pc, slot}] = true
	fe.restart = true
}

// startBlock makes tb the current block and computes its entry state from
// the edges that reached it so far. It reports false if the block is
// unreachable.
func (fe *jitFrontend) startBlock(tb *feBlock) bool {
	if len(tb.incoming) == 0 {
		return false
	}
	tb.started = true
	fe.cur = tb.ir
	if tb.npreds == 1 && len(tb.incoming) == 1 {
		in := tb.incoming[0]
		in.from.Kind = jit.BlockJump
		jit.AddEdge(in.from, tb.ir)
		fe.st = in.st
		return true
	}
	live := &fe.info.liveIn[tb.pc]
	st := make([]slotState, fe.nslots)
	pending := tb.npreds > len(tb.incoming) // back-edges will arrive later
	if pending {
		fe.unboxLoopCarried(tb, live)
	}
	for slot := 0; slot < fe.nslots; slot++ {
		if !live.has(slot) || fe.demoted[demoteKey{tb.pc, slot}] {
			continue
		}
		if fe.joinBoxed(tb, slot, pending, st) {
			continue
		}
		first := &tb.incoming[0].st[slot]
		same := true
		sameVal := true
		dirty := fe.forcedDirty[demoteKey{tb.pc, slot}]
		for i := range tb.incoming {
			s := &tb.incoming[i].st[slot]
			if s.kind != first.kind {
				same = false
				break
			}
			sameVal = sameVal && s.val == first.val
			dirty = dirty || s.dirty
		}
		if !same {
			continue
		}
		// a register that every edge delivers as the same SSA value and
		// that nothing in the region modifies needs no phi
		invariant := sameVal && !fe.needPhi[demoteKey{tb.pc, slot}] &&
			(!pending || (!fe.writtenInLoop(tb.pc).has(slot) && !fe.info.escaped.has(slot)))
		switch first.kind {
		case skInt, skFloat, skBool:
			if invariant {
				st[slot] = slotState{kind: first.kind, dirty: dirty, val: first.val}
				continue
			}
			typ := jit.TInt
			if first.kind == skFloat {
				typ = jit.TFloat
			}
			phi := fe.f.NewPhi(tb.ir, typ)
			for i := range tb.incoming {
				phi.Args = append(phi.Args, tb.incoming[i].st[slot].val)
			}
			st[slot] = slotState{kind: first.kind, dirty: dirty, val: phi}
			if first.kind == skFloat {
				fe.twinPhi(tb, slot, phi)
			}
		case skNil:
			if !pending {
				st[slot] = slotState{kind: skNil}
			}
		}
	}
	for i := range tb.incoming {
		in := &tb.incoming[i]
		fe.flushOn(in.from, in.st, tb.pc, func(slot int) bool { return st[slot].kind == skHome })
		in.from.Kind = jit.BlockJump
		jit.AddEdge(in.from, tb.ir)
	}
	tb.entry = cloneState(st)
	fe.st = st
	return true
}

// branch ends the current block with a conditional jump: to pcTrue if
// cond is non-zero, else to pcFalse.
func (fe *jitFrontend) branch(cond *jit.Value, pcTrue, pcFalse int) {
	if cond.IsConst() {
		if cond.Aux != 0 {
			fe.connect(fe.cur, pcTrue, fe.st)
		} else {
			fe.connect(fe.cur, pcFalse, fe.st)
		}
		return
	}
	b := fe.cur
	t, f := fe.f.NewBlock(), fe.f.NewBlock()
	b.Kind = jit.BlockIf
	b.Control = cond
	jit.AddEdge(b, t)
	jit.AddEdge(b, f)
	fe.connect(t, pcTrue, fe.st)
	fe.connect(f, pcFalse, fe.st)
}

// split ends the current block with a conditional jump to two new IR
// blocks and returns them (true branch first).
func (fe *jitFrontend) split(cond *jit.Value) (*jit.Block, *jit.Block) {
	b := fe.cur
	t, f := fe.f.NewBlock(), fe.f.NewBlock()
	b.Kind = jit.BlockIf
	b.Control = cond
	jit.AddEdge(b, t)
	jit.AddEdge(b, f)
	return t, f
}

// jumpIR ends block from with a jump to the IR block to.
func jumpIR(from, to *jit.Block) {
	from.Kind = jit.BlockJump
	jit.AddEdge(from, to)
}

/* }}} */

/* values {{{ */

func (fe *jitFrontend) constInt(c int64) *jit.Value { return fe.f.ConstInt(fe.cur, c) }

func (fe *jitFrontend) op(o jit.Op, typ jit.Type, args ...*jit.Value) *jit.Value {
	fe.nativeOps++
	return fe.f.NewValue(fe.cur, o, typ, 0, args...)
}

// loadMem is load for memory that compiled code writes itself: elements
// and length of unboxed array parts, number and kind of table fields.
func (fe *jitFrontend) loadMem(mem uint8, o jit.Op, typ jit.Type, base *jit.Value, disp int64) *jit.Value {
	v := fe.load(o, typ, base, disp)
	v.Mem = mem
	return v
}

// store emits a store of val to memory of the given class.
func (fe *jitFrontend) store(mem uint8, o jit.Op, base *jit.Value, disp int64, val *jit.Value) {
	fe.f.NewValue(fe.cur, o, jit.TInt, disp, base, val).Mem = mem
}

// load emits a load from memory that compiled code never writes (the
// registers, table headers, keys, boxed values): the optimizer may reuse
// its result until Go code runs again.
func (fe *jitFrontend) load(o jit.Op, typ jit.Type, base *jit.Value, disp int64) *jit.Value {
	v := fe.f.NewValue(fe.cur, o, typ, disp, base)
	v.Mem = jit.MemStable
	return v
}

// A boxed value is read from a location: the home slot of a register,
// identified by the slot number, the place inside a table that a
// register refers to (skRef), identified by refLoc of that register, or
// the constant a register holds (skConst: a table or function found in an
// upvalue or a global), identified by constLoc of that register. The
// words of a constant are known when the code is compiled. A constant
// that no register holds (the environment table) is identified by
// poolLoc of its index in the constant pool.

// refBias, constBias and poolBias distinguish the kinds of locations.
const (
	refBias   = 1 << 12
	constBias = 1 << 13
	poolBias  = 1 << 14
)

// poolLoc returns the location of a constant of the unit pool.
func poolLoc(idx int32) int { return int(idx) + poolBias }

// refLoc returns the location of the value the register slot refers to.
func refLoc(slot int) int { return slot + refBias }

// constLoc returns the location of the constant the register slot holds.
func constLoc(slot int) int { return slot + constBias }

// locSlot returns the register a location belongs to: the home slot or
// the register that holds the reference or the constant. A constant of
// the pool belongs to no register; register zero stands in where one is
// needed to name the site of a speculation.
func locSlot(loc int) int {
	if loc >= poolBias {
		return 0
	}
	return loc &^ (refBias | constBias)
}

// constAt returns the constant at a constant location.
func (fe *jitFrontend) constAt(loc int) LValue {
	if loc >= poolBias {
		return fe.consts[loc-poolBias]
	}
	return fe.consts[fe.st[locSlot(loc)].src]
}

// firstElement returns an element of the generic array part of the table
// v as a sample of what the array holds, or nil.
func firstElement(v LValue) LValue {
	tb, ok := v.(*LTable)
	if !ok || tb.akind != arrayKindGeneric {
		return nil
	}
	for _, e := range tb.array {
		if e != nil && e != LNil {
			return e
		}
	}
	return nil
}

// peek returns the value that was last seen at a location: for a home
// slot its current content, for a reference what the register held when
// the interpreter last ran this code, for a constant the constant.
func (fe *jitFrontend) peek(loc int) LValue {
	slot := loc
	if loc >= constBias {
		return fe.constAt(loc)
	}
	if loc >= refBias {
		slot = int(fe.st[locSlot(loc)].src)
		if v, ok := fe.refPeek[int32(slot)]; ok {
			return v
		}
	}
	if slot < len(fe.frame) {
		return fe.frame[slot]
	}
	return nil
}

// slotItab loads the type word of the boxed value at a location.
func (fe *jitFrontend) slotItab(loc int) *jit.Value {
	if loc >= constBias {
		return fe.constInt(int64(itabOf(fe.constAt(loc))))
	}
	if loc >= refBias {
		return fe.load(jit.OpLoad64, jit.TInt, fe.st[locSlot(loc)].val, 0)
	}
	return fe.load(jit.OpLoad64, jit.TInt, fe.f.RegBase(), int64(loc)*lvalueSize)
}

// slotData loads the data word of the boxed value at a location.
func (fe *jitFrontend) slotData(loc int) *jit.Value {
	if loc >= constBias {
		return fe.constInt(int64(uintptr(dataOf(fe.constAt(loc)))))
	}
	if loc >= refBias {
		return fe.load(jit.OpLoad64, jit.TInt, fe.st[locSlot(loc)].val, 8)
	}
	return fe.load(jit.OpLoad64, jit.TInt, fe.f.RegBase(), int64(loc)*lvalueSize+8)
}

// unbox loads the number in the home slot into an SSA value, guarded by a
// type check.
func (fe *jitFrontend) unbox(slot int, kind slotKind) *jit.Value {
	itab := int64(itabInteger)
	if kind == skFloat {
		itab = int64(itabNumber)
	}
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(slot), fe.constInt(itab)), slot, fbValue)
	p := fe.slotData(slot)
	var v *jit.Value
	if kind == skFloat {
		v = fe.load(jit.OpLoadF64, jit.TFloat, p, 0)
	} else {
		v = fe.load(jit.OpLoad64, jit.TInt, p, 0)
	}
	if !fe.info.escaped.has(slot) {
		fe.st[slot] = slotState{kind: kind, val: v}
	}
	return v
}

// unboxRef unboxes the number a register refers to (skRef). The home
// slot of the register does not hold it.
func (fe *jitFrontend) unboxRef(slot int, kind slotKind) *jit.Value {
	itab := int64(itabInteger)
	if kind == skFloat {
		itab = int64(itabNumber)
	}
	loc := refLoc(slot)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(loc), fe.constInt(itab)), slot, fbValue)
	p := fe.slotData(loc)
	var v *jit.Value
	if kind == skFloat {
		v = fe.load(jit.OpLoadF64, jit.TFloat, p, 0)
	} else {
		v = fe.load(jit.OpLoad64, jit.TInt, p, 0)
	}
	fe.st[slot] = slotState{kind: kind, dirty: true, val: v}
	return v
}

// predictKind returns the value kind expected in a home slot at the
// current instruction: recorded feedback first, else the value the
// register holds right now.
func (fe *jitFrontend) predictKind(slot int) uint8 {
	if k, ok := fe.jp.feedback[feedbackKey{fe.fbpc(), int16(slot), fbValue}]; ok {
		return k
	}
	return valueKind(fe.frame[slot])
}

// homeSlot resolves a register holding a boxed value to the location
// the value is read from: the home slot that contains it, the place in
// a table the register refers to or the constant the register holds. ok
// is false for registers that hold an unboxed value or nil.
func (fe *jitFrontend) homeSlot(slot int) (int, bool) {
	switch s := &fe.st[slot]; s.kind {
	case skHome:
		return slot, true
	case skAlias:
		return int(s.src), true
	case skRef:
		return refLoc(slot), true
	case skConst:
		return constLoc(slot), true
	}
	return 0, false
}

// num returns the unboxed number in a register, unboxing it if type
// prediction says it is a number. ok is false if the register does not
// (predictably) hold a number.
func (fe *jitFrontend) num(slot int) (v *jit.Value, kind slotKind, ok bool) {
	s := &fe.st[slot]
	switch s.kind {
	case skInt, skFloat:
		return s.val, s.kind, true
	case skHome:
		switch fe.predictKind(slot) {
		case vkInt:
			return fe.unbox(slot, skInt), skInt, true
		case vkFloat:
			return fe.unbox(slot, skFloat), skFloat, true
		}
	case skRef:
		switch valueKind(fe.peek(refLoc(slot))) {
		case vkInt:
			return fe.unboxRef(slot, skInt), skInt, true
		case vkFloat:
			return fe.unboxRef(slot, skFloat), skFloat, true
		}
	}
	return nil, 0, false
}

// rkNum returns the number denoted by a register-or-constant operand.
func (fe *jitFrontend) rkNum(rk int) (*jit.Value, slotKind, bool) {
	if rk&opBitRk != 0 {
		switch c := fe.proto.Constants[rk&^opBitRk].(type) {
		case LInteger:
			return fe.constInt(int64(c)), skInt, true
		case LNumber:
			return fe.f.ConstFloat(fe.cur, float64(c)), skFloat, true
		}
		return nil, 0, false
	}
	return fe.num(rk)
}

// toFloat converts an unboxed number to a float value.
func (fe *jitFrontend) toFloat(v *jit.Value, kind slotKind) *jit.Value {
	if kind == skFloat {
		return v
	}
	return fe.op(jit.OpIntToFloat, jit.TFloat, v)
}

// set records the result of an instruction in a register.
func (fe *jitFrontend) set(slot int, kind slotKind, v *jit.Value) {
	fe.st[slot] = slotState{kind: kind, dirty: true, val: v}
}

// constIndex adds a boxed constant to the unit pool.
func (fe *jitFrontend) constIndex(v LValue) int32 {
	fe.consts = append(fe.consts, v)
	return int32(len(fe.consts) - 1)
}

/* }}} */

/* instructions {{{ */

// inst translates the instruction at pc. It returns the pc of the next
// instruction and whether the instruction ended the current block.
func (fe *jitFrontend) inst(pc int) (next int, ended bool) {
	inst := fe.code(pc)
	op := opGetOpCode(inst)
	A, B, C := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	next = pc + 1
	fe.insts++
	openTop := fe.openTop
	fe.openTop = -1
	fe.pendingTop = openTop
	// an instruction whose native form failed too often is executed by
	// the interpreter (not in an inlined callee, which has no frame)
	interpret := fe.inl == 0 && fe.jp.feedback[feedbackKey{fe.fbpc(), -1, fbCallout}] >= jitCalloutStrikes
	if interpret && interpretable(op) {
		return fe.generic(pc, op)
	}
	switch op {
	case OP_MOVE, OP_MOVEN:
		fe.move(A, B)
	case OP_LOADK:
		switch c := fe.proto.Constants[opGetArgBx(inst)].(type) {
		case LInteger:
			fe.set(A, skInt, fe.constInt(int64(c)))
		case LNumber:
			fe.set(A, skFloat, fe.f.ConstFloat(fe.cur, float64(c)))
		default:
			fe.st[A] = slotState{kind: skConst, src: fe.constIndex(c)}
		}
	case OP_LOADBOOL:
		if B != 0 {
			fe.set(A, skBool, fe.constInt(1))
		} else {
			fe.set(A, skBool, fe.constInt(0))
		}
		if C != 0 {
			fe.connect(fe.cur, pc+2, fe.st)
			return 0, true
		}
	case OP_LOADNIL:
		for r := A; r <= B; r++ {
			fe.st[r] = slotState{kind: skNil}
		}
	case OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW, OP_IDIV, OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR:
		if !fe.arith(op, A, B, C) {
			return fe.generic(pc, op)
		}
	case OP_UNM:
		v, kind, ok := fe.rkNum(B)
		if !ok {
			return fe.generic(pc, op)
		}
		if kind == skInt {
			fe.set(A, skInt, fe.op(jit.OpNeg, jit.TInt, v))
		} else {
			r := fe.op(jit.OpFNeg, jit.TFloat, v)
			if t, ok := fe.twin(v); ok && !v.IsConst() {
				fe.setTwin(r, fe.op(jit.OpNeg, jit.TInt, t.v), t.bits)
			}
			fe.set(A, skFloat, r)
		}
	case OP_BNOT:
		v, kind, ok := fe.rkNum(B)
		if !ok || kind != skInt {
			return fe.generic(pc, op)
		}
		fe.set(A, skInt, fe.op(jit.OpNot, jit.TInt, v))
	case OP_NOT:
		switch s := &fe.st[B]; s.kind {
		case skNil:
			fe.set(A, skBool, fe.constInt(1))
		case skBool:
			fe.set(A, skBool, fe.op(jit.OpXor, jit.TInt, s.val, fe.constInt(1)))
		case skInt, skFloat, skConst:
			fe.set(A, skBool, fe.constInt(0))
		default:
			return fe.generic(pc, op)
		}
	case OP_LEN:
		if !fe.length(A, B) {
			return fe.generic(pc, op)
		}
	case OP_JMP:
		fe.connect(fe.cur, pc+1+opGetArgSbx(inst), fe.st)
		return 0, true
	case OP_EQ, OP_LT, OP_LE:
		fe.compare(op, A, B, C, !interpret)
		return 0, true
	case OP_TEST:
		// if truthy(R(A)) == (C == 0) then skip
		fe.test(A, func(truthy bool) int {
			if truthy == (C == 0) {
				return pc + 2
			}
			return pc + 1
		}, nil)
		return 0, true
	case OP_TESTSET:
		// if truthy(R(B)) != (C == 0) then R(A) := R(B) else skip
		assigns := func(truthy bool) bool { return truthy != (C == 0) }
		fe.test(B, func(truthy bool) int {
			if assigns(truthy) {
				return pc + 1
			}
			return pc + 2
		}, func(truthy bool) {
			if assigns(truthy) {
				fe.move(A, B)
			}
		})
		return 0, true
	case OP_FORPREP:
		fe.forPrep(A, pc+1, pc+1+opGetArgSbx(inst))
		return 0, true
	case OP_FORLOOP:
		fe.forLoop(A, pc+1+opGetArgSbx(inst), pc+1)
		return 0, true
	case OP_GETTABLE:
		if !fe.getTable(A, B, C) {
			return fe.generic(pc, op)
		}
	case OP_GETGLOBAL, OP_GETENV:
		if !fe.getGlobal(A, opGetArgBx(inst)) {
			return fe.generic(pc, op)
		}
	case OP_SETGLOBAL, OP_SETENV:
		if !fe.setGlobal(A, opGetArgBx(inst)) {
			return fe.generic(pc, op)
		}
	case OP_GETUPVAL:
		if !fe.getUpval(A, B) {
			return fe.generic(pc, op)
		}
	case OP_SELF:
		if !fe.selfMethod(A, B, C) {
			return fe.generic(pc, op)
		}
	case OP_TFORLOOP:
		if fe.inl != 0 {
			return fe.generic(pc, op)
		}
		fe.genericFor(A, B, C)
		return 0, true
	case OP_GETTABLEKS:
		if !fe.constField(A, B, C) && !fe.getField(A, B, C) {
			return fe.generic(pc, op)
		}
	case OP_SETTABLEKS:
		if !fe.setField(A, B, C) {
			return fe.generic(pc, op)
		}
	case OP_CALL:
		if B == 0 {
			// the arguments end with an open result list
			if openTop < 0 {
				return fe.generic(pc, op)
			}
			B = openTop - A
		}
		if !fe.intrinsicCall(A, B, C) {
			if done, ended := fe.inlineCall(A, B, C); done {
				if ended {
					return 0, true
				}
				break
			}
			return fe.generic(pc, op)
		}
	case OP_SETTABLE:
		if !fe.setTable(A, B, C) {
			return fe.generic(pc, op)
		}
	case OP_NOP:
	default:
		return fe.generic(pc, op)
	}
	return next, false
}

// interpretable reports whether the interpreter can execute a single
// instruction with this operation on behalf of compiled code, whatever
// its operands are.
func interpretable(op int) bool {
	switch op {
	case OP_MOVE, OP_MOVEN, OP_LOADK, OP_LOADNIL, OP_GETUPVAL, OP_GETGLOBAL, OP_GETENV,
		OP_GETTABLE, OP_GETTABLEKS, OP_SETGLOBAL, OP_SETENV, OP_SETUPVAL, OP_SETTABLE,
		OP_SETTABLEKS, OP_NEWTABLE, OP_SELF, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW,
		OP_IDIV, OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR, OP_UNM, OP_BNOT, OP_NOT, OP_LEN,
		OP_CONCAT, OP_CLOSE, OP_CLOSURE, OP_ERRNNIL, OP_TBC:
		return true
	}
	return false
}

// generic handles an instruction that has no native translation: simple
// instructions are executed by the interpreter through a callout, others
// end the compiled region.
func (fe *jitFrontend) generic(pc, op int) (int, bool) {
	if fe.inl != 0 {
		// the interpreter cannot run a single instruction of a function
		// that has no frame: hand over for good
		fe.unsupported()
		return 0, true
	}
	inst := fe.proto.Code[pc]
	A, B, C := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	next := fe.info.effects[pc].succs[0]
	if interpretable(op) {
		fe.calloutInst()
		return next, false
	}
	switch op {
	case OP_SETLIST:
		if (B != 0 || fe.pendingTop >= 0) && C != 0 {
			fe.calloutInst()
			return next, false
		}
	case OP_CALL:
		// calls of Go functions complete inside the callout; when the
		// callee turns out to be a Lua function the driver hands the
		// frame over to the interpreter
		// (an open argument list is fine if its end is known: the
		// callout restores the registry top)
		if (B != 0 || fe.pendingTop >= 0) && C != 0 {
			fe.calloutInst()
			for r := A; r < fe.nslots; r++ {
				fe.st[r] = slotState{}
			}
			return next, false
		}
	}
	fe.unsupported()
	return 0, true
}

// functionEnv returns the table in which the global accesses of a Lua
// function are resolved, or nil if it is not a plain table.
func functionEnv(fn *LFunction) *LTable {
	if fn == nil || fn.IsG {
		return nil
	}
	if idx := int(fn.Proto.EnvUpvalue); idx >= 0 {
		if idx < len(fn.Upvalues) && fn.Upvalues[idx] != nil {
			tb, _ := fn.Upvalues[idx].Value().(*LTable)
			return tb
		}
		return nil
	}
	if fn.Proto.Version == Lua55 {
		return nil
	}
	return fn.Env
}

// guardVersion makes the compiled code depend on the string-keyed
// function and table entries of tb staying unchanged.
func (fe *jitFrontend) guardVersion(tb *LTable) {
	tb.watched = true
	fe.keep = append(fe.keep, tb)
	addr := fe.constInt(int64(uintptr(unsafe.Pointer(&tb.version))))
	cur := fe.load(jit.OpLoad32, jit.TInt, addr, 0)
	fe.guard(fe.op(jit.OpEq, jit.TInt, cur, fe.constInt(int64(tb.version))), -1, 0)
}

// constValue reports whether v may be treated as a constant of the
// compiled code: functions and tables found under a string key, whose
// replacement bumps the version of the containing table.
func constValue(v LValue) bool {
	switch v.(type) {
	case *LFunction, *LTable:
		return true
	}
	return false
}

// constGlobal translates the load of a global that holds a function or a
// table (such as "math") into a guarded constant.
func (fe *jitFrontend) constGlobal(a, kidx int) bool {
	if fe.env == nil {
		return false
	}
	v := fe.env.RawGetString(fe.proto.stringConstants[kidx])
	if !constValue(v) {
		return false
	}
	fe.dependOnEnv()
	fe.guardVersion(fe.env)
	fe.st[a] = slotState{kind: skConst, src: fe.constIndex(v)}
	return true
}

// dependOnEnv makes the code depend on the identity of the environment
// table of the function that is being translated.
func (fe *jitFrontend) dependOnEnv() {
	if fe.inl != 0 {
		// the environment of an inlined callee is checked where it is
		// used: the entry check only covers the compiled function
		cur := fe.load(jit.OpLoad64, jit.TInt, fe.closureAddr(), int64(offFnEnv))
		fe.guard(fe.op(jit.OpEq, jit.TInt, cur, fe.constInt(int64(uintptr(unsafe.Pointer(fe.env))))), -1, 0)
	} else {
		fe.usesEnv = true
	}
}

// envLoc returns the location of the environment table, on whose
// identity the code depends from here on.
func (fe *jitFrontend) envLoc() int {
	fe.dependOnEnv()
	if fe.envConst < 0 || fe.inl != 0 {
		// (an inlined callee can have an environment of its own)
		idx := fe.constIndex(fe.env)
		if fe.inl != 0 {
			return poolLoc(idx)
		}
		fe.envConst = idx
	}
	return poolLoc(fe.envConst)
}

// envField reports whether the environment table has an entry for a
// global right now and whether that entry holds a number.
func (fe *jitFrontend) envField(kidx int) (key string, present, number bool) {
	key = fe.proto.stringConstants[kidx]
	if fe.env == nil {
		return key, false, false
	}
	i := fe.env.findField(key)
	if i < 0 || fe.env.fields[i].removed() {
		return key, false, false
	}
	return key, true, fe.env.fields[i].kind != fieldBoxed
}

// getGlobal translates R(a) := Gbl[Kst(kidx)]: a function or a table is
// a constant, any other value that exists is read like a field of the
// environment table. A global that does not exist is left to the
// interpreter, which may have to consult a metatable.
func (fe *jitFrontend) getGlobal(a, kidx int) bool {
	if fe.constGlobal(a, kidx) {
		return true
	}
	key, present, _ := fe.envField(kidx)
	return present && fe.getFieldAt(a, fe.envLoc(), key)
}

// setGlobal translates Gbl[Kst(kidx)] := R(a) for a number that replaces
// a number.
func (fe *jitFrontend) setGlobal(a, kidx int) bool {
	key, _, number := fe.envField(kidx)
	if _, ok := fe.numKind(a); !ok || !number {
		return false
	}
	return fe.setFieldAt(fe.envLoc(), key, a)
}

// constField translates R(a) := R(b)[K(c)] when R(b) is a constant table
// and the field holds a function or a table (such as "math.floor").
func (fe *jitFrontend) constField(a, b, c int) bool {
	s := &fe.st[b]
	if s.kind != skConst || c&opBitRk == 0 {
		return false
	}
	tb, ok := fe.consts[s.src].(*LTable)
	if !ok {
		return false
	}
	v := tb.RawGetString(fe.proto.stringConstants[c&^opBitRk])
	if !constValue(v) {
		return false
	}
	fe.guardVersion(tb)
	fe.st[a] = slotState{kind: skConst, src: fe.constIndex(v)}
	return true
}

// refTo makes register a refer to the boxed value at an address; sample
// is a value like the ones that will be found there.
func (fe *jitFrontend) refTo(a int, addr *jit.Value, sample LValue) {
	fe.st[a] = slotState{kind: skRef, val: addr, src: int32(a)}
	if sample != nil {
		fe.refPeek[int32(a)] = sample
	} else {
		delete(fe.refPeek, int32(a))
	}
}

// move translates R(a) := R(b).
func (fe *jitFrontend) move(a, b int) {
	s := fe.st[b]
	switch s.kind {
	case skInt, skFloat, skBool:
		fe.set(a, s.kind, s.val)
	case skNil, skAlias, skConst, skRef:
		fe.st[a] = s
	default:
		// a boxed value: try to unbox numbers, else record an alias
		if v, kind, ok := fe.num(b); ok {
			fe.set(a, kind, v)
			return
		}
		if a != b {
			fe.st[a] = slotState{kind: skAlias, src: int32(b)}
		}
	}
}

// arith translates a binary arithmetic or bitwise instruction. It
// reports false if the operands are not numbers of a supported shape.
func (fe *jitFrontend) arith(op, a, b, c int) bool {
	x, xk, ok1 := fe.rkNum(b)
	if !ok1 {
		return false
	}
	y, yk, ok2 := fe.rkNum(c)
	if !ok2 {
		return false
	}
	bothInt := xk == skInt && yk == skInt
	switch op {
	case OP_ADD, OP_SUB, OP_MUL:
		if bothInt {
			o := map[int]jit.Op{OP_ADD: jit.OpAdd, OP_SUB: jit.OpSub, OP_MUL: jit.OpMul}[op]
			fe.set(a, skInt, fe.op(o, jit.TInt, x, y))
			return true
		}
		o := map[int]jit.Op{OP_ADD: jit.OpFAdd, OP_SUB: jit.OpFSub, OP_MUL: jit.OpFMul}[op]
		r := fe.op(o, jit.TFloat, fe.toFloat(x, xk), fe.toFloat(y, yk))
		if xk == skFloat && yk == skFloat {
			fe.deriveTwin(map[int]jit.Op{OP_ADD: jit.OpAdd, OP_SUB: jit.OpSub, OP_MUL: jit.OpMul}[op], r, x, y)
		}
		fe.set(a, skFloat, r)
		return true
	case OP_DIV:
		fe.set(a, skFloat, fe.op(jit.OpFDiv, jit.TFloat, fe.toFloat(x, xk), fe.toFloat(y, yk)))
		return true
	case OP_POW:
		// only the common constant exponents have a native form
		if !y.IsConst() {
			return false
		}
		e := float64(y.Aux)
		if yk == skFloat {
			e = y.Float()
		}
		fx := fe.toFloat(x, xk)
		switch e {
		case 2:
			fe.set(a, skFloat, fe.op(jit.OpFMul, jit.TFloat, fx, fx))
		case 0.5:
			// pow(-0.0, 0.5) is +0 and pow(-inf, 0.5) is +inf, unlike sqrt
			fe.guard(fe.op(jit.OpFLt, jit.TInt, fe.f.ConstFloat(fe.cur, 0), fx), -1, 0)
			fe.set(a, skFloat, fe.op(jit.OpFSqrt, jit.TFloat, fx))
		default:
			return false
		}
		return true
	case OP_IDIV, OP_MOD:
		if bothInt {
			if !y.IsConst() || y.Aux == 0 {
				fe.guard(fe.op(jit.OpNe, jit.TInt, y, fe.constInt(0)), -1, 0)
			}
			o := jit.OpDiv
			if op == OP_MOD {
				o = jit.OpMod
			}
			fe.set(a, skInt, fe.op(o, jit.TInt, x, y))
			return true
		}
		if op == OP_IDIV {
			q := fe.op(jit.OpFDiv, jit.TFloat, fe.toFloat(x, xk), fe.toFloat(y, yk))
			fe.set(a, skFloat, fe.op(jit.OpFFloor, jit.TFloat, q))
			return true
		}
		return fe.floatModIntegral(a, x, xk, y, yk)
	case OP_BAND, OP_BOR, OP_BXOR:
		if !bothInt {
			return false
		}
		o := map[int]jit.Op{OP_BAND: jit.OpAnd, OP_BOR: jit.OpOr, OP_BXOR: jit.OpXor}[op]
		fe.set(a, skInt, fe.op(o, jit.TInt, x, y))
		return true
	case OP_SHL, OP_SHR:
		if !bothInt {
			return false
		}
		left := op == OP_SHL
		if y.IsConst() {
			n := y.Aux
			if n < 0 && n > -64 {
				left, n = !left, -n
			}
			if n < 0 || n >= 64 {
				fe.set(a, skInt, fe.constInt(0))
				return true
			}
			y = fe.constInt(n)
		} else {
			// shift counts outside 0..63 are rare: deoptimize
			fe.guard(fe.op(jit.OpULt, jit.TInt, y, fe.constInt(64)), -1, 0)
		}
		o := jit.OpShr
		if left {
			o = jit.OpShl
		}
		fe.set(a, skInt, fe.op(o, jit.TInt, x, y))
		return true
	}
	return false
}

// floatExactInt converts a number that takes part in float arithmetic to
// an integer, deoptimizing unless its float value is an exact integer.
// An integer operand is first converted to a float like the interpreter
// does, which rounds beyond 2^53.
func (fe *jitFrontend) floatExactInt(v *jit.Value, kind slotKind) *jit.Value {
	if kind == skInt {
		if v.IsConst() && v.Aux >= -(1<<53) && v.Aux <= 1<<53 {
			return v
		}
		v = fe.op(jit.OpIntToFloat, jit.TFloat, v)
	} else if t, ok := fe.twin(v); ok {
		return t.v
	}

	fe.guard(fe.op(jit.OpFLt, jit.TInt, v, fe.f.ConstFloat(fe.cur, 9223372036854775808.0)), -1, 0)
	i := fe.op(jit.OpFloatToInt, jit.TInt, v)
	fe.guard(fe.op(jit.OpFEq, jit.TInt, fe.op(jit.OpIntToFloat, jit.TFloat, i), v), -1, 0)
	return i
}

// floatModIntegral translates a float modulo whose operands hold integral
// values, the usual case in Lua 5.1 code where every number is a float.
// The remainder is computed with integers, which is exact; other operand
// values deoptimize. A zero remainder takes the sign of the dividend
// (negative zero for a negative or negative zero dividend), which the
// product of the dividend and zero yields without leaving native code.
func (fe *jitFrontend) floatModIntegral(a int, x *jit.Value, xk slotKind, y *jit.Value, yk slotKind) bool {
	ix := fe.floatExactInt(x, xk)
	iy := fe.floatExactInt(y, yk)
	fe.guard(fe.op(jit.OpNe, jit.TInt, iy, fe.constInt(0)), -1, 0)
	r := fe.op(jit.OpMod, jit.TInt, ix, iy)
	xf := fe.toFloat(x, xk)
	nonZero, zero := fe.split(fe.op(jit.OpNe, jit.TInt, r, fe.constInt(0)))
	join := fe.f.NewBlock()

	fe.cur = nonZero
	remainder := fe.op(jit.OpIntToFloat, jit.TFloat, r)
	jumpIR(fe.cur, join)

	fe.cur = zero
	signedZero := fe.op(jit.OpFMul, jit.TFloat, xf, fe.f.ConstFloat(fe.cur, 0))
	jumpIR(fe.cur, join)

	fe.cur = join
	result := fe.f.NewPhi(join, jit.TFloat)
	result.Args = []*jit.Value{remainder, signedZero}
	if yk == skFloat {
		// the remainder is smaller than the divisor
		if ty, ok := fe.twin(y); ok {
			fe.setTwin(result, r, ty.bits)
		}
	}
	fe.set(a, skFloat, result)
	return true
}

// intAsFloat converts an integer operand of a mixed comparison to a
// float, guarding that the conversion is exact.
func (fe *jitFrontend) intAsFloat(v *jit.Value) *jit.Value {
	if v.IsConst() {
		if v.Aux >= -(1<<53) && v.Aux <= 1<<53 {
			return fe.f.ConstFloat(fe.cur, float64(v.Aux))
		}
	}
	// |v| <= 2^53  <=>  (v + 2^53) unsigned <= 2^54
	shifted := fe.op(jit.OpAdd, jit.TInt, v, fe.constInt(1<<53))
	fe.guard(fe.op(jit.OpULt, jit.TInt, shifted, fe.constInt(1<<54+1)), -1, 0)
	return fe.op(jit.OpIntToFloat, jit.TFloat, v)
}

// compare translates OP_EQ, OP_LT and OP_LE followed by a conditional
// skip of the next instruction.
func (fe *jitFrontend) compare(op, a, b, c int, native bool) {
	pc := fe.pc
	// the next instruction is skipped when result == (A == 0)
	pcTrue, pcFalse := pc+1, pc+2
	if a == 0 {
		pcTrue, pcFalse = pc+2, pc+1
	}
	if native {
		if cond := fe.compareValue(op, b, c); cond != nil {
			fe.branch(cond, pcTrue, pcFalse)
			return
		}
	}
	// generic comparison: the interpreter executes it and reports whether
	// it skipped the next instruction
	if fe.inl != 0 {
		// (not for an inlined callee, which has no frame: see generic)
		fe.unsupported()
		return
	}
	fe.calloutInst()
	res := fe.loadMem(jit.MemNone, jit.OpLoad64, jit.TInt, fe.f.Ctx(), jit.CtxResult)
	fe.branch(fe.op(jit.OpNe, jit.TInt, res, fe.constInt(0)), pc+2, pc+1)
}

// compareValue returns the boolean value of a comparison if it can be
// computed natively.
func (fe *jitFrontend) compareValue(op, b, c int) *jit.Value {
	if op == OP_EQ {
		if eq, known := fe.constantEquality(b, c); known {
			if eq {
				return fe.constInt(1)
			}
			return fe.constInt(0)
		}
	}
	if op == OP_EQ && fe.isString(b) && fe.isString(c) {
		return fe.stringEq(b, c)
	}
	if op == OP_EQ && b&opBitRk == 0 && c&opBitRk == 0 {
		// comparisons against nil and between booleans
		sb, sc := &fe.st[b], &fe.st[c]
		if sc.kind == skNil {
			sb, sc = sc, sb
			b, c = c, b
		}
		if sb.kind == skNil {
			switch sc.kind {
			case skNil:
				return fe.constInt(1)
			case skInt, skFloat, skBool, skConst:
				return fe.constInt(0)
			}
			if slot, ok := fe.homeSlot(c); ok {
				return fe.op(jit.OpEq, jit.TInt, fe.slotItab(slot), fe.constInt(int64(itabNil)))
			}
		}
		if sb.kind == skBool && sc.kind == skBool {
			return fe.op(jit.OpEq, jit.TInt, sb.val, sc.val)
		}
	}
	x, xk, ok1 := fe.rkNum(b)
	if !ok1 {
		return nil
	}
	y, yk, ok2 := fe.rkNum(c)
	if !ok2 {
		return nil
	}
	if xk == skInt && yk == skInt {
		o := map[int]jit.Op{OP_EQ: jit.OpEq, OP_LT: jit.OpLt, OP_LE: jit.OpLe}[op]
		return fe.op(o, jit.TInt, x, y)
	}
	if xk == skInt {
		x = fe.intAsFloat(x)
	}
	if yk == skInt {
		y = fe.intAsFloat(y)
	}
	o := map[int]jit.Op{OP_EQ: jit.OpFEq, OP_LT: jit.OpFLt, OP_LE: jit.OpFLe}[op]
	return fe.op(o, jit.TInt, x, y)
}

// test branches on the truthiness of a register. target maps the outcome
// to the next pc; assign, if not nil, is applied to the state of each
// outcome before the edge is created.
func (fe *jitFrontend) test(slot int, target func(truthy bool) int, assign func(truthy bool)) {
	finish := func(truthy bool) {
		saved := cloneState(fe.st)
		if assign != nil {
			assign(truthy)
		}
		fe.connect(fe.cur, target(truthy), fe.st)
		fe.st = saved
	}
	s := &fe.st[slot]
	switch s.kind {
	case skNil:
		finish(false)
		return
	case skInt, skFloat, skConst:
		finish(true)
		return
	case skBool:
		if s.val.IsConst() {
			finish(s.val.Aux != 0)
			return
		}
		t, f := fe.split(s.val)
		fe.cur = t
		finish(true)
		fe.cur = f
		finish(false)
		return
	}
	home, _ := fe.homeSlot(slot)
	// a boxed value: nil and false are falsy, everything else is truthy
	itab := fe.slotItab(home)
	truthyB, falsyB := fe.f.NewBlock(), fe.f.NewBlock()
	isNil, notNil := fe.split(fe.op(jit.OpEq, jit.TInt, itab, fe.constInt(int64(itabNil))))
	jumpIR(isNil, falsyB)
	fe.cur = notNil
	isBool, notBool := fe.split(fe.op(jit.OpEq, jit.TInt, itab, fe.constInt(int64(itabBool))))
	jumpIR(notBool, truthyB)
	fe.cur = isBool
	bv := fe.load(jit.OpLoad8, jit.TInt, fe.slotData(home), 0)
	isTrue, isFalse := fe.split(fe.op(jit.OpNe, jit.TInt, bv, fe.constInt(0)))
	jumpIR(isTrue, truthyB)
	jumpIR(isFalse, falsyB)
	fe.cur = truthyB
	finish(true)
	fe.cur = falsyB
	finish(false)
}

// forPrep translates OP_FORPREP: the control values are in R(a..a+2).
func (fe *jitFrontend) forPrep(a, pcBody, pcExit int) {
	init, ik, ok1 := fe.num(a)
	limit, lk, ok2 := fe.num(a + 1)
	step, sk, ok3 := fe.num(a + 2)
	if !ok1 || !ok2 || !ok3 {
		fe.exitBlock()
		return
	}
	positive, ok := fe.stepDirection(a+2, step, sk)
	if !ok {
		fe.exitBlock()
		return
	}
	var skip *jit.Value
	if ik == skInt && sk == skInt {
		if lk != skInt {
			fe.exitBlock()
			return
		}
		if positive {
			skip = fe.op(jit.OpLt, jit.TInt, limit, init)
		} else {
			skip = fe.op(jit.OpLt, jit.TInt, init, limit)
		}
		fe.set(a, skInt, init)
		fe.set(a+1, skInt, limit)
		fe.set(a+2, skInt, step)
		fe.set(a+3, skInt, init)
	} else {
		finit, flimit := fe.toFloat(init, ik), fe.toFloat(limit, lk)
		fstep := fe.toFloat(step, sk)
		if ninit, nstep, bound, ok := fe.narrowForPrep(a, finit, flimit, fstep); ok {
			// integers of a limited size: the first index of Lua 5.1,
			// (init - step) + step, is exact, and no operand is a NaN
			finit, fstep = ninit, nstep
			fe.loopBits[pcBody] = bound
		} else {
			if !fe.L.lang55 {
				// Lua 5.1 computes the first index as (init - step) + step
				finit = fe.op(jit.OpFAdd, jit.TFloat, fe.op(jit.OpFSub, jit.TFloat, finit, fstep), fstep)
			}
			// the loop runs unless the limit is already passed;
			// comparisons with NaN are false, which the interpreter
			// treats differently in the two profiles, so NaN operands
			// deoptimize
			fe.guard(fe.op(jit.OpFEq, jit.TInt, flimit, flimit), -1, 0)
			fe.guard(fe.op(jit.OpFEq, jit.TInt, finit, finit), -1, 0)
		}
		if positive {
			skip = fe.op(jit.OpFLt, jit.TInt, flimit, finit)
		} else {
			skip = fe.op(jit.OpFLt, jit.TInt, finit, flimit)
		}
		fe.set(a, skFloat, finit)
		fe.set(a+1, skFloat, flimit)
		fe.set(a+2, skFloat, fstep)
		fe.set(a+3, skFloat, finit)
	}
	fe.branch(skip, pcExit, pcBody)
}

// stepDirection determines the direction of a numeric for loop from its
// step. A constant step is known; for any other step the direction it
// has right now (or a positive one if the loop did not run yet) is
// assumed and guarded: the step is not zero, not NaN and has that sign.
// It reports false if the loop cannot be translated (a zero step).
func (fe *jitFrontend) stepDirection(slot int, step *jit.Value, kind slotKind) (positive bool, ok bool) {
	if step.IsConst() {
		if kind == skInt {
			return step.Aux > 0, step.Aux != 0
		}
		f := step.Float()
		return f > 0, f != 0 && f == f
	}
	positive = true
	switch v := fe.frame[slot].(type) {
	case LInteger:
		positive = v >= 0
	case LNumber:
		positive = !(v < 0)
	}
	switch {
	case kind == skInt && positive:
		fe.guard(fe.op(jit.OpLt, jit.TInt, fe.constInt(0), step), -1, 0)
	case kind == skInt:
		// (the smallest integer has no negation)
		fe.guard(fe.op(jit.OpLt, jit.TInt, step, fe.constInt(0)), -1, 0)
		fe.guard(fe.op(jit.OpLt, jit.TInt, fe.constInt(-1<<63), step), -1, 0)
	case positive:
		fe.guard(fe.op(jit.OpFLt, jit.TInt, fe.f.ConstFloat(fe.cur, 0), step), -1, 0)
	default:
		fe.guard(fe.op(jit.OpFLt, jit.TInt, step, fe.f.ConstFloat(fe.cur, 0)), -1, 0)
	}
	return positive, true
}

// forLoop translates OP_FORLOOP.
func (fe *jitFrontend) forLoop(a, pcBody, pcExit int) {
	idx, ik, ok1 := fe.num(a)
	limit, lk, ok2 := fe.num(a + 1)
	step, sk, ok3 := fe.num(a + 2)
	if !ok1 || !ok2 || !ok3 || ik != lk || ik != sk {
		fe.exitBlock()
		return
	}
	positive, ok := fe.stepDirection(a+2, step, sk)
	if !ok {
		fe.exitBlock()
		return
	}
	var cont, next *jit.Value
	if ik == skInt {
		// the loop continues while the distance to the limit is at least
		// one step (computed without overflow)
		if positive {
			dist := fe.op(jit.OpSub, jit.TInt, limit, idx)
			cont = fe.op(jit.OpEq, jit.TInt, fe.op(jit.OpULt, jit.TInt, dist, step), fe.constInt(0))
		} else {
			dist := fe.op(jit.OpSub, jit.TInt, idx, limit)
			cont = fe.op(jit.OpEq, jit.TInt, fe.op(jit.OpULt, jit.TInt, dist, fe.op(jit.OpNeg, jit.TInt, step)), fe.constInt(0))
		}
		next = fe.op(jit.OpAdd, jit.TInt, idx, step)
	} else {
		next = fe.op(jit.OpFAdd, jit.TFloat, idx, step)
		fe.narrowNext(pcBody, next, idx, step)
		if positive {
			cont = fe.op(jit.OpFLe, jit.TInt, next, limit)
		} else {
			cont = fe.op(jit.OpFLe, jit.TInt, limit, next)
		}
	}
	// state of the continuing path: index and loop variable are updated
	saved := cloneState(fe.st)
	t, f := fe.split(cont)
	fe.cur = t
	fe.set(a, ik, next)
	fe.set(a+3, ik, next)
	fe.connect(fe.cur, pcBody, fe.st)
	fe.cur = f
	fe.st = saved
	fe.connect(fe.cur, pcExit, fe.st)
}

// tableOf loads the *LTable held by a register, guarded by a type check.
// ok is false if the register is not (predictably) a table.
func (fe *jitFrontend) tableOf(slot int) (tp *jit.Value, home int, ok bool) {
	home, ok = fe.homeSlot(slot)
	if !ok || valueKind(fe.peek(home)) != vkTable {
		return nil, 0, false
	}
	return fe.tableAt(home), home, true
}

// guardNoSparse makes the code depend on the table tp keeping all the
// elements of its array part in the stored part (see table_sparse.go).
func (fe *jitFrontend) guardNoSparse(tp *jit.Value) {
	sparse := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableSparse))
	fe.guard(fe.op(jit.OpEq, jit.TInt, sparse, fe.constInt(0)), -1, 0)
}

// tableAt loads the *LTable at a location that is predicted to hold a
// table, guarded by a type check.
func (fe *jitFrontend) tableAt(home int) *jit.Value {
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(home), fe.constInt(int64(itabTable))), home, fbValue)
	return fe.slotData(home)
}

// arrayKindOf predicts the array representation of the table in a home
// slot at the current instruction.
func (fe *jitFrontend) arrayKindOf(home int) uint8 {
	if k, ok := fe.jp.feedback[feedbackKey{fe.fbpc(), int16(locSlot(home)), fbArray}]; ok {
		return k
	}
	if tb, ok := fe.peek(home).(*LTable); ok {
		return tb.akind
	}
	return arrayKindGeneric
}

// arrayIndex returns the zero based index for a table key operand, if it
// is an integer.
func (fe *jitFrontend) arrayIndex(rk int) (*jit.Value, bool) {
	key, kk, ok := fe.rkNum(rk)
	if !ok {
		return nil, false
	}
	if kk == skFloat {
		if fe.L.lang55 {
			return nil, false
		}
		// Lua 5.1 profile: all numbers are floats; the index must be an
		// exact integer, which is known for a key with an integer twin
		if t, ok := fe.twin(key); ok {
			key = t.v
		} else {
			fe.guard(fe.op(jit.OpFLt, jit.TInt, key, fe.f.ConstFloat(fe.cur, 9007199254740992)), -1, 0)
			i := fe.op(jit.OpFloatToInt, jit.TInt, key)
			fe.guard(fe.op(jit.OpFEq, jit.TInt, fe.op(jit.OpIntToFloat, jit.TFloat, i), key), -1, 0)
			key = i
		}
	}
	return fe.op(jit.OpSub, jit.TInt, key, fe.constInt(1)), true
}

// getTable translates R(a) := R(b)[RK(c)] for integer keys on unboxed
// array parts and for numbers stored in generic array parts.
func (fe *jitFrontend) getTable(a, b, c int) bool {
	if _, ok := fe.homeSlot(b); !ok {
		return false
	}
	home, _ := fe.homeSlot(b)
	if valueKind(fe.peek(home)) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(home)
	// the result kind for generic arrays is predicted from the value the
	// destination register holds from the previous iteration
	resKind := fe.predictKind(a)
	sample := firstElement(fe.peek(home))
	if _, known := fe.jp.feedback[feedbackKey{fe.fbpc(), int16(a), fbValue}]; !known && sample != nil {
		resKind = valueKind(sample)
	}
	// any other element of a generic array is not copied: the register
	// refers to it where it is
	byRef := akind == arrayKindGeneric && resKind != vkInt && resKind != vkFloat
	idx, ok := fe.arrayIndex(c)
	if !ok {
		return false
	}
	tp, home, _ := fe.tableOf(b)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad8, jit.TInt, tp, int64(offTableAkind)), fe.constInt(int64(akind))), home, fbArray)
	var off uintptr
	switch akind {
	case arrayKindInt, arrayKindBool:
		off = offTableIarr
	case arrayKindFloat:
		off = offTableFarr
	default:
		off = offTableArray
	}
	data := fe.load(jit.OpLoad64, jit.TInt, tp, int64(off)+sliceOffData)
	n := fe.loadMem(jit.MemArrayLen, jit.OpLoad64, jit.TInt, tp, int64(off)+sliceOffLen)
	fe.guard(fe.op(jit.OpULt, jit.TInt, idx, n), -1, 0)
	switch akind {
	case arrayKindInt, arrayKindBool:
		addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(3)))
		kind := skInt
		if akind == arrayKindBool {
			kind = skBool // stored as the words 0 and 1
		}
		fe.set(a, kind, fe.loadMem(jit.MemArray, jit.OpLoad64, jit.TInt, addr, 0))
	case arrayKindFloat:
		addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(3)))
		fe.set(a, skFloat, fe.loadMem(jit.MemArray, jit.OpLoadF64, jit.TFloat, addr, 0))
	default:
		addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(4)))
		if byRef {
			// (a nil element would have to consult __index)
			mt := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable))
			fe.guard(fe.op(jit.OpEq, jit.TInt, mt, fe.constInt(int64(itabNil))), -1, 0)
			fe.st[a] = slotState{kind: skRef, val: addr, src: int32(a)}
			if sample != nil {
				fe.refPeek[int32(a)] = sample
			}
			return true
		}
		itab := int64(itabInteger)
		if resKind == vkFloat {
			itab = int64(itabNumber)
		}
		fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad64, jit.TInt, addr, 0), fe.constInt(itab)), -1, 0)
		p := fe.load(jit.OpLoad64, jit.TInt, addr, 8)
		if resKind == vkFloat {
			fe.set(a, skFloat, fe.load(jit.OpLoadF64, jit.TFloat, p, 0))
		} else {
			fe.set(a, skInt, fe.load(jit.OpLoad64, jit.TInt, p, 0))
		}
	}
	return true
}

// setTable translates R(a)[RK(b)] := RK(c) for integer keys and numbers
// stored into an unboxed array part of the matching kind, including
// appends that fit the capacity of the array.
func (fe *jitFrontend) setTable(a, b, c int) bool {
	home, ok := fe.homeSlot(a)
	if !ok || valueKind(fe.peek(home)) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(home)
	var val *jit.Value
	switch akind {
	case arrayKindInt, arrayKindFloat:
		v, vk, ok := fe.rkNum(c)
		if !ok || (akind == arrayKindInt) != (vk == skInt) {
			return false
		}
		val = v
	case arrayKindBool:
		// only booleans that are unboxed already (constants, comparisons)
		if c&opBitRk != 0 || fe.st[c].kind != skBool {
			return false
		}
		val = fe.st[c].val
	default:
		return false
	}
	idx, ok := fe.arrayIndex(b)
	if !ok {
		return false
	}
	tp, home, _ := fe.tableOf(a)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad8, jit.TInt, tp, int64(offTableAkind)), fe.constInt(int64(akind))), home, fbArray)
	off := int64(offTableIarr)
	storeOp := jit.OpStore64
	if akind == arrayKindFloat {
		off = int64(offTableFarr)
		storeOp = jit.OpStoreF64
	}
	data := fe.load(jit.OpLoad64, jit.TInt, tp, off+sliceOffData)
	n := fe.loadMem(jit.MemArrayLen, jit.OpLoad64, jit.TInt, tp, off+sliceOffLen)
	addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(3)))
	inBounds, grow := fe.split(fe.op(jit.OpULt, jit.TInt, idx, n))
	join := fe.f.NewBlock()

	fe.cur = inBounds
	fe.store(jit.MemArray, storeOp, addr, 0, val)
	jumpIR(fe.cur, join)

	// append: only if the element goes right behind the last one, the
	// capacity suffices, the new key is below MaxArrayIndex (larger keys
	// live in the hash part) and no metatable (__newindex) is involved
	fe.cur = grow
	fe.guard(fe.op(jit.OpEq, jit.TInt, idx, n), -1, 0)
	capv := fe.load(jit.OpLoad64, jit.TInt, tp, off+sliceOffCap)
	fe.guardExpected(fe.op(jit.OpULt, jit.TInt, n, capv))
	newLen := fe.op(jit.OpAdd, jit.TInt, n, fe.constInt(1))
	limit := fe.load(jit.OpLoad64, jit.TInt, fe.constInt(int64(uintptr(unsafe.Pointer(&MaxArrayIndex)))), 0)
	fe.guard(fe.op(jit.OpLt, jit.TInt, newLen, limit), -1, 0)
	mt := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable))
	fe.guard(fe.op(jit.OpEq, jit.TInt, mt, fe.constInt(int64(itabNil))), -1, 0)
	// (an append may have to move sparse elements behind the array)
	fe.guardNoSparse(tp)
	fe.store(jit.MemArray, storeOp, addr, 0, val)
	fe.store(jit.MemArrayLen, jit.OpStore64, tp, off+sliceOffLen, newLen)
	// the element takes the first of the nil slots that the table
	// counts behind its array part, if there is one (LTable.claimSlot)
	tail := fe.loadMem(jit.MemArrayLen, jit.OpLoad64, jit.TInt, tp, int64(offTableTail))
	taken := fe.op(jit.OpNe, jit.TInt, tail, fe.constInt(0))
	fe.store(jit.MemArrayLen, jit.OpStore64, tp, int64(offTableTail), fe.op(jit.OpSub, jit.TInt, tail, taken))
	jumpIR(fe.cur, join)

	fe.cur = join
	return true
}

// curFn returns the closure whose code is being translated.
func (fe *jitFrontend) curFn() *LFunction {
	return fe.scope
}

// fbpc returns the position of the current instruction for feedback keys.
func (fe *jitFrontend) fbpc() int32 {
	return fe.fbBase + int32(fe.pc)
}

// code returns the instruction at pc of the code being translated, with
// its register operands relocated into the slots of the unit.
func (fe *jitFrontend) code(pc int) uint32 {
	inst := fe.proto.Code[pc]
	if fe.slotBase != 0 {
		inst, _ = relocateInst(inst, fe.slotBase)
	}
	return inst
}

// closureAddr returns the address of the closure whose code is being
// translated. For the compiled function itself it is only known at run
// time: all closures of a prototype share the compiled code.
func (fe *jitFrontend) closureAddr() *jit.Value {
	if fe.inl != 0 {
		// an inlined callee is a constant of the code (kept alive by the
		// list of inlined calls)
		return fe.constInt(int64(uintptr(unsafe.Pointer(fe.scope))))
	}
	return fe.load(jit.OpLoad64, jit.TInt, fe.f.Ctx(), jit.CtxClosure)
}

// getUpval translates R(a) := Upvalue(idx) for a closed upvalue that
// holds a number, a function or a table. Numbers are unboxed; functions
// and tables become constants of the code, guarded by their identity
// (the usual case is a local function or module table captured by the
// compiled function).
func (fe *jitFrontend) getUpval(a, idx int) bool {
	fn := fe.curFn()
	if idx >= len(fn.Upvalues) || fn.Upvalues[idx] == nil {
		return false
	}
	if fe.jp.feedback[feedbackKey{fe.fbpc(), int16(a), fbUpval}] >= jitFieldMisses {
		return false
	}
	uv := fn.Upvalues[idx]
	open := !uv.closed && uv.reg != nil
	if !open && !uv.closed {
		return false
	}
	// a variable of the running activation, captured by an inlined
	// callee: the register itself is read, whatever form it has now
	own := -1
	if open && fe.inl != 0 && uv.reg == fe.L.reg && uv.index >= fe.base && uv.index < fe.base+fe.info.nslots {
		own = uv.index - fe.base
	}
	value := uv.Value()
	kind := valueKind(value)
	// numbers are unboxed and functions and tables become constants;
	// any other value is referred to where it is
	byRef := kind != vkInt && kind != vkFloat && !constValue(value)
	cells := fe.load(jit.OpLoad64, jit.TInt, fe.closureAddr(), int64(offFnUpvalues)+sliceOffData)
	cell := fe.load(jit.OpLoad64, jit.TInt, cells, int64(idx)*8)
	closed := fe.load(jit.OpLoad8, jit.TInt, cell, int64(offUvClosed))
	var itab, data *jit.Value
	if open {
		// the value lives in a register of an active function, found
		// relative to the registers of this one
		// (of this thread: a coroutine has registers of its own)
		fe.guard(fe.op(jit.OpEq, jit.TInt, closed, fe.constInt(0)), a, fbUpval)
		owner := fe.load(jit.OpLoad64, jit.TInt, cell, int64(offUvReg))
		fe.guard(fe.op(jit.OpEq, jit.TInt, owner, fe.load(jit.OpLoad64, jit.TInt, fe.f.Ctx(), jit.CtxRegistry)), a, fbUpval)
		index := fe.load(jit.OpLoad64, jit.TInt, cell, int64(offUvIndex))
		rel := fe.op(jit.OpSub, jit.TInt, index, fe.load(jit.OpLoad64, jit.TInt, fe.f.Ctx(), jit.CtxBase))
		if own >= 0 {
			fe.guard(fe.op(jit.OpEq, jit.TInt, rel, fe.constInt(int64(own))), a, fbUpval)
			fe.move(a, own)
			return true
		}
		// (registers below this function's are in memory: the functions
		// they belong to wait for a call to return)
		fe.guard(fe.op(jit.OpLt, jit.TInt, rel, fe.constInt(0)), a, fbUpval)
		addr := fe.op(jit.OpAdd, jit.TInt, fe.f.RegBase(), fe.op(jit.OpShl, jit.TInt, rel, fe.constInt(4)))
		if byRef {
			fe.refTo(a, addr, value)
			return true
		}
		itab = fe.load(jit.OpLoad64, jit.TInt, addr, 0)
		data = fe.load(jit.OpLoad64, jit.TInt, addr, 8)
	} else {
		fe.guard(fe.op(jit.OpNe, jit.TInt, closed, fe.constInt(0)), a, fbUpval)
		if byRef {
			fe.refTo(a, fe.op(jit.OpAdd, jit.TInt, cell, fe.constInt(int64(offUvValue))), value)
			return true
		}
		itab = fe.load(jit.OpLoad64, jit.TInt, cell, int64(offUvValue))
		data = fe.load(jit.OpLoad64, jit.TInt, cell, int64(offUvValue)+8)
	}
	fe.guard(fe.op(jit.OpEq, jit.TInt, itab, fe.constInt(int64(itabOf(value)))), a, fbUpval)
	switch kind {
	case vkInt:
		fe.set(a, skInt, fe.load(jit.OpLoad64, jit.TInt, data, 0))
	case vkFloat:
		fe.set(a, skFloat, fe.load(jit.OpLoadF64, jit.TFloat, data, 0))
	default:
		fe.guard(fe.op(jit.OpEq, jit.TInt, data, fe.constInt(int64(uintptr(dataOf(value))))), a, fbUpval)
		fe.st[a] = slotState{kind: skConst, src: fe.constIndex(value)}
	}
	return true
}

// fieldRef locates the number field key of the table in register slot
// and emits the guards under which native code may access it in place:
// the register holds a table whose string-keyed entry at the position
// found now is the entry for key. Entries never move, and a raw hit needs
// no metamethod, so nothing else has to be checked. It returns the
// address of the entries, the displacement of the entry and its kind.
//
// The key is recognized by the address of its bytes. Constants of all
// functions share one copy (see intern.go); a table filled with another
// copy of the key, for example by Go code, is accepted through the copy
// found now.
func (fe *jitFrontend) fieldRef(slot int, key string, boxedOK bool) (data *jit.Value, disp int64, kind uint8, ok bool) {
	home, ok := fe.homeSlot(slot)
	if !ok {
		return nil, 0, 0, false
	}
	return fe.fieldRefAt(home, key, boxedOK)
}

// fieldRefAt is fieldRef for the table at a location.
func (fe *jitFrontend) fieldRefAt(home int, key string, boxedOK bool) (data *jit.Value, disp int64, kind uint8, ok bool) {
	tb, isTable := fe.peek(home).(*LTable)
	if !isTable || fe.jp.feedback[feedbackKey{fe.fbpc(), int16(locSlot(home)), fbField}] >= jitFieldMisses {
		return nil, 0, 0, false
	}
	idx := tb.findField(key)
	if idx >= 0 {
		fe.fieldSample = tb.fields[idx].value
	}
	if idx < 0 || idx >= jitMaxFieldIndex || tb.fields[idx].removed() || (tb.fields[idx].kind == fieldBoxed && !boxedOK) {
		return nil, 0, 0, false
	}
	f := &tb.fields[idx]
	tp := fe.tableAt(home)
	data = fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableFields)+sliceOffData)
	n := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableFields)+sliceOffLen)
	fe.guard(fe.op(jit.OpULt, jit.TInt, fe.constInt(int64(idx)), n), home, fbField)
	disp = int64(idx) * int64(fieldSize)
	keyLen := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldKey)+8)
	keyAddr := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldKey))
	match := fe.op(jit.OpEq, jit.TInt, keyAddr, fe.constInt(int64(uintptr(unsafe.Pointer(unsafe.StringData(key))))))
	if unsafe.StringData(f.key) != unsafe.StringData(key) {
		fe.constIndex(LString(f.key)) // keeps the other copy alive
		other := fe.constInt(int64(uintptr(unsafe.Pointer(unsafe.StringData(f.key)))))
		match = fe.op(jit.OpOr, jit.TInt, match, fe.op(jit.OpEq, jit.TInt, keyAddr, other))
	}
	sameLen := fe.op(jit.OpEq, jit.TInt, keyLen, fe.constInt(int64(len(key))))
	fe.guard(fe.op(jit.OpAnd, jit.TInt, match, sameLen), home, fbField)
	return data, disp, f.kind, true
}

// getField translates R(a) := R(b)[K(c)] for a number field of a table.
func (fe *jitFrontend) getField(a, b, c int) bool {
	if c&opBitRk == 0 {
		return false
	}
	home, ok := fe.homeSlot(b)
	return ok && fe.getFieldAt(a, home, fe.proto.stringConstants[c&^opBitRk])
}

// getFieldAt translates R(a) := T[key] for the table T at a location.
func (fe *jitFrontend) getFieldAt(a, home int, key string) bool {
	data, disp, kind, ok := fe.fieldRefAt(home, key, true)
	if !ok {
		return false
	}
	cur := fe.loadMem(jit.MemField, jit.OpLoad8, jit.TInt, data, disp+int64(offFieldKind))
	fe.guard(fe.op(jit.OpEq, jit.TInt, cur, fe.constInt(int64(kind))), home, fbField)
	switch kind {
	case fieldInt:
		fe.set(a, skInt, fe.loadMem(jit.MemField, jit.OpLoad64, jit.TInt, data, disp+int64(offFieldNum)))
	case fieldFloat:
		fe.set(a, skFloat, fe.loadMem(jit.MemField, jit.OpLoadF64, jit.TFloat, data, disp+int64(offFieldNum)))
	default:
		// a string, table, function, ...: the register refers to the
		// value where it is. (An entry that was removed holds nil and
		// would have to consult __index.)
		itab := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldValue))
		fe.guard(fe.op(jit.OpNe, jit.TInt, itab, fe.constInt(int64(itabNil))), home, fbField)
		fe.st[a] = slotState{kind: skRef, src: int32(a), val: fe.op(jit.OpAdd, jit.TInt, data, fe.constInt(disp+int64(offFieldValue)))}
		fe.refPeek[int32(a)] = fe.fieldSample
	}
	return true
}

// setField translates R(a)[K(b)] := RK(c) for a number stored into a
// field that holds a number already. The number goes into the unboxed
// part of the entry; kind and the stale flag, which tells the interpreter
// to rebuild the boxed value, are written as one word.
func (fe *jitFrontend) setField(a, b, c int) bool {
	var key string
	if b&opBitRk != 0 {
		key = fe.proto.stringConstants[b&^opBitRk]
	} else if s := &fe.st[b]; s.kind == skConst {
		// a key constant that did not fit into the operand
		ks, isString := fe.consts[s.src].(LString)
		if !isString {
			return false
		}
		key = string(ks)
	} else {
		return false
	}
	home, ok := fe.homeSlot(a)
	return ok && fe.setFieldAt(home, key, c)
}

// setFieldAt translates T[key] := RK(c) for the table T at a location
// and a number that replaces a number.
func (fe *jitFrontend) setFieldAt(home int, key string, c int) bool {
	if _, isTable := fe.peek(home).(*LTable); !isTable {
		return false
	}
	val, vk, ok := fe.rkNum(c)
	if !ok {
		return false
	}
	data, disp, _, ok := fe.fieldRefAt(home, key, false)
	if !ok {
		return false
	}
	// the entry must hold a number: replacing other values can involve
	// the version counter of the table
	cur := fe.loadMem(jit.MemField, jit.OpLoad8, jit.TInt, data, disp+int64(offFieldKind))
	fe.guard(fe.op(jit.OpNe, jit.TInt, cur, fe.constInt(int64(fieldBoxed))), home, fbField)
	kind, store := int64(fieldInt), jit.OpStore64
	if vk == skFloat {
		kind, store = int64(fieldFloat), jit.OpStoreF64
	}
	fe.store(jit.MemField, store, data, disp+int64(offFieldNum), val)
	fe.store(jit.MemField, jit.OpStore64, data, disp+int64(offFieldKind), fe.constInt(kind|1<<8))
	return true
}

// length translates R(a) := #R(b) for tables with an unboxed array part
// and no metatable.
func (fe *jitFrontend) length(a, b int) bool {
	home, ok := fe.homeSlot(b)
	if !ok {
		return false
	}
	setLen := func(n *jit.Value) { fe.setIntResult(a, n, twinWideBits) }
	if valueKind(fe.peek(home)) == vkString {
		// the length of a string is the second word of its header
		fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(home), fe.constInt(int64(itabString))), home, fbValue)
		setLen(fe.load(jit.OpLoad64, jit.TInt, fe.slotData(home), 8))
		return true
	}
	if valueKind(fe.peek(home)) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(home)
	tp, home, _ := fe.tableOf(b)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad8, jit.TInt, tp, int64(offTableAkind)), fe.constInt(int64(akind))), home, fbArray)
	mt := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable))
	fe.guard(fe.op(jit.OpEq, jit.TInt, mt, fe.constInt(int64(itabNil))), -1, 0)
	off := int64(offTableIarr)
	switch akind {
	case arrayKindFloat:
		off = int64(offTableFarr)
	case arrayKindGeneric:
		off = int64(offTableArray)
	}
	// (the border of a table with sparse elements lies behind them)
	fe.guardNoSparse(tp)
	n := fe.loadMem(jit.MemArrayLen, jit.OpLoad64, jit.TInt, tp, off+sliceOffLen)
	if akind == arrayKindGeneric {
		// the length is the number of elements unless the array part
		// ends with nil values, which the interpreter sorts out
		data := fe.load(jit.OpLoad64, jit.TInt, tp, off+sliceOffData)
		filled, empty := fe.split(fe.op(jit.OpNe, jit.TInt, n, fe.constInt(0)))
		join := fe.f.NewBlock()
		fe.cur = filled
		last := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, fe.op(jit.OpSub, jit.TInt, n, fe.constInt(1)), fe.constInt(4)))
		fe.guard(fe.op(jit.OpNe, jit.TInt, fe.load(jit.OpLoad64, jit.TInt, last, 0), fe.constInt(int64(itabNil))), -1, 0)
		jumpIR(fe.cur, join)
		jumpIR(empty, join)
		fe.cur = join
	}
	setLen(n)
	return true
}

/* }}} */
