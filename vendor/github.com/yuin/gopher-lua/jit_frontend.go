package lua

import (
	"fmt"
	"reflect"
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
)

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
	// expected marks a guard whose failure is part of normal operation
	// (an array that has to grow) rather than a wrong speculation: it
	// does not count against the unit.
	expected bool
	// top is the register behind the last value of an open result list
	// that the instruction at the exit consumes (-1 for none): the
	// interpreter finds the end of such a list through the registry top.
	top int16
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

	// statistics for the profitability check
	nativeOps int
	callouts  int
}

// compileLoopIR translates the region starting at the loop header entryPC
// into IR. frame is the register window of the running function.
func compileLoopIR(L *LState, jp *jitProto, fn *LFunction, frame []LValue, entryPC int) (*jit.Func, *jitFrontend, error) {
	fe := &jitFrontend{
		L: L, jp: jp, fn: fn, proto: jp.proto, info: jp.proto.analysis(),
		env:   functionEnv(fn),
		frame: frame, entryPC: entryPC, nslots: jp.proto.analysis().nslots,
		demoted:     make(map[demoteKey]bool),
		forcedDirty: make(map[demoteKey]bool),
		needPhi:     make(map[demoteKey]bool),
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
	fe.meta = fe.meta[:0]
	fe.consts = fe.consts[:0]
	fe.keep = fe.keep[:0]
	fe.usesEnv = false
	fe.nativeOps, fe.callouts = 0, 0
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
	var work []int
	for _, p := range fe.preds[header] {
		if p >= header {
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
	code := fe.proto.Code
	for pc, inst := range code {
		if fe.info.data[pc] || opGetOpCode(inst) != OP_FORLOOP || pc+1+opGetArgSbx(inst) != fe.entryPC {
			continue
		}
		slot := opGetArgA(inst) + 2
		s := &fe.st[slot]
		switch s.kind {
		case skInt:
			c := fe.f.ConstInt(fe.cur, int64(fe.frame[slot].(LInteger)))
			fe.guard(fe.f.NewValue(fe.cur, jit.OpEq, jit.TInt, 0, s.val, c), -1, 0)
			s.val = c
		case skFloat:
			c := fe.f.ConstFloat(fe.cur, float64(fe.frame[slot].(LNumber)))
			fe.guard(fe.f.NewValue(fe.cur, jit.OpFEq, jit.TInt, 0, s.val, c), -1, 0)
			s.val = c
		}
		return
	}
}

/* exits and snapshots {{{ */

// newExit creates an exit with front end data.
func (fe *jitFrontend) newExit(kind jit.ExitKind, pc int, m exitMeta) *jit.Exit {
	m.top = -1
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
	for slot := range st {
		s := &st[slot]
		if !s.stale() || !live.has(slot) {
			continue
		}
		if only != nil && s.kind != skAlias && !only(slot) {
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
		}
		snap = append(snap, e)
	}
	return snap
}

// guard emits a guard on cond that deoptimizes to the current
// instruction. fbSlot, if >= 0, is the register whose kind is recorded
// when the guard fails.
func (fe *jitFrontend) guard(cond *jit.Value, fbSlot int, fbWhat uint8) {
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
	x := fe.newExit(jit.ExitCallout, fe.pc, exitMeta{kind: emInst, fbSlot: -1})
	x.Snap = fe.snapshot(fe.cur, fe.st, fe.pc, nil)
	fe.f.NewValue(fe.cur, jit.OpCallout, jit.TInt, 0).Exit = x
	markFlushed(fe.st, x.Snap)
	fe.callouts++
	// whatever the instruction wrote is now boxed in its home slot
	e := &fe.info.effects[fe.pc]
	for slot := range fe.st {
		if e.writes.has(slot) || fe.info.escaped.has(slot) {
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
			}
		case skNil:
			if have.kind != skNil {
				fe.demote(tb.pc, slot)
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
	}
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
	for slot := 0; slot < fe.nslots; slot++ {
		if !live.has(slot) || fe.demoted[demoteKey{tb.pc, slot}] {
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

func (fe *jitFrontend) load(o jit.Op, typ jit.Type, base *jit.Value, disp int64) *jit.Value {
	return fe.f.NewValue(fe.cur, o, typ, disp, base)
}

// slotItab loads the type word of the boxed value in a home slot.
func (fe *jitFrontend) slotItab(slot int) *jit.Value {
	return fe.load(jit.OpLoad64, jit.TInt, fe.f.RegBase(), int64(slot)*lvalueSize)
}

// slotData loads the data word of the boxed value in a home slot.
func (fe *jitFrontend) slotData(slot int) *jit.Value {
	return fe.load(jit.OpLoad64, jit.TInt, fe.f.RegBase(), int64(slot)*lvalueSize+8)
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

// predictKind returns the value kind expected in a home slot at the
// current instruction: recorded feedback first, else the value the
// register holds right now.
func (fe *jitFrontend) predictKind(slot int) uint8 {
	if k, ok := fe.jp.feedback[feedbackKey{int32(fe.pc), int16(slot), fbValue}]; ok {
		return k
	}
	return valueKind(fe.frame[slot])
}

// homeSlot resolves a register holding a boxed value to the home slot
// that currently contains it. ok is false for registers that are not a
// boxed value in some home slot.
func (fe *jitFrontend) homeSlot(slot int) (int, bool) {
	switch s := &fe.st[slot]; s.kind {
	case skHome:
		return slot, true
	case skAlias:
		return int(s.src), true
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
	inst := fe.proto.Code[pc]
	op := opGetOpCode(inst)
	A, B, C := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	next = pc + 1
	openTop := fe.openTop
	fe.openTop = -1
	fe.pendingTop = openTop
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
			fe.set(A, skFloat, fe.op(jit.OpFNeg, jit.TFloat, v))
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
		fe.compare(op, A, B, C)
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
		if !fe.constGlobal(A, opGetArgBx(inst)) {
			return fe.generic(pc, op)
		}
	case OP_GETTABLEKS:
		if !fe.constField(A, B, C) {
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

// generic handles an instruction that has no native translation: simple
// instructions are executed by the interpreter through a callout, others
// end the compiled region.
func (fe *jitFrontend) generic(pc, op int) (int, bool) {
	inst := fe.proto.Code[pc]
	A, B, C := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	next := fe.info.effects[pc].succs[0]
	switch op {
	case OP_MOVE, OP_MOVEN, OP_LOADK, OP_LOADNIL, OP_GETUPVAL, OP_GETGLOBAL, OP_GETENV,
		OP_GETTABLE, OP_GETTABLEKS, OP_SETGLOBAL, OP_SETENV, OP_SETUPVAL, OP_SETTABLE,
		OP_SETTABLEKS, OP_NEWTABLE, OP_SELF, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW,
		OP_IDIV, OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR, OP_UNM, OP_BNOT, OP_NOT, OP_LEN,
		OP_CONCAT, OP_CLOSE, OP_CLOSURE, OP_ERRNNIL:
		fe.calloutInst()
		return next, false
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
	fe.usesEnv = true
	fe.guardVersion(fe.env)
	fe.st[a] = slotState{kind: skConst, src: fe.constIndex(v)}
	return true
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

// Intrinsics: library functions with a native translation.
const (
	intrNone = iota
	intrSqrt
	intrFloor
	intrCeil
	intrAbs
)

// intrinsicOf identifies library functions that have a native form.
func intrinsicOf(fn *LFunction) int {
	if fn == nil || !fn.IsG || fn.GFunction == nil {
		return intrNone
	}
	switch reflect.ValueOf(fn.GFunction).Pointer() {
	case reflect.ValueOf(LGFunction(mathSqrt)).Pointer():
		return intrSqrt
	case reflect.ValueOf(LGFunction(mathFloor)).Pointer(), reflect.ValueOf(LGFunction(math55Floor)).Pointer():
		return intrFloor
	case reflect.ValueOf(LGFunction(mathCeil)).Pointer(), reflect.ValueOf(LGFunction(math55Ceil)).Pointer():
		return intrCeil
	case reflect.ValueOf(LGFunction(mathAbs)).Pointer(), reflect.ValueOf(LGFunction(math55Abs)).Pointer():
		return intrAbs
	}
	return intrNone
}

// floatToIntExact converts a float value that is known to be integral
// to an integer, deoptimizing if it does not fit.
func (fe *jitFrontend) floatToIntExact(f *jit.Value) *jit.Value {
	fe.guard(fe.op(jit.OpFLt, jit.TInt, f, fe.f.ConstFloat(fe.cur, 9223372036854775808.0)), -1, 0)
	fe.guard(fe.op(jit.OpFLe, jit.TInt, fe.f.ConstFloat(fe.cur, -9223372036854775808.0), f), -1, 0)
	return fe.op(jit.OpFloatToInt, jit.TInt, f)
}

// intrinsicCall translates a call of a known library function with one
// numeric argument and one result into native code.
func (fe *jitFrontend) intrinsicCall(a, b, c int) bool {
	s := &fe.st[a]
	if s.kind != skConst || b != 2 || (c != 2 && c != 0) {
		return false
	}
	fn, _ := fe.consts[s.src].(*LFunction)
	kind := intrinsicOf(fn)
	if kind == intrNone {
		return false
	}
	x, xk, ok := fe.num(a + 1)
	if !ok {
		return false
	}
	lang55 := fe.L.lang55
	switch kind {
	case intrSqrt:
		fe.set(a, skFloat, fe.op(jit.OpFSqrt, jit.TFloat, fe.toFloat(x, xk)))
	case intrFloor, intrCeil:
		o := jit.OpFFloor
		if kind == intrCeil {
			o = jit.OpFCeil
		}
		switch {
		case xk == skInt && lang55:
			fe.set(a, skInt, x)
		case lang55:
			fe.set(a, skInt, fe.floatToIntExact(fe.op(o, jit.TFloat, x)))
		default:
			fe.set(a, skFloat, fe.op(o, jit.TFloat, fe.toFloat(x, xk)))
		}
	case intrAbs:
		if xk == skInt && lang55 {
			mask := fe.op(jit.OpSar, jit.TInt, x, fe.constInt(63))
			fe.set(a, skInt, fe.op(jit.OpSub, jit.TInt, fe.op(jit.OpXor, jit.TInt, x, mask), mask))
		} else {
			fe.set(a, skFloat, fe.op(jit.OpFAbs, jit.TFloat, fe.toFloat(x, xk)))
		}
	}
	// the argument registers are dead after a call
	for r := a + 1; r < a+b && r < fe.nslots; r++ {
		fe.st[r] = slotState{}
	}
	if c == 0 {
		// all results were requested: there is exactly one
		fe.openTop = a + 1
	}
	return true
}

// move translates R(a) := R(b).
func (fe *jitFrontend) move(a, b int) {
	s := fe.st[b]
	switch s.kind {
	case skInt, skFloat, skBool:
		fe.set(a, s.kind, s.val)
	case skNil, skAlias, skConst:
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
		fe.set(a, skFloat, fe.op(o, jit.TFloat, fe.toFloat(x, xk), fe.toFloat(y, yk)))
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
func (fe *jitFrontend) compare(op, a, b, c int) {
	pc := fe.pc
	// the next instruction is skipped when result == (A == 0)
	pcTrue, pcFalse := pc+1, pc+2
	if a == 0 {
		pcTrue, pcFalse = pc+2, pc+1
	}
	if cond := fe.compareValue(op, b, c); cond != nil {
		fe.branch(cond, pcTrue, pcFalse)
		return
	}
	// generic comparison: the interpreter executes it and reports whether
	// it skipped the next instruction
	fe.calloutInst()
	res := fe.load(jit.OpLoad64, jit.TInt, fe.f.Ctx(), jit.CtxResult)
	fe.branch(fe.op(jit.OpNe, jit.TInt, res, fe.constInt(0)), pc+2, pc+1)
}

// compareValue returns the boolean value of a comparison if it can be
// computed natively.
func (fe *jitFrontend) compareValue(op, b, c int) *jit.Value {
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
	if !ok1 || !ok2 || !ok3 || !step.IsConst() {
		fe.exitBlock()
		return
	}
	var skip *jit.Value
	if ik == skInt && sk == skInt {
		if lk != skInt || step.Aux == 0 {
			fe.exitBlock()
			return
		}
		if step.Aux > 0 {
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
		fstep := step
		stepv := step.Float()
		if sk == skInt {
			stepv = float64(step.Aux)
			fstep = fe.f.ConstFloat(fe.cur, stepv)
		}
		if stepv == 0 || stepv != stepv {
			fe.exitBlock()
			return
		}
		if !fe.L.lang55 {
			// Lua 5.1 computes the first index as (init - step) + step
			finit = fe.op(jit.OpFAdd, jit.TFloat, fe.op(jit.OpFSub, jit.TFloat, finit, fstep), fstep)
		}
		// the loop runs unless the limit is already passed; comparisons
		// with NaN are false, which the interpreter treats differently in
		// the two profiles, so NaN operands deoptimize
		fe.guard(fe.op(jit.OpFEq, jit.TInt, flimit, flimit), -1, 0)
		fe.guard(fe.op(jit.OpFEq, jit.TInt, finit, finit), -1, 0)
		if stepv > 0 {
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

// forLoop translates OP_FORLOOP.
func (fe *jitFrontend) forLoop(a, pcBody, pcExit int) {
	idx, ik, ok1 := fe.num(a)
	limit, lk, ok2 := fe.num(a + 1)
	step, sk, ok3 := fe.num(a + 2)
	if !ok1 || !ok2 || !ok3 || !step.IsConst() || ik != lk || ik != sk {
		fe.exitBlock()
		return
	}
	var cont, next *jit.Value
	if ik == skInt {
		// the loop continues while the distance to the limit is at least
		// one step (computed without overflow)
		if step.Aux > 0 {
			dist := fe.op(jit.OpSub, jit.TInt, limit, idx)
			cont = fe.op(jit.OpEq, jit.TInt, fe.op(jit.OpULt, jit.TInt, dist, step), fe.constInt(0))
		} else if step.Aux < 0 {
			dist := fe.op(jit.OpSub, jit.TInt, idx, limit)
			cont = fe.op(jit.OpEq, jit.TInt, fe.op(jit.OpULt, jit.TInt, dist, fe.constInt(-step.Aux)), fe.constInt(0))
		} else {
			fe.exitBlock()
			return
		}
		next = fe.op(jit.OpAdd, jit.TInt, idx, step)
	} else {
		next = fe.op(jit.OpFAdd, jit.TFloat, idx, step)
		if step.Float() > 0 {
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
	if !ok || valueKind(fe.frame[home]) != vkTable {
		return nil, 0, false
	}
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(home), fe.constInt(int64(itabTable))), home, fbValue)
	return fe.slotData(home), home, true
}

// arrayKindOf predicts the array representation of the table in a home
// slot at the current instruction.
func (fe *jitFrontend) arrayKindOf(home int) uint8 {
	if k, ok := fe.jp.feedback[feedbackKey{int32(fe.pc), int16(home), fbArray}]; ok {
		return k
	}
	if tb, ok := fe.frame[home].(*LTable); ok {
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
		// exact integer
		fe.guard(fe.op(jit.OpFLt, jit.TInt, key, fe.f.ConstFloat(fe.cur, 9007199254740992)), -1, 0)
		i := fe.op(jit.OpFloatToInt, jit.TInt, key)
		fe.guard(fe.op(jit.OpFEq, jit.TInt, fe.op(jit.OpIntToFloat, jit.TFloat, i), key), -1, 0)
		key = i
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
	if valueKind(fe.frame[home]) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(home)
	// the result kind for generic arrays is predicted from the value the
	// destination register holds from the previous iteration
	resKind := fe.predictKind(a)
	if akind == arrayKindGeneric && resKind != vkInt && resKind != vkFloat {
		return false
	}
	idx, ok := fe.arrayIndex(c)
	if !ok {
		return false
	}
	tp, home, _ := fe.tableOf(b)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad8, jit.TInt, tp, int64(offTableAkind)), fe.constInt(int64(akind))), home, fbArray)
	var off uintptr
	switch akind {
	case arrayKindInt:
		off = offTableIarr
	case arrayKindFloat:
		off = offTableFarr
	default:
		off = offTableArray
	}
	data := fe.load(jit.OpLoad64, jit.TInt, tp, int64(off)+sliceOffData)
	n := fe.load(jit.OpLoad64, jit.TInt, tp, int64(off)+sliceOffLen)
	fe.guard(fe.op(jit.OpULt, jit.TInt, idx, n), -1, 0)
	switch akind {
	case arrayKindInt:
		addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(3)))
		fe.set(a, skInt, fe.load(jit.OpLoad64, jit.TInt, addr, 0))
	case arrayKindFloat:
		addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(3)))
		fe.set(a, skFloat, fe.load(jit.OpLoadF64, jit.TFloat, addr, 0))
	default:
		addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(4)))
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
	if !ok || valueKind(fe.frame[home]) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(home)
	if akind != arrayKindInt && akind != arrayKindFloat {
		return false
	}
	val, vk, ok := fe.rkNum(c)
	if !ok || (akind == arrayKindInt) != (vk == skInt) {
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
	n := fe.load(jit.OpLoad64, jit.TInt, tp, off+sliceOffLen)
	addr := fe.op(jit.OpAdd, jit.TInt, data, fe.op(jit.OpShl, jit.TInt, idx, fe.constInt(3)))
	inBounds, grow := fe.split(fe.op(jit.OpULt, jit.TInt, idx, n))
	join := fe.f.NewBlock()

	fe.cur = inBounds
	fe.f.NewValue(fe.cur, storeOp, jit.TInt, 0, addr, val)
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
	fe.f.NewValue(fe.cur, storeOp, jit.TInt, 0, addr, val)
	fe.f.NewValue(fe.cur, jit.OpStore64, jit.TInt, off+sliceOffLen, tp, newLen)
	jumpIR(fe.cur, join)

	fe.cur = join
	return true
}

// length translates R(a) := #R(b) for tables with an unboxed array part
// and no metatable.
func (fe *jitFrontend) length(a, b int) bool {
	home, ok := fe.homeSlot(b)
	if !ok || valueKind(fe.frame[home]) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(home)
	if akind != arrayKindInt && akind != arrayKindFloat {
		return false
	}
	tp, home, _ := fe.tableOf(b)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad8, jit.TInt, tp, int64(offTableAkind)), fe.constInt(int64(akind))), home, fbArray)
	mt := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable))
	fe.guard(fe.op(jit.OpEq, jit.TInt, mt, fe.constInt(int64(itabNil))), -1, 0)
	off := int64(offTableIarr)
	if akind == arrayKindFloat {
		off = int64(offTableFarr)
	}
	n := fe.load(jit.OpLoad64, jit.TInt, tp, off+sliceOffLen)
	if fe.L.lang55 {
		fe.set(a, skInt, n)
	} else {
		fe.set(a, skFloat, fe.op(jit.OpIntToFloat, jit.TFloat, n))
	}
	return true
}

/* }}} */
