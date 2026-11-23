package jit

import (
	"errors"
	"fmt"
)

// Layout of the context frame shared by native code and the Go driver.
// All offsets are in bytes; every field is a 64-bit word.
const (
	// CtxExit receives the id of the exit that was taken.
	CtxExit = 0
	// CtxTarget is the address the entry stub jumps to.
	CtxTarget = 8
	// CtxRegBase holds the address of the Lua register window; the entry
	// stub loads it into the pinned register on every entry.
	CtxRegBase = 16
	// CtxFuel is the safe point counter.
	CtxFuel = 24
	// CtxResult is a scratch word used to pass a callout result.
	CtxResult = 32
	// CtxClosure holds the address of the closure whose code is running
	// (filled in by the embedder before every entry).
	CtxClosure = 40
	// CtxBase holds the index of the first register of the running
	// function in the Lua registry (filled in by the embedder).
	CtxBase = 48
	// CtxRegistry holds the address of the registry object of the
	// running thread (filled in by the embedder).
	CtxRegistry = 56
	// CtxSaveG is the save area of the allocatable integer registers.
	CtxSaveG = 64
	// CtxSaveF is the save area of the allocatable float registers.
	CtxSaveF = CtxSaveG + 32*8
	// CtxSpill is the start of the spill slots.
	CtxSpill = CtxSaveF + 32*8
	// CtxHeaderWords is the number of words before the spill slots.
	CtxHeaderWords = CtxSpill / 8
)

// Abstract register indices understood by every MacroAsm in addition to
// the allocatable registers 0..NumGPR()-1 and the two scratch registers
// NumGPR() and NumGPR()+1.
const (
	// RegCtx is the pinned context frame register.
	RegCtx = -1
	// RegBase is the pinned Lua register window register.
	RegBase = -2
)

// Cond is an integer comparison condition.
type Cond uint8

const (
	CondEq Cond = iota
	CondNe
	CondLt
	CondGe
	CondLe
	CondGt
	CondULt
	CondUGe
)

// Negate returns the opposite condition.
func (c Cond) Negate() Cond { return c ^ 1 }

// MacroAsm is the architecture specific code generator driven by Emit.
//
// Integer register operands are abstract indices: 0..NumGPR()-1 are the
// allocatable registers, NumGPR() and NumGPR()+1 are scratch registers
// reserved for the emitter, and RegCtx / RegBase denote the pinned
// registers (valid as sources and as memory bases only). Float registers
// are numbered the same way with NumFPR(). An implementation may use
// further private temporaries but must never clobber an allocatable or
// emitter scratch register that is not the destination of the operation.
// Destinations may alias sources.
type MacroAsm interface {
	NumGPR() int
	NumFPR() int

	NewLabel() int
	Bind(label int)
	LabelOffset(label int) int
	Bytes() ([]byte, error)

	MovRR(dst, src int)
	MovRI(dst int, c int64)
	MovFF(dst, src int)
	MovFI(dst int, bits uint64)

	// Load reads size (1, 4 or 8) bytes zero extended from [base+disp].
	Load(dst, base int, disp int32, size int)
	LoadF(dst, base int, disp int32)
	Store(base int, disp int32, src int)
	StoreF(base int, disp int32, src int)

	// Arith emits dst = a op b for OpAdd..OpMod.
	Arith(op Op, dst, a, b int)
	// ArithImm emits dst = a op c and reports false (emitting nothing) if
	// the operation has no immediate form for c.
	ArithImm(op Op, dst, a int, c int64) bool
	// Unary emits OpNeg and OpNot.
	Unary(op Op, dst, a int)
	// FArith emits OpFAdd..OpFDiv.
	FArith(op Op, dst, a, b int)
	// FUnary emits OpFNeg, OpFSqrt, OpFAbs, OpFFloor and OpFCeil.
	FUnary(op Op, dst, a int)
	IntToFloat(dst, src int)
	FloatToInt(dst, src int)

	// CmpJump jumps to target if "a c b" holds.
	CmpJump(c Cond, a, b int, target int)
	// CmpImmJump is CmpJump with an immediate; it reports false (emitting
	// nothing) if the immediate cannot be encoded.
	CmpImmJump(c Cond, a int, imm int64, target int) bool
	// CmpSet materializes "a c b" as 0 or 1.
	CmpSet(c Cond, dst, a, b int)
	// FCmpJump jumps to target if the float relation op (OpFEq, OpFNe,
	// OpFLt, OpFLe) between a and b equals want.
	FCmpJump(op Op, a, b int, target int, want bool)
	// FCmpSet materializes the float relation as 0 or 1.
	FCmpSet(op Op, dst, a, b int)
	Jump(target int)

	// ExitStub stores code into the exit word of the context frame and
	// jumps to the common exit sequence at label common.
	ExitStub(code uint32, common int)
	// FuelCheck decrements the fuel counter and jumps to slow at zero.
	FuelCheck(slow int)
	// SaveAllAndReturn emits the common exit sequence: it dumps every
	// allocatable register into the save areas and returns to Go.
	SaveAllAndReturn()
	// Enter emits the entry stub: it restores every allocatable register
	// from the save areas, loads the pinned register window register and
	// jumps to the address stored in the target word.
	Enter()
}

// ExitEntry tells the Go driver where a snapshot value lives after an
// exit.
type ExitEntry struct {
	Slot  int
	Tag   uint8
	Loc   Loc
	Const int64
}

// ExitInfo describes an exit of the generated code.
type ExitInfo struct {
	Kind ExitKind
	PC   int
	Data int
	// Resume is the code offset to continue at after a callout or a fuel
	// exit (-1 for deoptimization exits).
	Resume  int
	Entries []ExitEntry
}

// Code is the result of compiling a function.
type Code struct {
	Bytes []byte
	// EntryOffset is the code offset of the entry block. Execution starts
	// at offset 0 (the entry stub) with the target word set to the
	// address of this offset.
	EntryOffset int
	Exits       []ExitInfo
	// FrameWords is the size of the context frame in 64-bit words.
	FrameWords int
	// Stats
	NumValues int
	NumBlocks int
	NumSpills int
}

// Compile optimizes f, allocates registers and emits machine code with
// the given macro assembler.
func Compile(f *Func, m MacroAsm) (*Code, error) {
	removeUnreachable(f)
	if err := f.Verify(); err != nil {
		return nil, err
	}
	Optimize(f)
	splitCriticalEdges(f)
	if err := f.Verify(); err != nil {
		return nil, fmt.Errorf("after optimization: %w", err)
	}
	res := allocate(f, m.NumGPR(), m.NumFPR())
	e := &emitter{f: f, m: m, s0: m.NumGPR(), s1: m.NumGPR() + 1, fs0: m.NumFPR(), fs1: m.NumFPR() + 1}
	return e.emit(res)
}

type emitter struct {
	f   *Func
	m   MacroAsm
	s0  int // integer scratch registers
	s1  int
	fs0 int // float scratch registers
	fs1 int

	blockLabels []int
	stubs       map[*Exit]int // deoptimization and fuel stubs
	stubOrder   []*Exit
	resume      map[*Exit]int // resume labels
	common      int
}

func spillDisp(n int) int32 { return int32(CtxSpill + 8*n) }

// useG returns a register holding the integer value v, loading it into
// scratch if it does not live in a register.
func (e *emitter) useG(v *Value, scratch int) int {
	switch v.Op {
	case OpConst:
		e.m.MovRI(scratch, v.Aux)
		return scratch
	case OpCtx:
		return RegCtx
	case OpRegBase:
		return RegBase
	}
	switch v.loc.Kind {
	case LocReg:
		return v.loc.N
	case LocSpill:
		e.m.Load(scratch, RegCtx, spillDisp(v.loc.N), 8)
		return scratch
	}
	panic(fmt.Sprintf("jit: value %s has no integer location", v.LongString()))
}

// useF is the float counterpart of useG.
func (e *emitter) useF(v *Value, scratch int) int {
	if v.Op == OpConst {
		e.m.MovFI(scratch, uint64(v.Aux))
		return scratch
	}
	switch v.loc.Kind {
	case LocFReg:
		return v.loc.N
	case LocSpill:
		e.m.LoadF(scratch, RegCtx, spillDisp(v.loc.N))
		return scratch
	}
	panic(fmt.Sprintf("jit: value %s has no float location", v.LongString()))
}

// dstG returns the register the result of v is computed into.
func (e *emitter) dstG(v *Value) int {
	if v.loc.Kind == LocReg {
		return v.loc.N
	}
	return e.s0
}

func (e *emitter) dstF(v *Value) int {
	if v.loc.Kind == LocFReg {
		return v.loc.N
	}
	return e.fs0
}

// doneG stores the result register into the spill slot of v if needed.
func (e *emitter) doneG(v *Value, r int) {
	if v.loc.Kind == LocSpill {
		e.m.Store(RegCtx, spillDisp(v.loc.N), r)
	}
}

func (e *emitter) doneF(v *Value, r int) {
	if v.loc.Kind == LocSpill {
		e.m.StoreF(RegCtx, spillDisp(v.loc.N), r)
	}
}

func intCond(op Op) Cond {
	switch op {
	case OpEq:
		return CondEq
	case OpNe:
		return CondNe
	case OpLt:
		return CondLt
	case OpLe:
		return CondLe
	case OpULt:
		return CondULt
	}
	panic("jit: not an integer comparison")
}

// stubLabel returns the label of the out-of-line stub of an exit.
func (e *emitter) stubLabel(x *Exit) int {
	if l, ok := e.stubs[x]; ok {
		return l
	}
	l := e.m.NewLabel()
	e.stubs[x] = l
	e.stubOrder = append(e.stubOrder, x)
	return l
}

// branchCond emits a jump to target taken when the condition value cond
// evaluates to want.
func (e *emitter) branchCond(cond *Value, want bool, target int) {
	if !cond.fused {
		r := e.useG(cond, e.s0)
		c := CondNe
		if !want {
			c = CondEq
		}
		if !e.m.CmpImmJump(c, r, 0, target) {
			panic("jit: cannot compare with zero")
		}
		return
	}
	if cond.Op.IsFloatCompare() {
		a := e.useF(cond.Args[0], e.fs0)
		b := e.useF(cond.Args[1], e.fs1)
		e.m.FCmpJump(cond.Op, a, b, target, want)
		return
	}
	c := intCond(cond.Op)
	if !want {
		c = c.Negate()
	}
	a := e.useG(cond.Args[0], e.s0)
	if rhs := cond.Args[1]; rhs.IsConst() {
		if e.m.CmpImmJump(c, a, rhs.Aux, target) {
			return
		}
	}
	b := e.useG(cond.Args[1], e.s1)
	e.m.CmpJump(c, a, b, target)
}

func (e *emitter) value(v *Value) {
	m := e.m
	switch v.Op {
	case OpConst, OpCtx, OpRegBase, OpPhi:
		return
	case OpAdd, OpSub, OpMul, OpAnd, OpOr, OpXor, OpShl, OpShr, OpSar, OpDiv, OpMod:
		dst := e.dstG(v)
		a := e.useG(v.Args[0], e.s0)
		if rhs := v.Args[1]; rhs.IsConst() && m.ArithImm(v.Op, dst, a, rhs.Aux) {
			e.doneG(v, dst)
			return
		}
		b := e.useG(v.Args[1], e.s1)
		m.Arith(v.Op, dst, a, b)
		e.doneG(v, dst)
	case OpNeg, OpNot:
		dst := e.dstG(v)
		m.Unary(v.Op, dst, e.useG(v.Args[0], e.s0))
		e.doneG(v, dst)
	case OpFAdd, OpFSub, OpFMul, OpFDiv:
		dst := e.dstF(v)
		a := e.useF(v.Args[0], e.fs0)
		b := e.useF(v.Args[1], e.fs1)
		m.FArith(v.Op, dst, a, b)
		e.doneF(v, dst)
	case OpFNeg, OpFSqrt, OpFAbs, OpFFloor, OpFCeil:
		dst := e.dstF(v)
		m.FUnary(v.Op, dst, e.useF(v.Args[0], e.fs0))
		e.doneF(v, dst)
	case OpIntToFloat:
		dst := e.dstF(v)
		m.IntToFloat(dst, e.useG(v.Args[0], e.s0))
		e.doneF(v, dst)
	case OpFloatToInt:
		dst := e.dstG(v)
		m.FloatToInt(dst, e.useF(v.Args[0], e.fs0))
		e.doneG(v, dst)
	case OpEq, OpNe, OpLt, OpLe, OpULt:
		if v.fused {
			return
		}
		dst := e.dstG(v)
		a := e.useG(v.Args[0], e.s0)
		b := e.useG(v.Args[1], e.s1)
		m.CmpSet(intCond(v.Op), dst, a, b)
		e.doneG(v, dst)
	case OpFEq, OpFNe, OpFLt, OpFLe:
		if v.fused {
			return
		}
		dst := e.dstG(v)
		a := e.useF(v.Args[0], e.fs0)
		b := e.useF(v.Args[1], e.fs1)
		m.FCmpSet(v.Op, dst, a, b)
		e.doneG(v, dst)
	case OpLoad64, OpLoad32, OpLoad8:
		size := 8
		if v.Op == OpLoad32 {
			size = 4
		} else if v.Op == OpLoad8 {
			size = 1
		}
		dst := e.dstG(v)
		m.Load(dst, e.useG(v.Args[0], e.s0), int32(v.Aux), size)
		e.doneG(v, dst)
	case OpLoadF64:
		dst := e.dstF(v)
		m.LoadF(dst, e.useG(v.Args[0], e.s0), int32(v.Aux))
		e.doneF(v, dst)
	case OpStore64:
		base := e.useG(v.Args[0], e.s0)
		m.Store(base, int32(v.Aux), e.useG(v.Args[1], e.s1))
	case OpStoreF64:
		base := e.useG(v.Args[0], e.s0)
		m.StoreF(base, int32(v.Aux), e.useF(v.Args[1], e.fs0))
	case OpGuard:
		e.branchCond(v.Args[0], false, e.stubLabel(v.Exit))
	case OpCallout:
		m.ExitStub(uint32(v.Exit.ID), e.common)
		l := m.NewLabel()
		m.Bind(l)
		e.resume[v.Exit] = l
	case OpFuel:
		m.FuelCheck(e.stubLabel(v.Exit))
		l := m.NewLabel()
		m.Bind(l)
		e.resume[v.Exit] = l
	default:
		panic(fmt.Sprintf("jit: cannot emit %s", v.LongString()))
	}
}

// pmove is one element of a parallel move. The source is a location
// (src), a value without location such as a constant (val), or the
// scratch register when parked is set.
type pmove struct {
	dst    Loc
	src    Loc
	val    *Value
	parked bool
	typ    Type
}

// moveSrcG returns a register holding the integer source of mv, using
// scratch when the source is not in a register.
func (e *emitter) moveSrcG(mv pmove, scratch int) int {
	switch {
	case mv.parked:
		return e.s0
	case mv.src.Kind == LocReg:
		return mv.src.N
	case mv.src.Kind == LocSpill:
		e.m.Load(scratch, RegCtx, spillDisp(mv.src.N), 8)
		return scratch
	}
	return e.useG(mv.val, scratch)
}

// moveSrcF is the float counterpart of moveSrcG.
func (e *emitter) moveSrcF(mv pmove, scratch int) int {
	switch {
	case mv.parked:
		return e.fs0
	case mv.src.Kind == LocFReg:
		return mv.src.N
	case mv.src.Kind == LocSpill:
		e.m.LoadF(scratch, RegCtx, spillDisp(mv.src.N))
		return scratch
	}
	return e.useF(mv.val, scratch)
}

// moveLoc emits a single move of a parallel move.
func (e *emitter) moveLoc(mv pmove) {
	m := e.m
	if mv.typ == TFloat {
		if mv.dst.Kind == LocFReg {
			if src := e.moveSrcF(mv, mv.dst.N); src != mv.dst.N {
				m.MovFF(mv.dst.N, src)
			}
			return
		}
		m.StoreF(RegCtx, spillDisp(mv.dst.N), e.moveSrcF(mv, e.fs1))
		return
	}
	if mv.dst.Kind == LocReg {
		if src := e.moveSrcG(mv, mv.dst.N); src != mv.dst.N {
			m.MovRR(mv.dst.N, src)
		}
		return
	}
	m.Store(RegCtx, spillDisp(mv.dst.N), e.moveSrcG(mv, e.s1))
}

// parallelMove emits a set of moves that conceptually happen at the same
// time. A move is emitted once no other pending move still reads its
// destination. When only cycles remain, one source is parked in the
// scratch register (s0 or fs0) and its readers are redirected to it,
// which breaks the cycle. Moves between spill slots use s1 / fs1.
func (e *emitter) parallelMove(moves []pmove) {
	pending := moves[:0]
	for _, mv := range moves {
		if mv.src.Kind != LocNone && mv.src == mv.dst {
			continue
		}
		pending = append(pending, mv)
	}
	blocked := func(i int) bool {
		dst := pending[i].dst
		for j, other := range pending {
			if j != i && !other.parked && other.src.Kind != LocNone && other.src == dst {
				return true
			}
		}
		return false
	}
	for len(pending) > 0 {
		progress := false
		for i := 0; i < len(pending); {
			if blocked(i) {
				i++
				continue
			}
			e.moveLoc(pending[i])
			pending = append(pending[:i], pending[i+1:]...)
			progress = true
		}
		if progress {
			continue
		}
		// only cycles remain; every pending move reads a real location
		k := -1
		for i, mv := range pending {
			if !mv.parked && mv.src.Kind != LocNone {
				k = i
				break
			}
		}
		if k < 0 {
			panic("jit: parallel move is stuck")
		}
		src := pending[k].src
		if pending[k].typ == TFloat {
			e.m.MovFF(e.fs0, e.moveSrcF(pending[k], e.fs0))
		} else {
			e.m.MovRR(e.s0, e.moveSrcG(pending[k], e.s0))
		}
		for i := range pending {
			if !pending[i].parked && pending[i].src == src {
				pending[i].parked = true
				pending[i].src = Loc{}
			}
		}
	}
}

// phiMoves emits the moves for the phis of succ on the edge from b.
func (e *emitter) phiMoves(b, succ *Block) {
	var moves []pmove
	pi := -1
	for _, v := range succ.Values {
		if v.Op != OpPhi {
			break
		}
		if v.loc.Kind == LocNone {
			continue
		}
		if pi < 0 {
			pi = predIndex(succ, b)
		}
		a := v.Args[pi]
		moves = append(moves, pmove{dst: v.loc, src: a.loc, val: a, typ: v.Type})
	}
	if len(moves) > 0 {
		e.parallelMove(moves)
	}
}

func (e *emitter) emit(res AllocResult) (*Code, error) {
	m := e.m
	f := e.f
	e.stubs = make(map[*Exit]int)
	e.resume = make(map[*Exit]int)
	e.blockLabels = make([]int, len(f.Blocks))
	for i := range f.Blocks {
		e.blockLabels[i] = m.NewLabel()
	}
	e.common = m.NewLabel()

	m.Enter()
	for i, b := range f.Blocks {
		m.Bind(e.blockLabels[i])
		for _, v := range b.Values {
			e.value(v)
		}
		var next *Block
		if i+1 < len(f.Blocks) {
			next = f.Blocks[i+1]
		}
		switch b.Kind {
		case BlockJump:
			succ := b.Succs[0]
			e.phiMoves(b, succ)
			if succ != next {
				m.Jump(e.blockLabels[succ.order])
			}
		case BlockIf:
			t, fl := b.Succs[0], b.Succs[1]
			switch {
			case fl == next:
				e.branchCond(b.Control, true, e.blockLabels[t.order])
			case t == next:
				e.branchCond(b.Control, false, e.blockLabels[fl.order])
			default:
				e.branchCond(b.Control, true, e.blockLabels[t.order])
				m.Jump(e.blockLabels[fl.order])
			}
		case BlockExit:
			m.ExitStub(uint32(b.Exit.ID), e.common)
		}
	}
	for i := 0; i < len(e.stubOrder); i++ {
		x := e.stubOrder[i]
		m.Bind(e.stubs[x])
		m.ExitStub(uint32(x.ID), e.common)
	}
	m.Bind(e.common)
	m.SaveAllAndReturn()

	code, err := m.Bytes()
	if err != nil {
		return nil, err
	}
	if len(code) == 0 {
		return nil, errors.New("jit: no code generated")
	}
	out := &Code{
		Bytes:       append([]byte(nil), code...),
		EntryOffset: m.LabelOffset(e.blockLabels[f.Entry.order]),
		Exits:       make([]ExitInfo, len(f.Exits)),
		FrameWords:  CtxHeaderWords + res.Spills,
		NumBlocks:   len(f.Blocks),
		NumSpills:   res.Spills,
	}
	for _, b := range f.Blocks {
		out.NumValues += len(b.Values)
	}
	for i, x := range f.Exits {
		info := ExitInfo{Kind: x.Kind, PC: x.PC, Data: x.Data, Resume: -1}
		if l, ok := e.resume[x]; ok {
			info.Resume = m.LabelOffset(l)
		}
		for _, s := range x.Snap {
			entry := ExitEntry{Slot: s.Slot, Tag: s.Tag, Loc: s.Val.loc}
			switch {
			case s.Val.IsConst():
				entry.Loc = Loc{Kind: LocConst}
				entry.Const = s.Val.Aux
			case s.Val.Op == OpRegBase:
				entry.Loc = Loc{Kind: LocRegBase}
			}
			info.Entries = append(info.Entries, entry)
		}
		out.Exits[i] = info
	}
	return out, nil
}
