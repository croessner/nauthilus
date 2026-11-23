package lua

import (
	"math"
	"math/bits"

	"github.com/yuin/gopher-lua/internal/jit"
)

/*
Index narrowing.

In the Lua 5.1 profile every number is a float, so the index of a numeric
for loop is one too. Using it as a table key or as an operand of the
modulo operator needs its integer value, which costs a conversion and two
guards at every use. The front end therefore carries an integer twin next
to float values that are known to hold integers of a limited magnitude:
the control values of numeric for loops, sums, differences and products
of such values, the length of a table or string. The twin is a second SSA
value that is computed with integer arithmetic; where it is not used it
is removed as dead code.

The twin of a float value v is recorded by the SSA value, not by the
register, so it has to be valid wherever v is: it is either defined
together with v (a phi next to the phi of v, an integer operation next to
the float operation) or it is what v was converted from.
*/

// intTwin is the integer form of a float SSA value: the float holds
// exactly the integer v, whose magnitude is below 2^bits.
type intTwin struct {
	v    *jit.Value
	bits uint8
}

const (
	// twinExactBits bounds the twins: integers below 2^53 are exact as
	// floats, and so is every sum, difference and product below it.
	twinExactBits = 53
	// twinLoopBits bounds the control values of a narrowed loop; the
	// room up to twinExactBits is what index arithmetic can use.
	twinLoopBits = 31
	// twinWideBits is the bound for loops over larger numbers and for
	// lengths.
	twinWideBits = 52
)

// narrowBounds are the bounds tried for the control values of a loop.
var narrowBounds = [...]uint8{twinLoopBits, twinWideBits}

// magnitudeBits returns the smallest b with |c| < 2^b.
func magnitudeBits(c int64) uint8 {
	if c < 0 {
		c = -c
	}
	return uint8(bits.Len64(uint64(c)))
}

// integralBelow reports whether f is an integer with |f| < 2^bits.
func integralBelow(f float64, bits uint8) bool {
	return f == math.Trunc(f) && math.Abs(f) < float64(uint64(1)<<bits)
}

// twinIn returns the integer twin of the float value v for use in block
// b: the one recorded for v or, for an integral constant, a constant.
func (fe *jitFrontend) twinIn(b *jit.Block, v *jit.Value) (intTwin, bool) {
	if v.IsConst() {
		if v.Type != jit.TFloat || !integralBelow(v.Float(), twinWideBits) {
			return intTwin{}, false
		}
		c := int64(v.Float())
		return intTwin{fe.f.ConstInt(b, c), magnitudeBits(c)}, true
	}
	t, ok := fe.twins[v]
	return t, ok
}

// twin is twinIn for the current block.
func (fe *jitFrontend) twin(v *jit.Value) (intTwin, bool) {
	return fe.twinIn(fe.cur, v)
}

// setTwin records iv as the integer twin of the float value v. The
// caller guarantees that iv is defined wherever v is.
func (fe *jitFrontend) setTwin(v, iv *jit.Value, bits uint8) {
	if bits <= twinExactBits && !v.IsConst() {
		fe.twins[v] = intTwin{iv, bits}
	}
}

// predictIntegral reports whether the register holds an integral float
// below 2^bits right now, which is what narrowing speculates on.
func (fe *jitFrontend) predictIntegral(slot int, bits uint8) bool {
	n, ok := fe.frame[slot].(LNumber)
	return ok && integralBelow(float64(n), bits)
}

// predictBelow is predictIntegral for a value that may have a fraction.
func (fe *jitFrontend) predictBelow(slot int, bits uint8) bool {
	n, ok := fe.frame[slot].(LNumber)
	return ok && math.Abs(float64(n)) < float64(uint64(1)<<bits)
}

// narrowBlocked reports whether narrowing the register at the current
// instruction failed before.
func (fe *jitFrontend) narrowBlocked(slot int) bool {
	return fe.jp.feedback[feedbackKey{fe.fbpc(), int16(slot), fbNarrow}] > 0
}

// guardBelow deoptimizes unless |v| < 2^bits for the float value v (a NaN
// fails as well). A failure turns narrowing off for the register slot at
// the current instruction.
func (fe *jitFrontend) guardBelow(v *jit.Value, bits uint8, slot int) {
	abs := fe.op(jit.OpFAbs, jit.TFloat, v)
	fe.guard(fe.op(jit.OpFLt, jit.TInt, abs, fe.f.ConstFloat(fe.cur, float64(uint64(1)<<bits))), slot, fbNarrow)
}

// guardIntBelow is guardBelow for an integer value.
func (fe *jitFrontend) guardIntBelow(iv *jit.Value, bits uint8, slot int) {
	// -2^bits < iv < 2^bits  <=>  iv + 2^bits - 1 (unsigned) < 2^(bits+1) - 1
	bound := int64(1) << bits
	shifted := fe.op(jit.OpAdd, jit.TInt, iv, fe.constInt(bound-1))
	fe.guard(fe.op(jit.OpULt, jit.TInt, shifted, fe.constInt(2*bound-1)), slot, fbNarrow)
}

// exactInt converts the float value v to an integer, deoptimizing unless
// v is an integer below 2^bits.
func (fe *jitFrontend) exactInt(v *jit.Value, bits uint8, slot int) *jit.Value {
	fe.guardBelow(v, bits, slot)
	i := fe.op(jit.OpFloatToInt, jit.TInt, v)
	fe.guard(fe.op(jit.OpFEq, jit.TInt, fe.op(jit.OpIntToFloat, jit.TFloat, i), v), slot, fbNarrow)
	return i
}

// entryForLoop returns the base register of the numeric for loop whose
// body the compiled code is entered at.
func (fe *jitFrontend) entryForLoop() (a int, ok bool) {
	for pc, inst := range fe.proto.Code {
		if !fe.info.data[pc] && opGetOpCode(inst) == OP_FORLOOP && pc+1+opGetArgSbx(inst) == fe.entryPC {
			return opGetArgA(inst), true
		}
	}
	return 0, false
}

// narrowEntry gives the registers that are unboxed in the entry block
// integer twins: the control values of the loop that is entered and the
// registers the loop uses for indexing without changing them.
func (fe *jitFrontend) narrowEntry() {
	if fe.L.lang55 {
		return
	}
	if a, ok := fe.entryForLoop(); ok {
		fe.narrowEntryLoop(a)
	}
	written := fe.writtenInLoop(fe.entryPC)
	used := fe.indexRegisters()
	for slot := range fe.st {
		s := &fe.st[slot]
		if s.kind != skFloat || s.val.IsConst() || !used.has(slot) || written.has(slot) || fe.narrowBlocked(slot) {
			continue
		}
		if _, done := fe.twins[s.val]; done {
			continue
		}
		for _, bits := range narrowBounds {
			if fe.predictIntegral(slot, bits) {
				fe.setTwin(s.val, fe.exactInt(s.val, bits, slot), bits)
				break
			}
		}
	}
}

// narrowEntryLoop narrows the control values in R(a..a+3) of the numeric
// for loop the code is entered at, if they are integers right now.
func (fe *jitFrontend) narrowEntryLoop(a int) {
	idx, limit, step := &fe.st[a], &fe.st[a+1], &fe.st[a+2]
	if idx.kind != skFloat || limit.kind != skFloat || step.kind != skFloat || fe.narrowBlocked(a) {
		return
	}
	for _, bits := range narrowBounds {
		if !fe.predictIntegral(a, bits) || !fe.predictIntegral(a+2, bits) || !fe.predictBelow(a+1, bits) {
			continue
		}
		fe.setTwin(idx.val, fe.exactInt(idx.val, bits, a), bits)
		if !step.val.IsConst() {
			fe.setTwin(step.val, fe.exactInt(step.val, bits, a), bits)
		}
		fe.guardBelow(limit.val, bits, a)
		fe.loopBits[fe.entryPC] = bits
		// the loop variable is a copy of the index when the body starts
		if v := &fe.st[a+3]; v.kind == skFloat && v.val != idx.val {
			fe.guard(fe.op(jit.OpFEq, jit.TInt, v.val, idx.val), -1, 0)
			v.val = idx.val
		}
		return
	}
}

// narrowForPrep narrows the control values of a numeric for loop that
// starts inside the compiled code. It returns the initial index and the
// step as floats that have integer twins and the bound of the control
// values; ok is false if the loop is not narrowed, in which case nothing
// was emitted.
func (fe *jitFrontend) narrowForPrep(a int, init, limit, step *jit.Value) (ninit, nstep *jit.Value, bound uint8, ok bool) {
	if fe.L.lang55 || fe.narrowBlocked(a) {
		return nil, nil, 0, false
	}
	it, iok := fe.twin(init)
	st, sok := fe.twin(step)
	lt, lok := fe.twin(limit)
	// What is not known about an operand is guessed from the value its
	// register holds from the last time the loop ran; a constant is
	// known completely.
	fits := func(v *jit.Value, t intTwin, known bool, slot int, bits uint8) bool {
		if known && t.bits <= bits {
			return true
		}
		return !v.IsConst() && fe.predictIntegral(slot, bits)
	}
	limitBelow := func(bits uint8) bool {
		switch {
		case lok && lt.bits <= bits:
			return true
		case limit.IsConst():
			return math.Abs(limit.Float()) < float64(uint64(1)<<bits)
		}
		return fe.predictBelow(a+1, bits)
	}
	for _, bits := range narrowBounds {
		if fits(init, it, iok, a, bits) && fits(step, st, sok, a+2, bits) && limitBelow(bits) {
			bound, ok = bits, true
			break
		}
	}
	if !ok {
		return nil, nil, 0, false
	}
	// narrowed returns the float form of an operand together with its
	// twin: a new value, so that the twin is defined wherever it is.
	narrowed := func(f *jit.Value, t intTwin, known bool) *jit.Value {
		switch {
		case !known:
			t.v = fe.exactInt(f, bound, a)
		case t.bits > bound:
			fe.guardIntBelow(t.v, bound, a)
		}
		if t.v.IsConst() {
			return fe.f.ConstFloat(fe.cur, float64(t.v.Aux))
		}
		nf := fe.op(jit.OpIntToFloat, jit.TFloat, t.v)
		fe.setTwin(nf, t.v, bound)
		return nf
	}
	ninit, nstep = narrowed(init, it, iok), narrowed(step, st, sok)
	if !limit.IsConst() && (!lok || lt.bits > bound) {
		fe.guardBelow(limit, bound, a)
	}
	return ninit, nstep, bound, true
}

// narrowNext gives the next index of a narrowed numeric for loop its
// twin. The loop continues only while the index does not pass the limit,
// so the index keeps the bound of the control values.
func (fe *jitFrontend) narrowNext(pcBody int, next, idx, step *jit.Value) {
	bound, ok := fe.loopBits[pcBody]
	if !ok {
		return
	}
	ti, ok1 := fe.twin(idx)
	ts, ok2 := fe.twin(step)
	if ok1 && ok2 && ti.bits <= bound && ts.bits <= bound {
		fe.setTwin(next, fe.op(jit.OpAdd, jit.TInt, ti.v, ts.v), bound)
	}
}

// deriveTwin gives the result r of the float addition, subtraction or
// multiplication of x and y a twin computed with the integer operation
// o, if both operands have twins and the result is certainly exact.
func (fe *jitFrontend) deriveTwin(o jit.Op, r, x, y *jit.Value) {
	if len(fe.twins) == 0 || (x.IsConst() && y.IsConst()) {
		return
	}
	tx, ok1 := fe.twin(x)
	ty, ok2 := fe.twin(y)
	if !ok1 || !ok2 {
		return
	}
	bits := tx.bits + ty.bits
	if o != jit.OpMul {
		bits = max(tx.bits, ty.bits) + 1
	}
	if bits <= twinExactBits {
		fe.setTwin(r, fe.op(o, jit.TInt, tx.v, ty.v), bits)
	}
}

// floorTwin gives r = floor(x) a twin if x is the quotient of a value
// with a twin and a constant integer: the float quotient of two integers
// below 2^52 is too close to the exact quotient to round across an
// integer, so its floor is the integer floor division.
func (fe *jitFrontend) floorTwin(r, x *jit.Value) {
	if t, ok := fe.twin(x); ok {
		fe.setTwin(r, t.v, t.bits)
		return
	}
	if x.Op != jit.OpFDiv {
		return
	}
	tn, ok1 := fe.twin(x.Args[0])
	td, ok2 := fe.twin(x.Args[1])
	if ok1 && ok2 && tn.bits <= twinWideBits && td.v.IsConst() && td.v.Aux != 0 {
		fe.setTwin(r, fe.op(jit.OpDiv, jit.TInt, tn.v, td.v), tn.bits)
	}
}

// twinPhi gives the float phi of a register at the entry of block tb an
// integer twin if every edge that reached the block delivers one. The
// twin of a phi at the head of a narrowed loop is given the bound of the
// control values of the loop, which the edges that arrive later must
// keep (see twinConforms).
func (fe *jitFrontend) twinPhi(tb *feBlock, slot int, phi *jit.Value) {
	if len(fe.twins) == 0 || fe.noTwin[demoteKey{tb.pc, slot}] {
		return
	}
	bits := fe.loopBits[tb.pc]
	args := make([]*jit.Value, len(tb.incoming))
	for i := range tb.incoming {
		in := &tb.incoming[i]
		t, ok := fe.twinIn(in.from, in.st[slot].val)
		if !ok {
			return
		}
		args[i] = t.v
		bits = max(bits, t.bits)
	}
	ip := fe.f.NewPhi(tb.ir, jit.TInt)
	ip.Args = args
	fe.setTwin(phi, ip, bits)
}

// phiTwin returns the twin phi that belongs to the float phi of a
// register at the entry of tb.
func (fe *jitFrontend) phiTwin(tb *feBlock, phi *jit.Value) (intTwin, bool) {
	t, ok := fe.twins[phi]
	if !ok || t.v.Op != jit.OpPhi || t.v.Block != tb.ir {
		return intTwin{}, false
	}
	return t, true
}

// twinConforms reports whether the value have that an edge from block
// from delivers for a float phi of tb fits the twin of that phi.
func (fe *jitFrontend) twinConforms(from *jit.Block, tb *feBlock, phi, have *jit.Value) bool {
	want, ok := fe.phiTwin(tb, phi)
	if !ok {
		return true
	}
	t, ok := fe.twinIn(from, have)
	return ok && t.bits <= want.bits
}

// addTwinArg appends the twin of the value have, delivered by an edge
// from block from, to the twin phi of a float phi of tb.
func (fe *jitFrontend) addTwinArg(from *jit.Block, tb *feBlock, phi, have *jit.Value) {
	if want, ok := fe.phiTwin(tb, phi); ok {
		t, _ := fe.twinIn(from, have)
		want.v.Args = append(want.v.Args, t.v)
	}
}

// indexRegisters returns the registers whose value takes part in
// indexing somewhere in the function: table keys, operands of the modulo
// operator and what these are computed from. It decides which registers
// are worth an integer twin.
func (fe *jitFrontend) indexRegisters() *regSet {
	if fe.indexRegs != nil {
		return fe.indexRegs
	}
	used := &regSet{}
	addRK := func(rk int) bool {
		if opIsK(rk) || used.has(rk) {
			return false
		}
		used.add(rk)
		return true
	}
	for changed := true; changed; {
		changed = false
		for pc, inst := range fe.proto.Code {
			if fe.info.data[pc] {
				continue
			}
			A, B, C := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
			switch opGetOpCode(inst) {
			case OP_GETTABLE:
				changed = addRK(C) || changed
			case OP_SETTABLE:
				changed = addRK(B) || changed
			case OP_MOD:
				changed = addRK(B) || changed
				changed = addRK(C) || changed
			case OP_ADD, OP_SUB, OP_MUL, OP_DIV:
				if used.has(A) {
					changed = addRK(B) || changed
					changed = addRK(C) || changed
				}
			case OP_MOVE, OP_UNM:
				if used.has(A) {
					changed = addRK(B) || changed
				}
			case OP_CALL:
				// the result of math.floor(x) is an index if x is
				if used.has(A) {
					changed = addRK(A+1) || changed
				}
			}
		}
	}
	fe.indexRegs = used
	return used
}
