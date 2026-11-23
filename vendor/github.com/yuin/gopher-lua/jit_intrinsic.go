package lua

import (
	"reflect"
	"sync"
	"unsafe"

	"github.com/yuin/gopher-lua/internal/jit"
)

// Intrinsics: library functions with a native translation.
const (
	intrNone = iota
	intrSqrt
	intrFloor
	intrCeil
	intrAbs
	intrMax
	intrMin
	intrType
	intrToNumber
	intrByte
	intrStrLen
)

// jitMaxSelectArgs bounds the arguments of math.max and math.min that
// are compared in native code.
const jitMaxSelectArgs = 4

var (
	intrinsicOnce  sync.Once
	intrinsicKinds map[uintptr]int
)

// intrinsicOf identifies library functions that have a native form.
func intrinsicOf(fn *LFunction) int {
	if fn == nil || !fn.IsG || fn.GFunction == nil {
		return intrNone
	}
	intrinsicOnce.Do(func() {
		intrinsicKinds = make(map[uintptr]int)
		for kind, fns := range map[int][]LGFunction{
			intrSqrt:     {mathSqrt},
			intrFloor:    {mathFloor, math55Floor},
			intrCeil:     {mathCeil, math55Ceil},
			intrAbs:      {mathAbs, math55Abs},
			intrMax:      {mathMax, math55Max},
			intrMin:      {mathMin, math55Min},
			intrType:     {baseType},
			intrToNumber: {baseToNumber, base55ToNumber},
			intrByte:     {strByte, str55Byte},
			intrStrLen:   {strLen, str55Len},
		} {
			for _, f := range fns {
				intrinsicKinds[reflect.ValueOf(f).Pointer()] = kind
			}
		}
	})
	return intrinsicKinds[reflect.ValueOf(fn.GFunction).Pointer()]
}

// floatToIntExact converts a float value that is known to be integral
// to an integer, deoptimizing if it does not fit.
func (fe *jitFrontend) floatToIntExact(f *jit.Value) *jit.Value {
	fe.guard(fe.op(jit.OpFLt, jit.TInt, f, fe.f.ConstFloat(fe.cur, 9223372036854775808.0)), -1, 0)
	fe.guard(fe.op(jit.OpFLe, jit.TInt, fe.f.ConstFloat(fe.cur, -9223372036854775808.0), f), -1, 0)
	return fe.op(jit.OpFloatToInt, jit.TInt, f)
}

// setIntResult sets R(a) to an integer below 2^bits that a library
// function or operator yields: an integer in the Lua 5.5 profile, a
// float with an integer twin in the Lua 5.1 profile.
func (fe *jitFrontend) setIntResult(a int, n *jit.Value, bits uint8) {
	if fe.L.lang55 {
		fe.set(a, skInt, n)
		return
	}
	f := fe.op(jit.OpIntToFloat, jit.TFloat, n)
	fe.setTwin(f, n, bits)
	fe.set(a, skFloat, f)
}

// numKind predicts the kind of the number in a register without
// emitting code: what num would return for it.
func (fe *jitFrontend) numKind(slot int) (slotKind, bool) {
	var vk uint8
	switch s := &fe.st[slot]; s.kind {
	case skInt, skFloat:
		return s.kind, true
	case skHome:
		vk = fe.predictKind(slot)
	case skRef:
		vk = valueKind(fe.peek(refLoc(slot)))
	}
	switch vk {
	case vkInt:
		return skInt, true
	case vkFloat:
		return skFloat, true
	}
	return 0, false
}

// typeAt returns the name of the type of the value in a register, as
// the type function reports it. The type of a boxed value is the one
// the register holds now; with emit set the code is made to depend on
// it. ok is false if nothing is known about the register.
func (fe *jitFrontend) typeAt(slot int, emit bool) (name string, ok bool) {
	switch s := &fe.st[slot]; s.kind {
	case skInt, skFloat:
		return LTNumber.String(), true
	case skBool:
		return LTBool.String(), true
	case skNil:
		return LTNil.String(), true
	case skConst:
		return fe.consts[s.src].Type().String(), true
	}
	loc, ok := fe.homeSlot(slot)
	if !ok {
		return "", false
	}
	v := fe.peek(loc)
	if v == nil {
		return "", false
	}
	if emit {
		fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(loc), fe.constInt(int64(itabOf(v)))), loc, fbValue)
	}
	return v.Type().String(), true
}

// intrinsicArgs reports whether the arguments in R(a+1..a+nargs) have a
// shape the native form of the library function handles.
func (fe *jitFrontend) intrinsicArgs(kind, a, nargs int) bool {
	switch kind {
	case intrType:
		_, ok := fe.typeAt(a+1, false)
		return ok && nargs == 1
	case intrStrLen:
		return nargs == 1 && fe.isString(a+1)
	case intrByte:
		// one byte at a given position; the forms with a default
		// position or a range can return any number of values
		k, ok := fe.numKind(a + 2)
		return ok && nargs == 2 && fe.isString(a+1) && !(k == skFloat && fe.L.lang55)
	case intrMax, intrMin:
		if nargs < 2 || nargs > jitMaxSelectArgs {
			return false
		}
		// the result is one of the arguments: they must be of one kind
		first, ok := fe.numKind(a + 1)
		for i := 2; ok && i <= nargs; i++ {
			var k slotKind
			k, ok = fe.numKind(a + i)
			ok = ok && k == first
		}
		return ok
	}
	_, ok := fe.numKind(a + 1)
	return ok && nargs == 1
}

// intrinsicCall translates the call R(a)(R(a+1), ..., R(a+b-1)) of a
// known library function with one result into native code. It reports
// false, having emitted nothing, if the call is not such a call.
func (fe *jitFrontend) intrinsicCall(a, b, c int) bool {
	if c != 2 && c != 0 {
		return false
	}
	fn, home := fe.functionAt(a)
	kind := intrinsicOf(fn)
	site := feedbackKey{fe.fbpc(), int16(a), fbInline}
	if kind == intrNone || !fe.intrinsicArgs(kind, a, b-1) || fe.jp.feedback[site] >= jitFieldMisses {
		return false
	}
	if home >= 0 {
		// the function was found in a register (local floor = math.floor)
		fe.guardCallee(fn, home, site)
	}
	switch kind {
	case intrType:
		name, _ := fe.typeAt(a+1, true)
		fe.st[a] = slotState{kind: skConst, src: fe.constIndex(LString(name))}
	case intrToNumber:
		fe.move(a, a+1)
	case intrStrLen:
		_, n := fe.stringParts(a + 1)
		fe.setIntResult(a, n, twinWideBits)
	case intrByte:
		ptr, n := fe.stringParts(a + 1)
		idx, _ := fe.arrayIndex(a + 2)
		// a position outside the string (or one counted from its end)
		// is left to the library function
		fe.guard(fe.op(jit.OpULt, jit.TInt, idx, n), a, fbInline)
		fe.setIntResult(a, fe.load(jit.OpLoad8, jit.TInt, fe.op(jit.OpAdd, jit.TInt, ptr, idx), 0), 8)
	case intrMax, intrMin:
		fe.intrinsicSelect(a, b-1, kind == intrMax)
	default:
		fe.intrinsicMath(kind, a)
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

// intrinsicMath translates R(a) := f(R(a+1)) for the math functions of
// one number.
func (fe *jitFrontend) intrinsicMath(kind, a int) {
	x, xk, _ := fe.num(a + 1)
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
			fx := fe.toFloat(x, xk)
			r := fe.op(o, jit.TFloat, fx)
			if kind == intrFloor && xk == skFloat {
				fe.floorTwin(r, fx)
			}
			fe.set(a, skFloat, r)
		}
	case intrAbs:
		if xk == skInt && lang55 {
			mask := fe.op(jit.OpSar, jit.TInt, x, fe.constInt(63))
			fe.set(a, skInt, fe.op(jit.OpSub, jit.TInt, fe.op(jit.OpXor, jit.TInt, x, mask), mask))
		} else {
			fe.set(a, skFloat, fe.op(jit.OpFAbs, jit.TFloat, fe.toFloat(x, xk)))
		}
	}
}

// intrinsicSelect translates R(a) := math.max(R(a+1), ..., R(a+nargs))
// or math.min. Like the library functions it keeps the first argument
// unless a later one is strictly greater (smaller), which also decides
// what a NaN or a zero of the other sign yields.
func (fe *jitFrontend) intrinsicSelect(a, nargs int, largest bool) {
	cur, kind, _ := fe.num(a + 1)
	lt, typ := jit.OpFLt, jit.TFloat
	if kind == skInt {
		lt, typ = jit.OpLt, jit.TInt
	}
	for i := 2; i <= nargs; i++ {
		v, _, _ := fe.num(a + i)
		better := fe.op(lt, jit.TInt, cur, v)
		if !largest {
			better = fe.op(lt, jit.TInt, v, cur)
		}
		take, keep := fe.split(better)
		join := fe.f.NewBlock()
		jumpIR(take, join)
		jumpIR(keep, join)
		fe.cur = join
		phi := fe.f.NewPhi(join, typ)
		phi.Args = []*jit.Value{v, cur}
		if kind == skFloat {
			// an index stays an index: math.min(i, n)
			tv, ok1 := fe.twinIn(take, v)
			tc, ok2 := fe.twinIn(keep, cur)
			if ok1 && ok2 && len(fe.twins) > 0 {
				ip := fe.f.NewPhi(join, jit.TInt)
				ip.Args = []*jit.Value{tv.v, tc.v}
				fe.setTwin(phi, ip, max(tv.bits, tc.bits))
			}
		}
		cur = phi
	}
	fe.set(a, kind, cur)
}

// stringOperand returns the string a register-or-constant operand is
// known to hold when the code is compiled.
func (fe *jitFrontend) stringOperand(rk int) (string, bool) {
	var v LValue
	if rk&opBitRk != 0 {
		v = fe.proto.Constants[rk&^opBitRk]
	} else if s := &fe.st[rk]; s.kind == skConst {
		v = fe.consts[s.src]
	}
	str, ok := v.(LString)
	return string(str), ok
}

// constantEquality decides R(b) == R(c) at compile time where a string
// constant is involved: two known strings are compared here, and a
// string never equals a number, a boolean or nil.
func (fe *jitFrontend) constantEquality(b, c int) (equal, known bool) {
	sb, okb := fe.stringOperand(b)
	sc, okc := fe.stringOperand(c)
	switch {
	case okb && okc:
		return sb == sc, true
	case !okb && !okc:
		return false, false
	}
	// the operand that is not a known string
	other := b
	if okb {
		other = c
	}
	if other&opBitRk != 0 {
		return false, true // a constant of another type
	}
	switch fe.st[other].kind {
	case skInt, skFloat, skBool, skNil, skConst:
		// (a constant that is not a string is a function or a table)
		return false, true
	}
	return false, false
}

// jitMaxStringCompare is the length up to which strings are compared
// byte by byte in native code.
const jitMaxStringCompare = 64

// isString predicts whether a register-or-constant operand is a string.
func (fe *jitFrontend) isString(rk int) bool {
	if _, ok := fe.stringOperand(rk); ok {
		return true
	}
	if rk&opBitRk != 0 {
		return false
	}
	loc, ok := fe.homeSlot(rk)
	return ok && valueKind(fe.peek(loc)) == vkString
}

// stringParts returns the address of the bytes and the length of the
// string an operand holds (see isString), guarded by a type check.
func (fe *jitFrontend) stringParts(rk int) (ptr, n *jit.Value) {
	if s, ok := fe.stringOperand(rk); ok {
		fe.constIndex(LString(s)) // keeps the bytes alive
		return fe.constInt(int64(uintptr(unsafe.Pointer(unsafe.StringData(s))))), fe.constInt(int64(len(s)))
	}
	loc, _ := fe.homeSlot(rk)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(loc), fe.constInt(int64(itabString))), loc, fbValue)
	header := fe.slotData(loc)
	return fe.load(jit.OpLoad64, jit.TInt, header, 0), fe.load(jit.OpLoad64, jit.TInt, header, 8)
}

// stringEq translates the comparison of two strings for equality:
// strings of different length differ, strings that share their bytes
// are equal, and the bytes of any other pair are compared one by one.
// Long strings that need the comparison of their bytes are left to the
// interpreter.
func (fe *jitFrontend) stringEq(b, c int) *jit.Value {
	pb, nb := fe.stringParts(b)
	pc, nc := fe.stringParts(c)
	join := fe.f.NewBlock()
	var results []*jit.Value
	// decided ends the block blk with the given outcome
	decided := func(blk *jit.Block, equal int64) {
		results = append(results, fe.f.ConstInt(blk, equal))
		jumpIR(blk, join)
	}
	sameLen, otherLen := fe.split(fe.op(jit.OpEq, jit.TInt, nb, nc))
	decided(otherLen, 0)
	fe.cur = sameLen
	shared, apart := fe.split(fe.op(jit.OpEq, jit.TInt, pb, pc))
	decided(shared, 1)
	fe.cur = apart
	fe.guard(fe.op(jit.OpULt, jit.TInt, nb, fe.constInt(jitMaxStringCompare+1)), -1, 0)
	zero := fe.constInt(0)
	head := fe.f.NewBlock()
	jumpIR(fe.cur, head)
	fe.cur = head
	i := fe.f.NewPhi(head, jit.TInt)
	done, more := fe.split(fe.op(jit.OpEq, jit.TInt, i, nb))
	decided(done, 1)
	fe.cur = more
	x := fe.load(jit.OpLoad8, jit.TInt, fe.op(jit.OpAdd, jit.TInt, pb, i), 0)
	y := fe.load(jit.OpLoad8, jit.TInt, fe.op(jit.OpAdd, jit.TInt, pc, i), 0)
	next := fe.op(jit.OpAdd, jit.TInt, i, fe.constInt(1))
	same, differ := fe.split(fe.op(jit.OpEq, jit.TInt, x, y))
	decided(differ, 0)
	jumpIR(same, head)
	i.Args = []*jit.Value{zero, next}
	fe.cur = join
	result := fe.f.NewPhi(join, jit.TInt)
	result.Args = results
	return result
}
