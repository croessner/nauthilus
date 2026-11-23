package lua

import (
	"math"
	"strings"
)

// This file contains the number semantics shared by the interpreter, the
// constant folder and the JIT runtime helpers: arithmetic on the integer
// and float subtypes, numeric for loops and to-be-closed variables.

// toFloat converts a number value to float64.
func toFloat(v LValue) (float64, bool) {
	switch n := v.(type) {
	case LNumber:
		return float64(n), true
	case LInteger:
		return float64(n), true
	}
	return 0, false
}

// isBitwiseOp reports whether opcode is a bitwise binary operator.
func isBitwiseOp(opcode int) bool {
	return opcode >= OP_BAND && opcode <= OP_SHR
}

// numberArith55 performs a binary arithmetic or bitwise operation on two
// number values with Lua 5.3+ semantics (integer and float subtypes). ok
// is false if an operand is not a number or the operation raises an
// error (integer division or modulo by zero, no integer representation).
func numberArith55(opcode int, lhs, rhs LValue) (LValue, bool) {
	switch opcode {
	case OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR:
		a, ok1 := LVAsInteger(lhs)
		b, ok2 := LVAsInteger(rhs)
		if !ok1 || !ok2 {
			return nil, false
		}
		switch opcode {
		case OP_BAND:
			return LInteger(a & b), true
		case OP_BOR:
			return LInteger(a | b), true
		case OP_BXOR:
			return LInteger(a ^ b), true
		case OP_SHL:
			return LInteger(intShiftLeft(a, b)), true
		default:
			if b == minInteger {
				return LInteger(0), true
			}
			return LInteger(intShiftLeft(a, -b)), true
		}
	case OP_DIV, OP_POW:
		a, ok1 := toFloat(lhs)
		b, ok2 := toFloat(rhs)
		if !ok1 || !ok2 {
			return nil, false
		}
		if opcode == OP_DIV {
			return LNumber(a / b), true
		}
		return LNumber(numPow(a, b)), true
	}
	if li, ok := lhs.(LInteger); ok {
		if ri, ok := rhs.(LInteger); ok {
			switch opcode {
			case OP_ADD:
				return li + ri, true
			case OP_SUB:
				return li - ri, true
			case OP_MUL:
				return li * ri, true
			case OP_MOD:
				if ri == 0 {
					return nil, false
				}
				return LInteger(intMod(int64(li), int64(ri))), true
			case OP_IDIV:
				if ri == 0 {
					return nil, false
				}
				return LInteger(intFloorDiv(int64(li), int64(ri))), true
			}
			return nil, false
		}
	}
	a, ok1 := toFloat(lhs)
	b, ok2 := toFloat(rhs)
	if !ok1 || !ok2 {
		return nil, false
	}
	switch opcode {
	case OP_ADD:
		return LNumber(a + b), true
	case OP_SUB:
		return LNumber(a - b), true
	case OP_MUL:
		return LNumber(a * b), true
	case OP_MOD:
		return LNumber(floatMod(a, b)), true
	case OP_IDIV:
		return LNumber(math.Floor(a / b)), true
	}
	return nil, false
}

var arithEvents = map[int]string{
	OP_ADD: "__add", OP_SUB: "__sub", OP_MUL: "__mul", OP_DIV: "__div",
	OP_MOD: "__mod", OP_POW: "__pow", OP_IDIV: "__idiv", OP_BAND: "__band",
	OP_BOR: "__bor", OP_BXOR: "__bxor", OP_SHL: "__shl", OP_SHR: "__shr",
}

// typeNameOf returns the type name used in error messages; it honors the
// __name metafield in the Lua 5.5 profile.
func (ls *LState) typeNameOf(v LValue) string {
	if ls.lang55 {
		if mt, ok := ls.metatable(v, true).(*LTable); ok {
			if name, ok := mt.RawGetString("__name").(LString); ok {
				return string(name)
			}
		}
	}
	return v.Type().String()
}

// arithSlow implements the generic path of the binary arithmetic and
// bitwise operators: mixed number subtypes, metamethods, string coercion
// and error reporting.
func arithSlow(L *LState, opcode int, lhs, rhs LValue) LValue {
	if v, ok := numberArith55(opcode, lhs, rhs); ok {
		return v
	}
	_, lnum := toFloat(lhs)
	_, rnum := toFloat(rhs)
	if lnum && rnum {
		// both are numbers: the operation itself failed
		switch opcode {
		case OP_MOD:
			L.RaiseError("%s", "attempt to perform 'n%0'")
		case OP_IDIV:
			L.RaiseError("attempt to divide by zero")
		default:
			L.RaiseError("number has no integer representation")
		}
		return LNil
	}
	event := arithEvents[opcode]
	op := L.metaOp2(lhs, rhs, event)
	if _, ok := op.(*LFunction); ok {
		L.reg.Push(op)
		L.reg.Push(lhs)
		L.reg.Push(rhs)
		L.Call(2, 1)
		return L.reg.Pop()
	}
	bitwise := isBitwiseOp(opcode)
	if !bitwise || !L.lang55 {
		// strings are coerced to numbers by arithmetic operators
		nl, nr := lhs, rhs
		if str, ok := lhs.(LString); ok {
			if n, ok := L.strToNumber(string(str)); ok {
				nl = n
			}
		}
		if str, ok := rhs.(LString); ok {
			if n, ok := L.strToNumber(string(str)); ok {
				nr = n
			}
		}
		if v, ok := numberArith55(opcode, nl, nr); ok {
			return v
		}
		_, lnum = toFloat(nl)
		_, rnum = toFloat(nr)
		if lnum && rnum {
			return arithSlow(L, opcode, nl, nr) // raises the operation error
		}
	}
	if !L.lang55 {
		L.RaiseError("cannot perform %v operation between %v and %v",
			strings.TrimLeft(event, "_"), lhs.Type().String(), rhs.Type().String())
		return LNil
	}
	culprit := rhs
	if _, ok := toFloat(lhs); !ok {
		culprit = lhs
	}
	if bitwise {
		if _, isnum := toFloat(culprit); isnum {
			L.RaiseError("number has no integer representation")
		}
		L.RaiseError("attempt to perform bitwise operation on a %s value", L.typeNameOf(culprit))
	}
	L.RaiseError("attempt to perform arithmetic on a %s value", L.typeNameOf(culprit))
	return LNil
}

// unaryMinus implements the generic path of the unary minus operator.
func unaryMinus(L *LState, v LValue) LValue {
	switch n := v.(type) {
	case LNumber:
		return -n
	case LInteger:
		return -n
	}
	op := L.metaOp1(v, "__unm")
	if op.Type() == LTFunction {
		L.reg.Push(op)
		L.reg.Push(v)
		if L.lang55 {
			L.reg.Push(v)
			L.Call(2, 1)
		} else {
			L.Call(1, 1)
		}
		return L.reg.Pop()
	}
	if str, ok := v.(LString); ok {
		if num, ok := L.strToNumber(string(str)); ok {
			return unaryMinus(L, num)
		}
	}
	if L.lang55 {
		L.RaiseError("attempt to perform arithmetic on a %s value", L.typeNameOf(v))
	}
	L.RaiseError("__unm undefined")
	return LNil
}

// bitwiseNot implements the unary bitwise not operator.
func bitwiseNot(L *LState, v LValue) LValue {
	if i, ok := LVAsInteger(v); ok {
		return LInteger(^i)
	}
	op := L.metaOp1(v, "__bnot")
	if op.Type() == LTFunction {
		L.reg.Push(op)
		L.reg.Push(v)
		L.reg.Push(v)
		L.Call(2, 1)
		return L.reg.Pop()
	}
	if _, ok := toFloat(v); ok {
		L.RaiseError("number has no integer representation")
	}
	L.RaiseError("attempt to perform bitwise operation on a %s value", L.typeNameOf(v))
	return LNil
}

// objLen implements the generic path of the length operator.
func objLen(L *LState, v LValue) LValue {
	if s, ok := v.(LString); ok {
		return L.newInt(int64(len(s)))
	}
	op := L.metaOp1(v, "__len")
	if op.Type() == LTFunction {
		L.reg.Push(op)
		L.reg.Push(v)
		L.Call(1, 1)
		return L.reg.Pop()
	}
	if tb, ok := v.(*LTable); ok {
		return L.newInt(int64(tb.Len()))
	}
	if L.lang55 {
		L.RaiseError("attempt to get length of a %s value", L.typeNameOf(v))
	}
	L.RaiseError("__len undefined")
	return LNil
}

// compareError raises the error for an invalid order comparison.
func compareError(L *LState, lhs, rhs LValue) {
	if L.lang55 {
		t1, t2 := L.typeNameOf(lhs), L.typeNameOf(rhs)
		if t1 == t2 {
			L.RaiseError("attempt to compare two %s values", t1)
		}
		L.RaiseError("attempt to compare %s with %s", t1, t2)
	}
	L.RaiseError("attempt to compare %v with %v", lhs.Type().String(), rhs.Type().String())
}

// lessEqual implements the generic path of the <= operator.
func lessEqual(L *LState, lhs, rhs LValue) bool {
	if res, ok := numLessEq(lhs, rhs); ok {
		return res
	}
	if s1, ok := lhs.(LString); ok {
		if s2, ok := rhs.(LString); ok {
			return strCmp(string(s1), string(s2)) <= 0
		}
	}
	if L.lang55 {
		op := L.metaOp2(lhs, rhs, "__le")
		if op.Type() == LTFunction {
			L.reg.Push(op)
			L.reg.Push(lhs)
			L.reg.Push(rhs)
			L.Call(2, 1)
			return LVAsBool(L.reg.Pop())
		}
		compareError(L, lhs, rhs)
		return false
	}
	if lhs.Type() != rhs.Type() || lhs.Type() == LTNumber {
		compareError(L, lhs, rhs)
	}
	switch objectRational(L, lhs, rhs, "__le") {
	case 1:
		return true
	case 0:
		return false
	}
	return !objectRationalWithError(L, rhs, lhs, "__lt")
}

/* numeric for loops {{{ */

// forError raises the error for an invalid for loop control value.
func forError(L *LState, what string, v LValue) {
	if L.lang55 {
		name := what
		if what == "init" {
			name = "initial value"
		}
		L.RaiseError("bad 'for' %s (number expected, got %s)", name, L.typeNameOf(v))
	}
	L.RaiseError("for statement %s must be a number", what)
}

// forLimit computes the integer limit of an integer for loop. skip is
// true if the loop must not run at all.
func forLimit(L *LState, init int64, limit LValue, step int64) (lim int64, skip bool) {
	switch l := limit.(type) {
	case LInteger:
		lim = int64(l)
	default:
		var f float64
		switch lf := limit.(type) {
		case LNumber:
			f = float64(lf)
		case LString:
			n, ok := L.strToNumber(string(lf))
			if !ok {
				forError(L, "limit", limit)
			}
			if i, isint := n.(LInteger); isint {
				return forLimit(L, init, i, step)
			}
			f = float64(n.(LNumber))
		default:
			forError(L, "limit", limit)
		}
		var ok bool
		if step < 0 {
			lim, ok = floatToIntegerCeil(f)
		} else {
			lim, ok = floatToIntegerFloor(f)
		}
		if !ok {
			// a float out of integer bounds (or NaN)
			if f > 0 {
				if step < 0 {
					return 0, true
				}
				lim = maxInteger
			} else {
				if step > 0 {
					return 0, true
				}
				lim = minInteger
			}
		}
	}
	if step > 0 {
		return lim, init > lim
	}
	return lim, init < lim
}

// forNumber coerces a for loop control value to a number value.
func forNumber(L *LState, what string, v LValue) LValue {
	switch n := v.(type) {
	case LNumber, LInteger:
		return v
	case LString:
		if L.lang55 {
			if num, ok := L.strToNumber(string(n)); ok {
				return num
			}
		}
	}
	forError(L, what, v)
	return nil
}

// forPrep prepares a numeric for loop whose control values are in the
// registers ra (initial value), ra+1 (limit) and ra+2 (step). It returns
// false if the loop body must be skipped. The generic path handles
// integer loops, mixed subtypes and coercions; the all-float fast path is
// inlined in the OP_FORPREP handler.
func forPrep(L *LState, ra int) bool {
	reg := L.reg
	// (an initial value or step given as a string makes it a float loop)
	if init, ok := reg.array[ra].(LInteger); ok {
		if step, ok := reg.array[ra+2].(LInteger); ok {
			if step == 0 {
				L.RaiseError("'for' step is zero")
			}
			limit, skip := forLimit(L, int64(init), reg.array[ra+1], int64(step))
			if skip {
				return false
			}
			reg.array[ra] = init
			reg.array[ra+1] = LInteger(limit)
			reg.array[ra+2] = step
			reg.Set(ra+3, init)
			return true
		}
	}
	// a float loop; invalid control values are reported in the order of
	// the respective reference implementation
	var initv, limitv, stepv LValue
	if L.lang55 {
		limitv = forNumber(L, "limit", reg.array[ra+1])
		stepv = forNumber(L, "step", reg.array[ra+2])
		initv = forNumber(L, "init", reg.array[ra])
	} else {
		initv = forNumber(L, "init", reg.array[ra])
		stepv = forNumber(L, "step", reg.array[ra+2])
		limitv = forNumber(L, "limit", reg.array[ra+1])
	}
	init, _ := toFloat(initv)
	limit, _ := toFloat(limitv)
	step, _ := toFloat(stepv)
	if L.lang55 {
		if step == 0 {
			L.RaiseError("'for' step is zero")
		}
		if (step > 0 && limit < init) || (step <= 0 && init < limit) {
			return false
		}
	} else {
		init = (init - step) + step
		if !((step > 0 && init <= limit) || (step <= 0 && init >= limit)) {
			return false
		}
	}
	reg.array[ra] = LNumber(init)
	reg.array[ra+1] = LNumber(limit)
	reg.array[ra+2] = LNumber(step)
	reg.Set(ra+3, LNumber(init))
	return true
}

// forLoopInt advances an integer for loop. It reports whether the loop
// continues and the new index.
func forLoopInt(idx, limit, step int64) (int64, bool) {
	if step > 0 {
		if uint64(limit)-uint64(idx) < uint64(step) {
			return idx, false
		}
	} else {
		if uint64(idx)-uint64(limit) < uint64(0)-uint64(step) {
			return idx, false
		}
	}
	return idx + step, true
}

/* }}} */

/* to-be-closed variables {{{ */

// tbcEntry is a pending to-be-closed variable of a thread.
type tbcEntry struct {
	idx int // registry index of the variable
	val LValue
}

// markTBC registers the value in registry index idx as to-be-closed.
func (ls *LState) markTBC(idx int, name string) {
	v := ls.reg.array[idx]
	if v == nil || v == LNil || v == LFalse {
		return
	}
	if ls.metaOp1(v, "__close") == LNil {
		ls.RaiseError("variable '%s' got a non-closable value", name)
	}
	ls.tbc = append(ls.tbc, tbcEntry{idx, v})
}

// closeTBC calls the __close metamethods of the pending to-be-closed
// variables with a registry index >= level, in reverse order.
func (ls *LState) closeTBC(level int, errObj LValue) {
	for n := len(ls.tbc); n > 0 && ls.tbc[n-1].idx >= level; n = len(ls.tbc) {
		entry := ls.tbc[n-1]
		ls.tbc = ls.tbc[:n-1]
		ls.callClose(entry.val, errObj)
	}
}

// callClose invokes the __close metamethod of v.
func (ls *LState) callClose(v LValue, errObj LValue) {
	op := ls.metaOp1(v, "__close")
	if op == LNil {
		ls.RaiseError("metamethod 'close' is not callable (a nil value)")
	}
	top := ls.reg.Top()
	ls.reg.Push(op)
	ls.reg.Push(v)
	ls.reg.Push(errObj)
	ls.Call(2, 0)
	ls.reg.SetTop(top)
}

// closeTBCOnError closes the pending to-be-closed variables at or above
// level while an error is being propagated. Errors raised by the close
// handlers replace the original error. It must be called after the call
// stack has been unwound to the protected call.
func (ls *LState) closeTBCOnError(level int, err *ApiError) *ApiError {
	// detach the entries first: the close handlers run in registry space
	// that the unwound frames used, so the stale indices must not be
	// mistaken for variables of the handler frames
	first := len(ls.tbc)
	for first > 0 && ls.tbc[first-1].idx >= level {
		first--
	}
	pending := append([]tbcEntry(nil), ls.tbc[first:]...)
	ls.tbc = ls.tbc[:first]
	for n := len(pending) - 1; n >= 0; n-- {
		entry := pending[n]
		op := ls.metaOp1(entry.val, "__close")
		if op == LNil {
			continue
		}
		ls.reg.Push(op)
		ls.reg.Push(entry.val)
		if err != nil && err.Object != nil {
			ls.reg.Push(err.Object)
		} else {
			ls.reg.Push(LNil)
		}
		if cerr := ls.PCall(2, 0, nil); cerr != nil {
			if aerr, ok := cerr.(*ApiError); ok {
				err = aerr
			} else {
				err = newApiErrorS(ApiErrorRun, cerr.Error())
			}
		}
	}
	return err
}

/* }}} */

// varargFromTable implements "..." in a function with a named vararg
// table: the values are read from the table, which the function may have
// modified. ra is the first destination register and b the B operand of
// OP_VARARG (number of wanted values + 1, or 0 for all).
func varargFromTable(L *LState, ra, b int, v LValue) {
	tb, ok := v.(*LTable)
	if !ok {
		L.RaiseError("vararg table has no proper 'n'")
	}
	n, ok := tb.RawGetString("n").(LInteger)
	if !ok || n < 0 || int64(n) > int64(L.reg.maxSize+len(L.reg.array)) {
		L.RaiseError("vararg table has no proper 'n'")
	}
	nwant := b - 1
	if b == 0 {
		nwant = int(n)
	}
	reg := L.reg
	reg.SetTop(ra + nwant)
	for i := 0; i < nwant; i++ {
		if i < int(n) {
			reg.array[ra+i] = tb.RawGetInt(i + 1)
		} else {
			reg.array[ra+i] = LNil
		}
	}
}

// varargTable builds the table of a Lua 5.5 named vararg parameter.
func varargTable(L *LState, cf *callFrame) *LTable {
	nparams := int(cf.Fn.Proto.NumParameters)
	nvarargs := cf.NArgs - nparams
	if nvarargs < 0 {
		nvarargs = 0
	}
	tb := L.newTable(nvarargs, 1)
	start := cf.Base + nparams + 1
	for i := 0; i < nvarargs; i++ {
		tb.RawSetInt(i+1, L.reg.array[start+i])
	}
	tb.RawSetString("n", L.newInt(int64(nvarargs)))
	return tb
}

// indexError raises the error for indexing a non-table value.
func (ls *LState) indexError(obj LValue, key string) {
	if ls.lang55 {
		ls.RaiseError("attempt to index a %s value (field '%s')", ls.typeNameOf(obj), key)
	}
	ls.RaiseError("attempt to index a non-table object(%v) with key '%s'", obj.Type().String(), key)
}

// callError raises the error for calling a non-callable value.
func (ls *LState) callError(v LValue) {
	if ls.lang55 && v != nil {
		ls.RaiseError("attempt to call a %s value", ls.typeNameOf(v))
	}
	ls.RaiseError("attempt to call a non-function object")
}

// callEq55 implements the Lua 5.3+ __eq metamethod lookup: the first
// operand's metamethod is tried first, then the second operand's.
func callEq55(L *LState, lhs, rhs LValue) bool {
	op := L.metaOp2(lhs, rhs, "__eq")
	if op.Type() != LTFunction {
		return false
	}
	L.reg.Push(op)
	L.reg.Push(lhs)
	L.reg.Push(rhs)
	L.Call(2, 1)
	return LVAsBool(L.reg.Pop())
}

// returnCloseTBC closes the to-be-closed variables of the frame that is
// about to return. The return values start at registry index ra; b is the
// B operand of OP_RETURN (number of values + 1, or 0 for "up to top").
func returnCloseTBC(L *LState, lbase, ra, b int) {
	if L.tbc[len(L.tbc)-1].idx < lbase {
		return
	}
	reg := L.reg
	if b > 0 && reg.top < ra+b-1 {
		reg.top = ra + b - 1
	}
	L.closeTBC(lbase, LNil)
}

// chainError raises the error for a metamethod chain that is too long.
func (ls *LState) chainError(event, legacy string) {
	if ls.lang55 {
		ls.RaiseError("'%s' chain too long; possible loop", event)
	}
	ls.RaiseError("%s", legacy)
}
