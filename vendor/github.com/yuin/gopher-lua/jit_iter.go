package lua

import (
	"reflect"

	"github.com/yuin/gopher-lua/internal/jit"
)

// This file translates generic for loops. The call of the iterator is a
// callout in general: the loop body is compiled, the interpreter fetches
// the next element. The iterator of ipairs over an array of numbers or
// booleans is translated completely.

// Code addresses of the ipairs iterators, by which they are recognized.
var (
	ipairsIter51 = reflect.ValueOf(ipairsaux).Pointer()
	ipairsIter55 = reflect.ValueOf(base55IpairsAux).Pointer()
)

// isIpairsIterator reports whether v is the iterator function of ipairs.
func isIpairsIterator(v LValue) bool {
	fn, ok := v.(*LFunction)
	if !ok || !fn.IsG || fn.GFunction == nil {
		return false
	}
	addr := reflect.ValueOf(fn.GFunction).Pointer()
	return addr == ipairsIter51 || addr == ipairsIter55
}

// genericFor translates the instruction that advances a generic for loop
// with the control values in R(a) (iterator), R(a+1) (state) and R(a+2)
// (control variable) and c loop variables from R(a+3+b) on.
func (fe *jitFrontend) genericFor(a, b, c int) {
	pc := fe.pc
	body, exit := fe.info.effects[pc].succs[0], pc+2
	if fe.ipairsStep(a, a+3+b, c, body, exit) {
		return
	}
	// the interpreter calls the iterator and reports whether the loop
	// is finished; it stored the loop variables and used the registers
	// behind them
	fe.calloutInst()
	for r := a + 2; r < fe.info.nslots; r++ {
		fe.st[r] = slotState{}
	}
	res := fe.loadMem(jit.MemNone, jit.OpLoad64, jit.TInt, fe.f.Ctx(), jit.CtxResult)
	fe.branch(fe.op(jit.OpNe, jit.TInt, res, fe.constInt(0)), exit, body)
}

// ipairsStep translates one step of ipairs over a table whose array part
// is unboxed: the next element exists if its index is below the length
// of the array part. It reports false if the loop is not such a loop.
func (fe *jitFrontend) ipairsStep(a, rv, nvars, body, exit int) bool {
	iterHome, ok := fe.homeSlot(a)
	if !ok || !isIpairsIterator(fe.peek(iterHome)) {
		return false
	}
	tableHome, ok := fe.homeSlot(a + 1)
	if !ok || valueKind(fe.peek(tableHome)) != vkTable {
		return false
	}
	akind := fe.arrayKindOf(tableHome)
	if fe.peek(tableHome).(*LTable).Metatable != LNil {
		return false
	}
	ctl, ck, ok := fe.num(a + 2)
	if !ok {
		return false
	}
	// the iterator must be the one seen now
	iter := fe.peek(iterHome)
	fe.constIndex(iter) // keeps it alive
	sameIter := fe.op(jit.OpEq, jit.TInt, fe.slotData(iterHome), fe.constInt(int64(uintptr(dataOf(iter)))))
	isFn := fe.op(jit.OpEq, jit.TInt, fe.slotItab(iterHome), fe.constInt(int64(itabFunc)))
	fe.guard(fe.op(jit.OpAnd, jit.TInt, sameIter, isFn), -1, 0)
	tp, _, _ := fe.tableOf(a + 1)
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.load(jit.OpLoad8, jit.TInt, tp, int64(offTableAkind)), fe.constInt(int64(akind))), tableHome, fbArray)
	mt := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable))
	fe.guard(fe.op(jit.OpEq, jit.TInt, mt, fe.constInt(int64(itabNil))), -1, 0)

	// the control variable counts the elements visited so far, which is
	// the position of the next one in the array part
	idx := ctl
	if ck == skFloat {
		idx = fe.floatExactInt(ctl, ck)
	}
	off, shift := int64(offTableIarr), int64(3)
	switch akind {
	case arrayKindFloat:
		off = int64(offTableFarr)
	case arrayKindGeneric:
		off, shift = int64(offTableArray), 4
	}
	data := fe.load(jit.OpLoad64, jit.TInt, tp, off+sliceOffData)
	n := fe.loadMem(jit.MemArrayLen, jit.OpLoad64, jit.TInt, tp, off+sliceOffLen)
	more, done := fe.split(fe.op(jit.OpULt, jit.TInt, idx, n))
	addr := fe.f.NewValue(more, jit.OpAdd, jit.TInt, 0, data, fe.f.NewValue(more, jit.OpShl, jit.TInt, 0, idx, fe.f.ConstInt(more, shift)))
	if akind == arrayKindGeneric {
		// a generic array part can hold nil, which ends the loop as well
		itab := fe.f.NewValue(more, jit.OpLoad64, jit.TInt, 0, addr)
		isNil := fe.f.NewValue(more, jit.OpEq, jit.TInt, 0, itab, fe.f.ConstInt(more, int64(itabNil)))
		hole, elem := fe.f.NewBlock(), fe.f.NewBlock()
		more.Kind = jit.BlockIf
		more.Control = isNil
		jit.AddEdge(more, hole)
		jit.AddEdge(more, elem)
		jumpIR(hole, done)
		more = elem
	}

	// finished: the iterator returns nil and nothing changes
	saved := cloneState(fe.st)
	fe.cur = done
	fe.connect(fe.cur, exit, fe.st)

	fe.cur, fe.st = more, saved
	next := fe.op(jit.OpAdd, jit.TInt, idx, fe.constInt(1))
	nk, nv := skInt, next
	if !fe.L.lang55 {
		nk, nv = skFloat, fe.op(jit.OpIntToFloat, jit.TFloat, next)
	}
	fe.set(a+2, nk, nv)
	fe.set(rv, nk, nv)
	if nvars > 1 {
		switch akind {
		case arrayKindGeneric:
			fe.st[rv+1] = slotState{kind: skRef, val: addr, src: int32(rv + 1)}
			if sample := firstElement(fe.peek(tableHome)); sample != nil {
				fe.refPeek[int32(rv+1)] = sample
			}
		case arrayKindInt:
			fe.set(rv+1, skInt, fe.loadMem(jit.MemArray, jit.OpLoad64, jit.TInt, addr, 0))
		case arrayKindBool:
			fe.set(rv+1, skBool, fe.loadMem(jit.MemArray, jit.OpLoad64, jit.TInt, addr, 0))
		default:
			fe.set(rv+1, skFloat, fe.loadMem(jit.MemArray, jit.OpLoadF64, jit.TFloat, addr, 0))
		}
	}
	for r := rv + 2; r < rv+nvars; r++ {
		fe.st[r] = slotState{kind: skNil}
	}
	fe.connect(fe.cur, body, fe.st)
	return true
}
