package lua

import (
	"unsafe"

	"github.com/yuin/gopher-lua/internal/jit"
)

// This file translates method lookups (obj:name(...)) for the usual
// class pattern: the object is a table, the method is a function that
// the object holds itself or that is found through the chain of __index
// tables of its metatable. The function becomes a constant of the code,
// so that the call that follows can be inlined.

// keyMatches returns the condition that the entry at displacement disp
// of the entries at data has exactly the key k (address and length).
func (fe *jitFrontend) keyMatches(data *jit.Value, disp int64, k string) *jit.Value {
	fe.constIndex(LString(k)) // keeps the bytes of the key alive
	addr := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldKey))
	n := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldKey)+8)
	same := fe.op(jit.OpEq, jit.TInt, addr, fe.constInt(int64(uintptr(unsafe.Pointer(unsafe.StringData(k))))))
	return fe.op(jit.OpAnd, jit.TInt, same, fe.op(jit.OpEq, jit.TInt, n, fe.constInt(int64(len(k)))))
}

// classMethod finds the function a method name resolves to through the
// metatable mt of an object: mt.__index must be a table that holds the
// function or leads to it through its own metatable. It returns the
// tables the result depends on, starting with mt.
func classMethod(mt *LTable, name string) (fn *LFunction, chain []*LTable) {
	chain = append(chain, mt)
	for depth := 0; depth < jitMaxClassDepth; depth++ {
		class, ok := mt.RawGetString("__index").(*LTable)
		if !ok {
			return nil, nil
		}
		chain = append(chain, class)
		switch v := class.RawGetString(name).(type) {
		case *LFunction:
			return v, chain
		case *LNilType:
		default:
			return nil, nil
		}
		if mt, ok = class.Metatable.(*LTable); !ok {
			return nil, nil
		}
		chain = append(chain, mt)
	}
	return nil, nil
}

// guardMetatable makes the code depend on the metatable of the constant
// table tb being what it is now.
func (fe *jitFrontend) guardMetatable(tb *LTable) {
	addr := fe.constInt(int64(uintptr(unsafe.Pointer(&tb.Metatable))))
	itab := fe.load(jit.OpLoad64, jit.TInt, addr, 0)
	data := fe.load(jit.OpLoad64, jit.TInt, addr, 8)
	same := fe.op(jit.OpEq, jit.TInt, itab, fe.constInt(int64(itabOf(tb.Metatable))))
	same = fe.op(jit.OpAnd, jit.TInt, same, fe.op(jit.OpEq, jit.TInt, data, fe.constInt(int64(uintptr(dataOf(tb.Metatable))))))
	fe.guard(same, -1, 0)
}

// selfMethod translates R(a+1) := R(b); R(a) := R(b)[K(c)] for a method
// that is a known function.
func (fe *jitFrontend) selfMethod(a, b, c int) bool {
	if c&opBitRk == 0 {
		return false
	}
	name := fe.proto.stringConstants[c&^opBitRk]
	home, ok := fe.homeSlot(b)
	if !ok {
		return false
	}
	if _, isString := fe.peek(home).(LString); isString {
		return fe.stringMethod(a, b, home, name)
	}
	obj, isTable := fe.peek(home).(*LTable)
	site := feedbackKey{fe.fbpc(), int16(locSlot(home)), fbField}
	if !isTable || fe.jp.feedback[site] >= jitFieldMisses {
		return false
	}
	var fn *LFunction
	own := obj.findField(name)
	var chain []*LTable
	switch {
	case own >= jitMaxFieldIndex:
		return false
	case own >= 0:
		// a function the object holds itself
		if fn, _ = obj.fields[own].value.(*LFunction); fn == nil || obj.fields[own].kind != fieldBoxed {
			return false
		}
	default:
		mt, hasMT := obj.Metatable.(*LTable)
		if !hasMT || len(obj.fields) > jitMaxShapeFields || obj.fieldIndex != nil {
			return false
		}
		if fn, chain = classMethod(mt, name); fn == nil {
			return false
		}
	}

	tp, _, _ := fe.tableOf(b)
	data := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableFields)+sliceOffData)
	n := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableFields)+sliceOffLen)
	if own >= 0 {
		// the entry is where it was, has that key and holds the function
		disp := int64(own) * int64(fieldSize)
		fe.guard(fe.op(jit.OpULt, jit.TInt, fe.constInt(int64(own)), n), home, fbField)
		ok := fe.keyMatches(data, disp, obj.fields[own].key)
		kind := fe.loadMem(jit.MemField, jit.OpLoad8, jit.TInt, data, disp+int64(offFieldKind))
		ok = fe.op(jit.OpAnd, jit.TInt, ok, fe.op(jit.OpEq, jit.TInt, kind, fe.constInt(int64(fieldBoxed))))
		itab := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldValue))
		val := fe.load(jit.OpLoad64, jit.TInt, data, disp+int64(offFieldValue)+8)
		ok = fe.op(jit.OpAnd, jit.TInt, ok, fe.op(jit.OpEq, jit.TInt, itab, fe.constInt(int64(itabFunc))))
		ok = fe.op(jit.OpAnd, jit.TInt, ok, fe.op(jit.OpEq, jit.TInt, val, fe.constInt(int64(uintptr(unsafe.Pointer(fn))))))
		fe.guard(ok, home, fbField)
	} else {
		// The object has exactly the string keys it has now, none of
		// which is the method name, and the metatable it has now. The
		// tables behind the metatable are constants of the code: their
		// version changes when an entry that is a function or table is
		// replaced or a key is added, and their metatables are checked.
		ok := fe.op(jit.OpEq, jit.TInt, n, fe.constInt(int64(len(obj.fields))))
		fe.guard(ok, home, fbField)
		ok = nil
		for i := range obj.fields {
			m := fe.keyMatches(data, int64(i)*int64(fieldSize), obj.fields[i].key)
			if ok == nil {
				ok = m
			} else {
				ok = fe.op(jit.OpAnd, jit.TInt, ok, m)
			}
		}
		mtItab := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable))
		mtData := fe.load(jit.OpLoad64, jit.TInt, tp, int64(offTableMetatable)+8)
		m := fe.op(jit.OpAnd, jit.TInt,
			fe.op(jit.OpEq, jit.TInt, mtItab, fe.constInt(int64(itabTable))),
			fe.op(jit.OpEq, jit.TInt, mtData, fe.constInt(int64(uintptr(unsafe.Pointer(chain[0]))))))
		if ok == nil {
			ok = m
		} else {
			ok = fe.op(jit.OpAnd, jit.TInt, ok, m)
		}
		fe.guard(ok, home, fbField)
		for i, tb := range chain {
			tb.watchedKeys = true
			fe.guardVersion(tb)
			if i > 0 {
				fe.guardMetatable(tb)
			}
		}
	}
	fe.move(a+1, b)
	fe.st[a] = slotState{kind: skConst, src: fe.constIndex(fn)}
	return true
}

// stringMethod translates R(a+1) := R(b); R(a) := R(b)[name] for a string
// in R(b): the method is the function that the __index table of the
// metatable of strings holds under that name. The code depends on the
// metatable of strings not being replaced and on the two tables keeping
// their functions.
func (fe *jitFrontend) stringMethod(a, b, home int, name string) bool {
	g := fe.L.G
	mt, _ := g.builtinMts[int(LTString)].(*LTable)
	if mt == nil {
		return false
	}
	index, _ := mt.RawGetString("__index").(*LTable)
	if index == nil {
		return false
	}
	fn, _ := index.RawGetString(name).(*LFunction)
	if fn == nil {
		return false
	}
	fe.guard(fe.op(jit.OpEq, jit.TInt, fe.slotItab(home), fe.constInt(int64(itabString))), home, fbValue)
	gen := fe.load(jit.OpLoad64, jit.TInt, fe.constInt(int64(uintptr(unsafe.Pointer(&g.builtinMtGen)))), 0)
	fe.guard(fe.op(jit.OpEq, jit.TInt, gen, fe.constInt(int64(g.builtinMtGen))), -1, 0)
	mt.watchedKeys = true
	fe.guardVersion(mt)
	if index != mt {
		index.watchedKeys = true
		fe.guardVersion(index)
	}
	fe.move(a+1, b)
	fe.st[a] = slotState{kind: skConst, src: fe.constIndex(fn)}
	return true
}
