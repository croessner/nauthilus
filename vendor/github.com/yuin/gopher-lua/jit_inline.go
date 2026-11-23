package lua

import (
	"unsafe"

	"github.com/yuin/gopher-lua/internal/jit"
)

// This file contains the inlining of Lua function calls: inside a
// compiled loop the code of a small callee is translated in place of the
// call. No frame is pushed and arguments and results stay in machine
// registers. The callee's registers are the slots behind the function
// value, exactly where its frame would be, so that an exit inside the
// callee only has to create the frame (see jitEnterInlined) for the
// interpreter to continue there.
//
// Only functions made of simple instructions and forward branches are
// inlined; a callee with loops, varargs or instructions that need the
// interpreter is called through the interpreter as before.

// relocateInst adds delta to the register operands of an instruction
// that inlinableProto accepts. It reports false if a register does not
// fit into its operand.
func relocateInst(inst uint32, delta int) (uint32, bool) {
	ok := true
	reg := func(r int) int {
		r += delta
		if r > opMaxArgsA {
			ok = false
		}
		return r
	}
	rk := func(v int) int {
		if v&opBitRk != 0 {
			return v
		}
		return reg(v)
	}
	a, b, c := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	switch opGetOpCode(inst) {
	case OP_JMP:
	case OP_EQ, OP_LT, OP_LE:
		opSetArgB(&inst, rk(b))
		opSetArgC(&inst, rk(c))
	case OP_TESTSET:
		opSetArgA(&inst, reg(a))
		opSetArgB(&inst, reg(b))
	case OP_LOADK, OP_LOADBOOL, OP_GETUPVAL, OP_GETGLOBAL, OP_CALL, OP_TAILCALL, OP_RETURN, OP_TEST:
		opSetArgA(&inst, reg(a))
	case OP_MOVE, OP_MOVEN, OP_LOADNIL, OP_UNM, OP_NOT, OP_LEN, OP_BNOT:
		opSetArgA(&inst, reg(a))
		opSetArgB(&inst, reg(b))
	case OP_GETTABLE, OP_GETTABLEKS, OP_SELF:
		opSetArgA(&inst, reg(a))
		if opGetOpCode(inst) == OP_SELF {
			reg(a + 1) // the object goes into the register behind the method
		}
		opSetArgB(&inst, reg(b))
		opSetArgC(&inst, rk(c))
	case OP_SETTABLE, OP_SETTABLEKS,
		OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW, OP_IDIV, OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR:
		opSetArgA(&inst, reg(a))
		opSetArgB(&inst, rk(b))
		opSetArgC(&inst, rk(c))
	default:
		ok = false
	}
	return inst, ok
}

// inlinableProto reports whether a function can be translated in place of
// a call: it is short, has a fixed number of parameters, only jumps
// forward and consists of instructions that relocateInst knows.
func inlinableProto(proto *FunctionProto) bool {
	if proto.IsVarArg != 0 || len(proto.Code) > jitMaxInlineInsts {
		return false
	}
	for pc, inst := range proto.Code {
		b, c := opGetArgB(inst), opGetArgC(inst)
		switch opGetOpCode(inst) {
		case OP_TAILCALL:
			if b == 0 {
				return false
			}
		case OP_RETURN:
			// (a tail call is followed by a return of all its results
			// that is never executed)
			if b == 0 && (pc == 0 || opGetOpCode(proto.Code[pc-1]) != OP_TAILCALL) {
				return false
			}
		case OP_CALL:
			if b == 0 || c == 0 {
				return false
			}
		case OP_JMP:
			if target := pc + 1 + opGetArgSbx(inst); target <= pc || target >= len(proto.Code) {
				return false
			}
		case OP_MOVE, OP_MOVEN, OP_LOADK, OP_LOADBOOL, OP_LOADNIL, OP_GETUPVAL, OP_GETGLOBAL,
			OP_GETTABLE, OP_GETTABLEKS, OP_SETTABLE, OP_SETTABLEKS, OP_SELF,
			OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW, OP_IDIV, OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR,
			OP_UNM, OP_NOT, OP_LEN, OP_BNOT, OP_EQ, OP_LT, OP_LE, OP_TEST, OP_TESTSET:
		default:
			return false
		}
	}
	return true
}

// mergeSlot combines the states a register has on the paths that meet at
// a join. It reports whether the states are compatible; phi is true if
// the merged state needs a phi over the values of the paths.
func mergeSlot(states []slotState) (merged slotState, phi, ok bool) {
	first := states[0]
	same, clean, kind := true, true, true
	for i := range states {
		s := &states[i]
		if *s != first {
			same = false
		}
		if s.stale() {
			clean = false
		}
		if s.kind != first.kind {
			kind = false
		}
	}
	switch {
	case same:
		return first, false, true
	case clean:
		// the home slot is current on every path
		return slotState{}, false, true
	case kind && (first.kind == skInt || first.kind == skFloat || first.kind == skBool):
		return slotState{kind: first.kind, dirty: true}, true, true
	}
	return slotState{}, false, false
}

// joinInline joins the paths in edges in a new block and merges their
// register states. Only the slots for which needed reports true have to
// be compatible; the others are dropped. It reports false if the paths
// cannot be joined.
func (fe *jitFrontend) joinInline(edges []feEdge, needed func(slot int) bool) bool {
	if len(edges) == 1 {
		fe.cur, fe.st = edges[0].from, edges[0].st
		return true
	}
	join := fe.f.NewBlock()
	for _, e := range edges {
		jumpIR(e.from, join)
	}
	st := cloneState(edges[0].st)
	states := make([]slotState, len(edges))
	for slot := range st {
		for i, e := range edges {
			states[i] = e.st[slot]
		}
		merged, phi, ok := mergeSlot(states)
		switch {
		case !ok && needed(slot):
			return false
		case !ok:
			merged = slotState{}
		case phi:
			typ := jit.TInt
			if merged.kind == skFloat {
				typ = jit.TFloat
			}
			merged.val = fe.f.NewPhi(join, typ)
			for i := range states {
				merged.val.Args = append(merged.val.Args, states[i].val)
			}
		}
		st[slot] = merged
	}
	fe.cur, fe.st = join, st
	return true
}

// functionAt returns the function in register a if the code can treat
// it as a constant: it is one already (a global or upvalue function) or
// the register holds it boxed. home is the location whose identity has
// to be guarded in the second case, else -1.
func (fe *jitFrontend) functionAt(a int) (fn *LFunction, home int) {
	home = -1
	if s := &fe.st[a]; s.kind == skConst {
		fn, _ = fe.consts[s.src].(*LFunction)
	} else if h, ok := fe.homeSlot(a); ok {
		fn, _ = fe.peek(h).(*LFunction)
		home = h
	}
	if fn == nil {
		return nil, -1
	}
	return fn, home
}

// calleeAt is functionAt for Lua functions.
func (fe *jitFrontend) calleeAt(a int) (fn *LFunction, home int) {
	fn, home = fe.functionAt(a)
	if fn == nil || fn.IsG || fn.Proto == nil {
		return nil, -1
	}
	return fn, home
}

// guardCallee makes the code depend on the identity of the function in
// the slot home. A failure counts against inlining at the call site.
func (fe *jitFrontend) guardCallee(fn *LFunction, home int, site feedbackKey) {
	same := fe.op(jit.OpEq, jit.TInt, fe.slotData(home), fe.constInt(int64(uintptr(unsafe.Pointer(fn)))))
	isFn := fe.op(jit.OpEq, jit.TInt, fe.slotItab(home), fe.constInt(int64(itabFunc)))
	x := fe.newExit(jit.ExitDeopt, fe.pc, exitMeta{kind: emDeopt, fbSlot: site.slot, fbWhat: fbInline})
	x.Snap = fe.snapshot(fe.cur, fe.st, fe.pc, nil)
	fe.f.NewValue(fe.cur, jit.OpGuard, jit.TInt, 0, fe.op(jit.OpAnd, jit.TInt, same, isFn)).Exit = x
}

// inlineCall translates the call R(a)(R(a+1), ..., R(a+b-1)) with c-1
// results by translating the callee in place. done is false if the call
// is not inlined (nothing was emitted that changes the state); ended is
// true if the current block ended inside the callee or the translation
// has to start over.
func (fe *jitFrontend) inlineCall(a, b, c int) (done, ended bool) {
	return fe.inlineCallAs(a, b, c, false)
}

// inlineCallAs is inlineCall for an ordinary call or, with tail set, for
// the tail call that ends an inlined callee. c is the number of results
// wanted plus one; zero asks for all results, whose end is then recorded
// like for any other open result list.
func (fe *jitFrontend) inlineCallAs(a, b, c int, tail bool) (done, ended bool) {
	site := feedbackKey{fe.fbpc(), int16(a), fbInline}
	if b == 0 || fe.jp.feedback[site] >= jitFieldMisses {
		return false, false
	}
	// nothing is emitted before the call is known to be inlined
	fn, home := fe.calleeAt(a)
	if fn == nil {
		return false, false
	}
	proto := fn.Proto
	if !inlinableProto(proto) || proto.Version != fe.proto.Version {
		return false, false
	}
	depth := 0
	for i := fe.inl; i != 0; i = fe.inlined[i-1].parent {
		depth++
		if fe.inlined[i-1].callee.Proto == proto {
			return false, false
		}
	}
	if depth >= jitMaxInlineDepth || proto == fe.jp.proto {
		return false, false
	}
	base := a + 1
	need := base + proto.analysis().nslots
	for _, inst := range proto.Code {
		if _, ok := relocateInst(inst, base); !ok {
			return false, false
		}
	}
	if need > jitMaxSlots || need > cap(fe.frame) {
		return false, false
	}
	if need > fe.nslots {
		// the unit needs more slots: translate again with a larger window
		fe.nslots = need
		fe.frame = fe.frame[:need]
		fe.restart = true
		return true, true
	}
	if home >= 0 {
		fe.guardCallee(fn, home, site)
	}

	// the frame of the callee: missing arguments are nil, everything
	// behind the parameters is unset
	nargs, nret, np := b-1, c-1, int(proto.NumParameters)
	for i := nargs; i < np; i++ {
		fe.st[base+i] = slotState{kind: skNil}
	}
	for s := base + intMax(nargs, np); s < need; s++ {
		fe.st[s] = slotState{}
	}
	call := inlineCall{callee: fn, callPC: fe.pc, ra: a, nargs: nargs, nret: nret, tail: tail, parent: fe.inl, site: site}
	if fe.inl != 0 {
		call.live = fe.inlined[fe.inl-1].live
	} else {
		call.live = fe.info.liveIn[fe.pc+1]
		for r := a; r < a+nret; r++ {
			call.live.del(r)
		}
	}
	for s := base; s < need; s++ {
		call.live.add(s)
	}
	fe.inlined = append(fe.inlined, call)

	// translate the callee in its own scope
	saved := *fe
	fe.inl = len(fe.inlined)
	fe.scope, fe.proto, fe.slotBase = fn, proto, base
	fe.fbBase = (saved.fbBase*31+int32(saved.pc)+1)<<8&0x3fffff00 | 1<<30
	fe.env = functionEnv(fn)
	fe.pendingTop, fe.openTop = -1, -1
	fe.edges = make(map[int][]feEdge)
	nres, ok := fe.inlineBody(a, c, need)
	fe.inl, fe.scope, fe.proto, fe.slotBase = saved.inl, saved.scope, saved.proto, saved.slotBase
	fe.fbBase, fe.env, fe.pc, fe.edges = saved.fbBase, saved.env, saved.pc, saved.edges
	fe.pendingTop, fe.openTop = -1, -1
	switch {
	case fe.restart:
		return true, true
	case !ok:
		// the paths of the callee cannot be joined: translate again
		// without inlining this call
		fe.jp.feedback[site] = jitFieldMisses
		fe.restart = true
		return true, true
	case nres < 0:
		return true, true // every path leaves native code
	}
	if c == 0 {
		fe.openTop = a + nres
	}
	for s := a + nres; s < need; s++ {
		fe.st[s] = slotState{}
	}
	return true, false
}

// inlineBody translates the instructions of the callee of an inlined
// call whose function value is in slot a. Control flow inside the callee
// only goes forward, so its instructions are translated in order; paths
// that meet are joined, and so are the paths that return. The results
// end up in the slots from a on. It returns their number (-1 if no path
// returns to the caller) and false if paths could not be joined.
func (fe *jitFrontend) inlineBody(a, c, need int) (nres int, ok bool) {
	proto, base := fe.proto, fe.slotBase
	info := proto.analysis()
	var returns []feEdge
	nres = -1
	reachable := true
	for pc := 0; pc < len(proto.Code); pc++ {
		if incoming := fe.edges[pc]; len(incoming) > 0 {
			if reachable {
				incoming = append(incoming, feEdge{fe.cur, cloneState(fe.st)})
			}
			delete(fe.edges, pc)
			live := &info.liveIn[pc]
			if !fe.joinInline(incoming, func(slot int) bool { return slot < base || live.has(slot-base) }) {
				return 0, false
			}
			reachable = true
		}
		if !reachable {
			continue
		}
		fe.pc = pc
		inst := fe.code(pc)
		op := opGetOpCode(inst)
		if op != OP_RETURN && op != OP_TAILCALL {
			if _, ended := fe.inst(pc); ended {
				reachable = false
			}
			if fe.restart {
				return 0, true
			}
			continue
		}
		// the path returns n values from register from, directly or
		// through a tail call that is translated in place as well
		from, n := opGetArgA(inst), opGetArgB(inst)-1
		if n < 0 {
			return 0, false // an open return that a jump reaches after all
		}
		if op == OP_TAILCALL {
			done, ended := fe.inlineCallAs(from, opGetArgB(inst), c, true)
			if !done {
				// the interpreter takes over at the tail call
				fe.unsupported()
				ended = true
			}
			if fe.restart {
				return 0, true
			}
			if ended {
				reachable = false
				continue
			}
			n = c - 1
			if c == 0 {
				n = fe.openTop - from
			}
		}
		// the results move down into the registers of the call; values
		// the callee did not return are nil
		want := c - 1
		if c == 0 {
			want = n
		}
		if nres >= 0 && nres != want {
			return 0, false // paths return different numbers of values
		}
		nres = want
		for i := 0; i < want; i++ {
			if i < n {
				fe.move(a+i, from+i)
			} else {
				fe.st[a+i] = slotState{kind: skNil}
			}
		}
		returns = append(returns, feEdge{fe.cur, cloneState(fe.st)})
		reachable = false
	}
	if len(returns) == 0 {
		return -1, true
	}
	// behind the call only the results and the caller's registers count
	if !fe.joinInline(returns, func(slot int) bool { return slot < a+nres }) {
		return 0, false
	}
	return nres, true
}

// jitEnterInlined creates the frames of the inlined calls an exit lies
// in, outermost first, and makes the innermost one the current frame at
// position pc. cf is the frame of the compiled function and base its
// register base; the registers of the callees were written back already.
func (ls *LState) jitEnterInlined(u *jitUnit, inl int, cf *callFrame, base, pc int) {
	var chain [jitMaxInlineDepth + 1]int
	n := 0
	for i := inl; i != 0; i = u.inlined[i-1].parent {
		chain[n] = i
		n++
	}
	frame := cf
	// a tail call returns for the function it replaces: retBase and nret
	// carry that function's return information to the frame that stays
	retBase, nret := 0, 0
	for k := n - 1; k >= 0; k-- {
		call := &u.inlined[chain[k]-1]
		ra := base + call.ra
		rb, nr, tailCall := ra, call.nret, 0
		if call.tail {
			rb, nr, tailCall = retBase, nret, 1
		} else {
			frame.Pc = call.callPC + 1
		}
		if k > 0 && u.inlined[chain[k-1]-1].tail {
			retBase, nret = rb, nr
			continue
		}
		if ls.stack.IsFull() {
			ls.RaiseError("stack overflow")
		}
		ls.stack.Push(callFrame{
			Fn: call.callee, Base: ra, LocalBase: ra + 1, ReturnBase: rb,
			NArgs: call.nargs, NRet: nr, Parent: frame, TailCall: tailCall,
		})
		frame = ls.stack.Last()
	}
	frame.Pc = pc
	ls.currentFrame = frame
	if top := frame.LocalBase + int(frame.Fn.Proto.NumUsedRegisters); ls.reg.top < top {
		ls.reg.SetTop(top)
	}
}
