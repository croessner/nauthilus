package lua

import "sync"

// This file contains the bytecode analysis used by the JIT compiler:
// instruction effects, control flow and register liveness. The results
// depend only on the bytecode, so they are computed once per prototype
// and shared between states.

// regSet is a set of bytecode registers (0..255).
type regSet [4]uint64

func (s *regSet) add(r int) {
	if r >= 0 && r < 256 {
		s[r>>6] |= 1 << (uint(r) & 63)
	}
}

func (s *regSet) del(r int) {
	if r >= 0 && r < 256 {
		s[r>>6] &^= 1 << (uint(r) & 63)
	}
}

func (s *regSet) has(r int) bool {
	return r >= 0 && r < 256 && s[r>>6]&(1<<(uint(r)&63)) != 0
}

// addFrom adds every register >= r.
func (s *regSet) addFrom(r int) {
	for ; r < 256; r++ {
		s.add(r)
	}
}

func (s *regSet) union(o *regSet) bool {
	changed := false
	for i := range s {
		if n := s[i] | o[i]; n != s[i] {
			s[i] = n
			changed = true
		}
	}
	return changed
}

// bcEffect describes what a bytecode instruction does to registers and
// where control continues.
type bcEffect struct {
	reads  regSet
	writes regSet // registers that are definitely overwritten
	succs  [2]int // successor pcs; -1 if unused
	nsucc  int
}

// jitProtoCache holds the lazily computed bytecode analysis of a
// prototype.
type jitProtoCache struct {
	once sync.Once
	info *bcInfo
}

// bcInfo is the immutable analysis result of a prototype.
type bcInfo struct {
	effects []bcEffect
	// liveIn[pc] is the set of registers whose value may be read before
	// being overwritten when execution continues at pc.
	liveIn []regSet
	// leader[pc] is true if pc starts a basic block.
	leader []bool
	// preds[pc] is the number of control flow predecessors of a leader.
	preds []int32
	// escaped is the set of registers captured as upvalues by closures
	// created in this function.
	escaped regSet
	// data[pc] is true for words that are not executable instructions
	// (closure upvalue descriptors and SETLIST extra arguments).
	data []bool
	// nslots is the number of registers the function may touch. It can
	// exceed FunctionProto.NumUsedRegisters, which does not account for
	// the registers implied by loop and call instructions.
	nslots int
}

// maxRegister returns the highest register index referenced by the
// instruction at pc.
func maxRegister(fp *FunctionProto, pc int, e *bcEffect) int {
	inst := fp.Code[pc]
	a, b, c := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	m := -1
	for r := 255; r >= 0; r-- {
		if e.reads.has(r) || e.writes.has(r) {
			m = r
			break
		}
	}
	switch opGetOpCode(inst) {
	case OP_FORPREP, OP_FORLOOP:
		m = intMax(m, a+3)
	case OP_TFORLOOP:
		m = intMax(m, a+3+b+intMax(c, 3))
	case OP_CALL:
		// open argument and result lists are bounded by the registry top
		if b == 0 || c == 0 {
			m = intMax(m, a)
		}
		m = intMax(m, a+c-2)
	case OP_TAILCALL, OP_RETURN, OP_SETLIST, OP_VARARG:
		if b == 0 {
			m = intMax(m, a)
		} else {
			m = intMax(m, a+b-1)
		}
	case OP_TESTSET, OP_SELF:
		m = intMax(m, a+1)
	}
	return m
}

// analysis returns the bytecode analysis of the prototype.
func (fp *FunctionProto) analysis() *bcInfo {
	fp.jit.once.Do(func() { fp.jit.info = analyzeBytecode(fp) })
	return fp.jit.info
}

// addRK adds a register-or-constant operand to a read set.
func addRK(s *regSet, rk int) {
	if rk&opBitRk == 0 {
		s.add(rk)
	}
}

// instEffect computes the effect of the instruction at pc.
func instEffect(fp *FunctionProto, pc int) (bcEffect, int) {
	code := fp.Code
	inst := code[pc]
	op := opGetOpCode(inst)
	A, B, C := opGetArgA(inst), opGetArgB(inst), opGetArgC(inst)
	e := bcEffect{succs: [2]int{pc + 1, -1}, nsucc: 1}
	skip := 0 // number of data words following the instruction
	switch op {
	case OP_MOVE, OP_MOVEN:
		e.reads.add(B)
		e.writes.add(A)
	case OP_LOADK, OP_GETUPVAL, OP_GETGLOBAL, OP_GETENV, OP_NEWTABLE, OP_VARARGTAB:
		e.writes.add(A)
	case OP_LOADBOOL:
		e.writes.add(A)
		if C != 0 {
			e.succs[0] = pc + 2
		}
	case OP_LOADNIL:
		for r := A; r <= B; r++ {
			e.writes.add(r)
		}
	case OP_GETTABLE, OP_GETTABLEKS:
		e.reads.add(B)
		addRK(&e.reads, C)
		e.writes.add(A)
	case OP_SETGLOBAL, OP_SETUPVAL, OP_SETENV, OP_TBC, OP_ERRNNIL:
		e.reads.add(A)
	case OP_SETTABLE, OP_SETTABLEKS:
		e.reads.add(A)
		addRK(&e.reads, B)
		addRK(&e.reads, C)
	case OP_SELF:
		e.reads.add(B)
		addRK(&e.reads, C)
		e.writes.add(A)
		e.writes.add(A + 1)
	case OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW, OP_IDIV, OP_BAND, OP_BOR, OP_BXOR, OP_SHL, OP_SHR:
		addRK(&e.reads, B)
		addRK(&e.reads, C)
		e.writes.add(A)
	case OP_UNM, OP_NOT, OP_LEN, OP_BNOT:
		addRK(&e.reads, B)
		e.writes.add(A)
	case OP_CONCAT:
		for r := B; r <= C; r++ {
			e.reads.add(r)
		}
		e.writes.add(A)
	case OP_JMP:
		e.succs[0] = pc + 1 + opGetArgSbx(inst)
	case OP_EQ, OP_LT, OP_LE:
		addRK(&e.reads, B)
		addRK(&e.reads, C)
		e.succs[1] = pc + 2
		e.nsucc = 2
	case OP_TEST:
		e.reads.add(A)
		e.succs[1] = pc + 2
		e.nsucc = 2
	case OP_TESTSET:
		e.reads.add(B)
		// R(A) is only written on one path: do not treat it as a kill
		e.succs[1] = pc + 2
		e.nsucc = 2
	case OP_CALL:
		if B == 0 {
			e.reads.addFrom(A)
		} else {
			for r := A; r < A+B; r++ {
				e.reads.add(r)
			}
		}
		for r := A; r <= A+C-2; r++ {
			e.writes.add(r)
		}
	case OP_TAILCALL:
		if B == 0 {
			e.reads.addFrom(A)
		} else {
			for r := A; r < A+B; r++ {
				e.reads.add(r)
			}
		}
	case OP_RETURN:
		if B == 0 {
			e.reads.addFrom(A)
		} else {
			for r := A; r <= A+B-2; r++ {
				e.reads.add(r)
			}
		}
		e.nsucc = 0
		e.succs[0] = -1
	case OP_FORPREP:
		e.reads.add(A)
		e.reads.add(A + 1)
		e.reads.add(A + 2)
		// R(A+3) is only written when the loop runs
		e.succs[1] = pc + 1 + opGetArgSbx(inst)
		e.nsucc = 2
	case OP_FORLOOP:
		e.reads.add(A)
		e.reads.add(A + 1)
		e.reads.add(A + 2)
		e.succs[0] = pc + 1 + opGetArgSbx(inst)
		e.succs[1] = pc + 1
		e.nsucc = 2
	case OP_TFORLOOP:
		e.reads.add(A)
		e.reads.add(A + 1)
		e.reads.add(A + 2)
		// the loop variables receive the results of the iterator (nil
		// when the loop ends); B selects the layout with a closing value
		for r := A + 3 + B; r < A+3+B+C; r++ {
			e.writes.add(r)
		}
		// the instruction is followed by a JMP back to the loop body that
		// is taken when the iterator returned a value
		e.succs[0] = pc + 2 + opGetArgSbx(code[pc+1])
		e.succs[1] = pc + 2
		e.nsucc = 2
	case OP_SETLIST:
		if B == 0 {
			e.reads.addFrom(A)
		} else {
			for r := A; r <= A+B; r++ {
				e.reads.add(r)
			}
		}
		if C == 0 {
			skip = 1
			e.succs[0] = pc + 2
		}
	case OP_CLOSE, OP_NOP:
	case OP_CLOSURE:
		e.writes.add(A)
		skip = int(fp.FunctionPrototypes[opGetArgBx(inst)].NumUpvalues)
		for i := 1; i <= skip; i++ {
			if d := code[pc+i]; opGetOpCode(d) == OP_MOVE {
				e.reads.add(opGetArgB(d))
			}
		}
		e.succs[0] = pc + 1 + skip
	case OP_VARARG:
		if B == 0 {
			// open result list: nothing is definitely written
		} else {
			for r := A; r <= A+B-2; r++ {
				e.writes.add(r)
			}
		}
	default:
		// unknown instruction: be conservative
		e.reads.addFrom(0)
	}
	return e, skip
}

// isOpenEnded reports whether the instruction reads "all registers from
// A up to the registry top".
func isOpenEnded(inst uint32) bool {
	switch opGetOpCode(inst) {
	case OP_CALL, OP_TAILCALL, OP_RETURN, OP_SETLIST:
		return opGetArgB(inst) == 0
	}
	return false
}

// analyzeBytecode computes control flow and liveness information.
func analyzeBytecode(fp *FunctionProto) *bcInfo {
	n := len(fp.Code)
	info := &bcInfo{
		effects: make([]bcEffect, n),
		liveIn:  make([]regSet, n),
		leader:  make([]bool, n+1),
		preds:   make([]int32, n+1),
		data:    make([]bool, n),
	}
	info.nslots = int(fp.NumUsedRegisters)
	for pc := 0; pc < n; pc++ {
		e, skip := instEffect(fp, pc)
		if isOpenEnded(fp.Code[pc]) {
			// "all registers from A" must not inflate the register count
			trimmed := e
			trimmed.reads = regSet{}
			info.nslots = intMax(info.nslots, maxRegister(fp, pc, &trimmed)+1)
		} else {
			info.nslots = intMax(info.nslots, maxRegister(fp, pc, &e)+1)
		}
		info.effects[pc] = e
		if opGetOpCode(fp.Code[pc]) == OP_CLOSURE {
			for i := 1; i <= skip; i++ {
				if d := fp.Code[pc+i]; opGetOpCode(d) == OP_MOVE {
					info.escaped.add(opGetArgB(d))
				}
			}
		}
		for i := 1; i <= skip && pc+i < n; i++ {
			info.data[pc+i] = true
			info.effects[pc+i] = bcEffect{succs: [2]int{-1, -1}}
		}
		pc += skip
	}
	// leaders and predecessor counts
	info.leader[0] = true
	for pc := 0; pc < n; pc++ {
		if info.data[pc] {
			continue
		}
		e := &info.effects[pc]
		fallsThrough := e.nsucc == 1 && e.succs[0] == pc+1
		for i := 0; i < e.nsucc; i++ {
			s := e.succs[i]
			if s < 0 || s > n {
				continue
			}
			info.preds[s]++
			if !fallsThrough {
				info.leader[s] = true
			}
		}
		if !fallsThrough && pc+1 <= n {
			info.leader[pc+1] = true
		}
	}
	// a fall-through into a jump target also starts a block there
	for pc := 0; pc <= n; pc++ {
		if info.preds[pc] > 1 {
			info.leader[pc] = true
		}
	}
	// backward liveness fixpoint; escaped registers are always live
	for changed := true; changed; {
		changed = false
		for pc := n - 1; pc >= 0; pc-- {
			if info.data[pc] {
				continue
			}
			e := &info.effects[pc]
			var live regSet
			for i := 0; i < e.nsucc; i++ {
				if s := e.succs[i]; s >= 0 && s < n {
					live.union(&info.liveIn[s])
				}
			}
			for i := range live {
				live[i] = (live[i] &^ e.writes[i]) | e.reads[i] | info.escaped[i]
			}
			if info.liveIn[pc].union(&live) {
				changed = true
			}
		}
	}
	return info
}
