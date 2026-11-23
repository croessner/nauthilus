package jit

import (
	x "github.com/yuin/gopher-lua/internal/jit/asm/amd64"
)

// Register assignment of the amd64 backend.
//
//	allocatable integer registers: RBX RSI RDI R8 R9 R10 R11 R12
//	emitter scratch registers:     RAX RDX
//	private temporary:             RCX
//	pinned:                        R15 (context frame), R13 (register window)
//	never touched:                 RSP RBP R14
//	allocatable float registers:   X0..X12
//	emitter scratch registers:     X13 X14
//	private temporary:             X15
var amd64GPR = [...]x.Reg{x.RBX, x.RSI, x.RDI, x.R8, x.R9, x.R10, x.R11, x.R12, x.RAX, x.RDX}

const (
	amd64NumGPR = 8
	amd64NumFPR = 13
	amd64Tmp    = x.RCX
	amd64FTmp   = x.X15
	amd64Ctx    = x.R15
	amd64Base   = x.R13
)

// AMD64 is the x86-64 macro assembler. It requires SSE4.1.
type AMD64 struct {
	a *x.Assembler
}

// NewAMD64 returns a macro assembler for x86-64.
func NewAMD64() *AMD64 { return &AMD64{a: x.New()} }

func (m *AMD64) NumGPR() int { return amd64NumGPR }
func (m *AMD64) NumFPR() int { return amd64NumFPR }

// g maps an abstract integer register index to a machine register.
func (m *AMD64) g(i int) x.Reg {
	switch i {
	case RegCtx:
		return amd64Ctx
	case RegBase:
		return amd64Base
	}
	return amd64GPR[i]
}

// f maps an abstract float register index to a machine register.
func (m *AMD64) f(i int) x.XReg { return x.XReg(i) }

func (m *AMD64) NewLabel() int             { return int(m.a.NewLabel()) }
func (m *AMD64) Bind(label int)            { m.a.Bind(x.Label(label)) }
func (m *AMD64) LabelOffset(label int) int { return m.a.LabelOffset(x.Label(label)) }
func (m *AMD64) Bytes() ([]byte, error)    { return m.a.Bytes() }

func (m *AMD64) MovRR(dst, src int) {
	if d, s := m.g(dst), m.g(src); d != s {
		m.a.MovRR(d, s)
	}
}

func (m *AMD64) MovRI(dst int, c int64) { m.a.MovRI(m.g(dst), c) }

func (m *AMD64) MovFF(dst, src int) {
	if dst != src {
		m.a.MovapdXX(m.f(dst), m.f(src))
	}
}

func (m *AMD64) MovFI(dst int, bits uint64) {
	if bits == 0 {
		m.a.XorpdXX(m.f(dst), m.f(dst))
		return
	}
	m.a.MovRI(amd64Tmp, int64(bits))
	m.a.MovqXR(m.f(dst), amd64Tmp)
}

func (m *AMD64) Load(dst, base int, disp int32, size int) {
	mem := x.M(m.g(base), disp)
	switch size {
	case 8:
		m.a.MovRM(m.g(dst), mem)
	case 4:
		m.a.MovRM32(m.g(dst), mem)
	default:
		m.a.MovzxRM8(m.g(dst), mem)
	}
}

func (m *AMD64) LoadF(dst, base int, disp int32) {
	m.a.MovsdXM(m.f(dst), x.M(m.g(base), disp))
}

func (m *AMD64) Store(base int, disp int32, src int) {
	m.a.MovMR(x.M(m.g(base), disp), m.g(src))
}

func (m *AMD64) StoreF(base int, disp int32, src int) {
	m.a.MovsdMX(x.M(m.g(base), disp), m.f(src))
}

func fitsInt32(c int64) bool { return c >= -1<<31 && c <= 1<<31-1 }

func (m *AMD64) Arith(op Op, dst, a, b int) {
	d, ra, rb := m.g(dst), m.g(a), m.g(b)
	switch op {
	case OpShl, OpShr, OpSar:
		m.a.MovRR(amd64Tmp, rb)
		if d != ra {
			m.a.MovRR(d, ra)
		}
		switch op {
		case OpShl:
			m.a.ShlRCL(d)
		case OpShr:
			m.a.ShrRCL(d)
		default:
			m.a.SarRCL(d)
		}
		return
	case OpDiv, OpMod:
		m.divMod(op, d, ra, rb)
		return
	}
	commutative := op != OpSub
	switch {
	case d == ra:
	case d == rb && commutative:
		rb = ra
	case d == rb:
		m.a.MovRR(amd64Tmp, rb)
		m.a.MovRR(d, ra)
		rb = amd64Tmp
	case op == OpAdd:
		m.a.Lea(d, x.MIdx(ra, rb, 1, 0))
		return
	default:
		m.a.MovRR(d, ra)
	}
	switch op {
	case OpAdd:
		m.a.AddRR(d, rb)
	case OpSub:
		m.a.SubRR(d, rb)
	case OpMul:
		m.a.ImulRR(d, rb)
	case OpAnd:
		m.a.AndRR(d, rb)
	case OpOr:
		m.a.OrRR(d, rb)
	case OpXor:
		m.a.XorRR(d, rb)
	default:
		panic("jit: amd64: unsupported integer operation " + op.String())
	}
}

// divMod emits floor division or modulo. The divisor is known to be
// non-zero; a divisor of -1 is special-cased because the hardware
// division traps on overflow.
func (m *AMD64) divMod(op Op, d, ra, rb x.Reg) {
	a := m.a
	special := a.NewLabel()
	done := a.NewLabel()
	adjust := a.NewLabel()
	a.MovRR(amd64Tmp, rb)
	if ra != x.RAX {
		a.MovRR(x.RAX, ra)
	}
	a.CmpRI(amd64Tmp, -1)
	a.Jcc(x.CondE, special)
	a.Cqo()
	a.IdivR(amd64Tmp)
	// floor adjustment: needed if the remainder is non-zero and its sign
	// differs from the sign of the divisor
	a.TestRR(x.RDX, x.RDX)
	a.Jcc(x.CondE, done)
	a.XorRR(x.RDX, amd64Tmp)
	a.Jcc(x.CondS, adjust)
	a.XorRR(x.RDX, amd64Tmp)
	a.Jmp(done)
	a.Bind(adjust)
	a.XorRR(x.RDX, amd64Tmp)
	a.SubRI(x.RAX, 1)
	a.AddRR(x.RDX, amd64Tmp)
	a.Jmp(done)
	a.Bind(special)
	a.NegR(x.RAX)
	a.XorRR(x.RDX, x.RDX)
	a.Bind(done)
	if op == OpDiv {
		if d != x.RAX {
			a.MovRR(d, x.RAX)
		}
	} else if d != x.RDX {
		a.MovRR(d, x.RDX)
	}
}

func (m *AMD64) ArithImm(op Op, dst, a int, c int64) bool {
	d, ra := m.g(dst), m.g(a)
	switch op {
	case OpShl, OpShr, OpSar:
		if c < 0 || c > 63 {
			return false
		}
		if d != ra {
			m.a.MovRR(d, ra)
		}
		switch op {
		case OpShl:
			m.a.ShlRI(d, uint8(c))
		case OpShr:
			m.a.ShrRI(d, uint8(c))
		default:
			m.a.SarRI(d, uint8(c))
		}
		return true
	case OpAdd, OpSub, OpAnd, OpOr, OpXor, OpMul:
	default:
		return false
	}
	if !fitsInt32(c) {
		return false
	}
	imm := int32(c)
	switch op {
	case OpMul:
		m.a.ImulRRI(d, ra, imm)
		return true
	case OpAdd:
		if d != ra {
			m.a.Lea(d, x.M(ra, imm))
			return true
		}
	case OpSub:
		if d != ra && c != -1<<31 {
			m.a.Lea(d, x.M(ra, -imm))
			return true
		}
	}
	if d != ra {
		m.a.MovRR(d, ra)
	}
	switch op {
	case OpAdd:
		m.a.AddRI(d, imm)
	case OpSub:
		m.a.SubRI(d, imm)
	case OpAnd:
		m.a.AndRI(d, imm)
	case OpOr:
		m.a.OrRI(d, imm)
	case OpXor:
		m.a.XorRI(d, imm)
	}
	return true
}

func (m *AMD64) Unary(op Op, dst, a int) {
	d, ra := m.g(dst), m.g(a)
	if d != ra {
		m.a.MovRR(d, ra)
	}
	if op == OpNeg {
		m.a.NegR(d)
	} else {
		m.a.NotR(d)
	}
}

func (m *AMD64) FArith(op Op, dst, a, b int) {
	d, fa, fb := m.f(dst), m.f(a), m.f(b)
	commutative := op == OpFAdd || op == OpFMul
	switch {
	case d == fa:
	case d == fb && commutative:
		fb = fa
	case d == fb:
		m.a.MovapdXX(amd64FTmp, fb)
		m.a.MovapdXX(d, fa)
		fb = amd64FTmp
	default:
		m.a.MovapdXX(d, fa)
	}
	switch op {
	case OpFAdd:
		m.a.AddsdXX(d, fb)
	case OpFSub:
		m.a.SubsdXX(d, fb)
	case OpFMul:
		m.a.MulsdXX(d, fb)
	case OpFDiv:
		m.a.DivsdXX(d, fb)
	default:
		panic("jit: amd64: unsupported float operation " + op.String())
	}
}

func (m *AMD64) FUnary(op Op, dst, a int) {
	d, fa := m.f(dst), m.f(a)
	switch op {
	case OpFSqrt:
		m.a.SqrtsdXX(d, fa)
	case OpFFloor:
		m.a.RoundsdXXI(d, fa, 0x09) // round toward -inf, suppress precision exception
	case OpFCeil:
		m.a.RoundsdXXI(d, fa, 0x0A) // round toward +inf, suppress precision exception
	case OpFNeg, OpFAbs:
		mask := int64(-1 << 63)
		if op == OpFAbs {
			mask = 1<<63 - 1
		}
		m.a.MovRI(amd64Tmp, mask)
		m.a.MovqXR(amd64FTmp, amd64Tmp)
		if d != fa {
			m.a.MovapdXX(d, fa)
		}
		if op == OpFNeg {
			m.a.XorpdXX(d, amd64FTmp)
		} else {
			m.a.AndpdXX(d, amd64FTmp)
		}
	default:
		panic("jit: amd64: unsupported float operation " + op.String())
	}
}

func (m *AMD64) IntToFloat(dst, src int) {
	m.a.XorpdXX(m.f(dst), m.f(dst)) // break the false output dependency
	m.a.Cvtsi2sdXR(m.f(dst), m.g(src))
}

func (m *AMD64) FloatToInt(dst, src int) {
	m.a.Cvttsd2siRX(m.g(dst), m.f(src))
}

func amd64Cond(c Cond) x.Cond {
	switch c {
	case CondEq:
		return x.CondE
	case CondNe:
		return x.CondNE
	case CondLt:
		return x.CondL
	case CondGe:
		return x.CondGE
	case CondLe:
		return x.CondLE
	case CondGt:
		return x.CondG
	case CondULt:
		return x.CondB
	default:
		return x.CondAE
	}
}

func (m *AMD64) CmpJump(c Cond, a, b int, target int) {
	m.a.CmpRR(m.g(a), m.g(b))
	m.a.Jcc(amd64Cond(c), x.Label(target))
}

func (m *AMD64) CmpImmJump(c Cond, a int, imm int64, target int) bool {
	if !fitsInt32(imm) {
		return false
	}
	if imm == 0 && (c == CondEq || c == CondNe) {
		m.a.TestRR(m.g(a), m.g(a))
	} else {
		m.a.CmpRI(m.g(a), int32(imm))
	}
	m.a.Jcc(amd64Cond(c), x.Label(target))
	return true
}

func (m *AMD64) CmpSet(c Cond, dst, a, b int) {
	m.a.CmpRR(m.g(a), m.g(b))
	m.a.Setcc(amd64Cond(c), m.g(dst))
	m.a.MovzxRR8(m.g(dst), m.g(dst))
}

func (m *AMD64) FCmpJump(op Op, a, b int, target int, want bool) {
	fa, fb := m.f(a), m.f(b)
	t := x.Label(target)
	switch op {
	case OpFLt:
		// "b above a" is false for unordered operands
		m.a.UcomisdXX(fb, fa)
		if want {
			m.a.Jcc(x.CondA, t)
		} else {
			m.a.Jcc(x.CondBE, t)
		}
	case OpFLe:
		m.a.UcomisdXX(fb, fa)
		if want {
			m.a.Jcc(x.CondAE, t)
		} else {
			m.a.Jcc(x.CondB, t)
		}
	case OpFEq, OpFNe:
		m.a.UcomisdXX(fa, fb)
		if want == (op == OpFEq) {
			// jump if ordered and equal
			skip := m.a.NewLabel()
			m.a.Jcc(x.CondP, skip)
			m.a.Jcc(x.CondE, t)
			m.a.Bind(skip)
		} else {
			// jump if unordered or different
			m.a.Jcc(x.CondP, t)
			m.a.Jcc(x.CondNE, t)
		}
	default:
		panic("jit: amd64: unsupported float comparison " + op.String())
	}
}

func (m *AMD64) FCmpSet(op Op, dst, a, b int) {
	fa, fb := m.f(a), m.f(b)
	d := m.g(dst)
	switch op {
	case OpFLt:
		m.a.UcomisdXX(fb, fa)
		m.a.Setcc(x.CondA, d)
	case OpFLe:
		m.a.UcomisdXX(fb, fa)
		m.a.Setcc(x.CondAE, d)
	case OpFEq:
		m.a.UcomisdXX(fa, fb)
		m.a.Setcc(x.CondE, d)
		m.a.Setcc(x.CondNP, amd64Tmp)
		m.a.AndRR(d, amd64Tmp)
	case OpFNe:
		m.a.UcomisdXX(fa, fb)
		m.a.Setcc(x.CondNE, d)
		m.a.Setcc(x.CondP, amd64Tmp)
		m.a.OrRR(d, amd64Tmp)
	default:
		panic("jit: amd64: unsupported float comparison " + op.String())
	}
	m.a.MovzxRR8(d, d)
}

func (m *AMD64) Jump(target int) { m.a.Jmp(x.Label(target)) }

func (m *AMD64) ExitStub(code uint32, common int) {
	m.a.MovMI(x.M(amd64Ctx, CtxExit), int32(code))
	m.a.Jmp(x.Label(common))
}

func (m *AMD64) FuelCheck(slow int) {
	m.a.DecM(x.M(amd64Ctx, CtxFuel))
	m.a.Jcc(x.CondE, x.Label(slow))
}

func (m *AMD64) SaveAllAndReturn() {
	for i := 0; i < amd64NumGPR; i++ {
		m.a.MovMR(x.M(amd64Ctx, int32(CtxSaveG+8*i)), amd64GPR[i])
	}
	for i := 0; i < amd64NumFPR; i++ {
		m.a.MovsdMX(x.M(amd64Ctx, int32(CtxSaveF+8*i)), x.XReg(i))
	}
	m.a.Ret()
}

func (m *AMD64) Enter() {
	for i := 0; i < amd64NumGPR; i++ {
		m.a.MovRM(amd64GPR[i], x.M(amd64Ctx, int32(CtxSaveG+8*i)))
	}
	for i := 0; i < amd64NumFPR; i++ {
		m.a.MovsdXM(x.XReg(i), x.M(amd64Ctx, int32(CtxSaveF+8*i)))
	}
	m.a.MovRM(amd64Base, x.M(amd64Ctx, CtxRegBase))
	m.a.JmpM(x.M(amd64Ctx, CtxTarget))
}
