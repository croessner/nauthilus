package jit

import (
	a64 "github.com/yuin/gopher-lua/internal/jit/asm/arm64"
)

// Register assignment of the arm64 backend.
//
//	allocatable integer registers: X0..X15
//	emitter scratch registers:     X16 X17
//	private temporaries:           X21 X22 X23
//	pinned:                        X19 (context frame), X20 (register window)
//	never touched:                 X18 X26 X27 X28 X29 X30 SP
//	allocatable float registers:   V0..V27
//	emitter scratch registers:     V28 V29
//	private temporaries:           V30 V31
const (
	arm64NumGPR = 16
	arm64NumFPR = 28
	arm64Tmp    = a64.X21
	arm64Tmp2   = a64.X22
	arm64Tmp3   = a64.X23
	arm64Ctx    = a64.X19
	arm64Base   = a64.X20
)

// ARM64 is the AArch64 macro assembler.
type ARM64 struct {
	a *a64.Assembler
}

// NewARM64 returns a macro assembler for AArch64.
func NewARM64() *ARM64 { return &ARM64{a: a64.New()} }

func (m *ARM64) NumGPR() int { return arm64NumGPR }
func (m *ARM64) NumFPR() int { return arm64NumFPR }

// g maps an abstract integer register index to a machine register.
func (m *ARM64) g(i int) a64.Reg {
	switch i {
	case RegCtx:
		return arm64Ctx
	case RegBase:
		return arm64Base
	}
	return a64.Reg(i) // X0..X15 and the scratch registers X16, X17
}

// f maps an abstract float register index to a machine register.
func (m *ARM64) f(i int) a64.VReg { return a64.VReg(i) }

func (m *ARM64) NewLabel() int             { return int(m.a.NewLabel()) }
func (m *ARM64) Bind(label int)            { m.a.Bind(a64.Label(label)) }
func (m *ARM64) LabelOffset(label int) int { return m.a.LabelOffset(a64.Label(label)) }
func (m *ARM64) Bytes() ([]byte, error)    { return m.a.Bytes() }

func (m *ARM64) MovRR(dst, src int) {
	if d, s := m.g(dst), m.g(src); d != s {
		m.a.MovRR(d, s)
	}
}

func (m *ARM64) MovRI(dst int, c int64) { m.a.MovRI(m.g(dst), c) }

func (m *ARM64) MovFF(dst, src int) {
	if dst != src {
		m.a.FmovDD(m.f(dst), m.f(src))
	}
}

func (m *ARM64) MovFI(dst int, bits uint64) {
	if bits == 0 {
		m.a.FmovDR(m.f(dst), a64.XZR)
		return
	}
	m.a.MovRI(arm64Tmp, int64(bits))
	m.a.FmovDR(m.f(dst), arm64Tmp)
}

// addr returns a base register and displacement that the load/store
// instructions of the given access size can encode, materializing the
// address in a temporary if necessary.
func (m *ARM64) addr(base int, disp int32, size int32) (a64.Reg, int32) {
	b := m.g(base)
	if disp >= -256 && disp <= 255 {
		return b, disp
	}
	if disp >= 0 && disp%size == 0 && disp/size <= 4095 {
		return b, disp
	}
	m.a.MovRI(arm64Tmp, int64(disp))
	m.a.AddRR(arm64Tmp, b, arm64Tmp)
	return arm64Tmp, 0
}

func (m *ARM64) Load(dst, base int, disp int32, size int) {
	switch size {
	case 8:
		b, d := m.addr(base, disp, 8)
		m.a.LdrRM(m.g(dst), b, d)
	case 4:
		b, d := m.addr(base, disp, 4)
		m.a.LdrRM32(m.g(dst), b, d)
	default:
		b, d := m.addr(base, disp, 1)
		m.a.LdrbRM(m.g(dst), b, d)
	}
}

func (m *ARM64) LoadF(dst, base int, disp int32) {
	b, d := m.addr(base, disp, 8)
	m.a.LdrDM(m.f(dst), b, d)
}

func (m *ARM64) Store(base int, disp int32, src int) {
	b, d := m.addr(base, disp, 8)
	m.a.StrRM(m.g(src), b, d)
}

func (m *ARM64) StoreF(base int, disp int32, src int) {
	b, d := m.addr(base, disp, 8)
	m.a.StrDM(m.f(src), b, d)
}

func (m *ARM64) Arith(op Op, dst, a, b int) {
	d, ra, rb := m.g(dst), m.g(a), m.g(b)
	switch op {
	case OpAdd:
		m.a.AddRR(d, ra, rb)
	case OpSub:
		m.a.SubRR(d, ra, rb)
	case OpMul:
		m.a.MulRR(d, ra, rb)
	case OpAnd:
		m.a.AndRR(d, ra, rb)
	case OpOr:
		m.a.OrrRR(d, ra, rb)
	case OpXor:
		m.a.EorRR(d, ra, rb)
	case OpShl:
		m.a.LslRR(d, ra, rb)
	case OpShr:
		m.a.LsrRR(d, ra, rb)
	case OpSar:
		m.a.AsrRR(d, ra, rb)
	case OpDiv, OpMod:
		// quotient truncated toward zero and matching remainder; the
		// division instruction does not trap (minint / -1 wraps)
		done := m.a.NewLabel()
		m.a.SdivRR(arm64Tmp, ra, rb)
		m.a.MsubRRRR(arm64Tmp2, arm64Tmp, rb, ra)
		m.a.Cbz(arm64Tmp2, done)
		m.a.EorRR(arm64Tmp3, arm64Tmp2, rb)
		m.a.CmpRI(arm64Tmp3, 0)
		m.a.Bcond(a64.CondGE, done)
		// remainder and divisor have different signs: round down
		m.a.SubRI(arm64Tmp, arm64Tmp, 1)
		m.a.AddRR(arm64Tmp2, arm64Tmp2, rb)
		m.a.Bind(done)
		if op == OpDiv {
			m.a.MovRR(d, arm64Tmp)
		} else {
			m.a.MovRR(d, arm64Tmp2)
		}
	default:
		panic("jit: arm64: unsupported integer operation " + op.String())
	}
}

func (m *ARM64) ArithImm(op Op, dst, a int, c int64) bool {
	d, ra := m.g(dst), m.g(a)
	switch op {
	case OpAdd, OpSub:
		neg := c < 0
		if neg {
			if c == -1<<63 {
				return false
			}
			c = -c
		}
		if c > 1<<24 || !a64.ImmAddSubOK(uint32(c)) {
			return false
		}
		if (op == OpAdd) != neg {
			m.a.AddRI(d, ra, uint32(c))
		} else {
			m.a.SubRI(d, ra, uint32(c))
		}
		return true
	case OpShl, OpShr, OpSar:
		if c < 0 || c > 63 {
			return false
		}
		switch op {
		case OpShl:
			m.a.LslRI(d, ra, uint8(c))
		case OpShr:
			m.a.LsrRI(d, ra, uint8(c))
		default:
			m.a.AsrRI(d, ra, uint8(c))
		}
		return true
	}
	return false
}

func (m *ARM64) Unary(op Op, dst, a int) {
	if op == OpNeg {
		m.a.NegRR(m.g(dst), m.g(a))
	} else {
		m.a.MvnRR(m.g(dst), m.g(a))
	}
}

func (m *ARM64) FArith(op Op, dst, a, b int) {
	d, fa, fb := m.f(dst), m.f(a), m.f(b)
	switch op {
	case OpFAdd:
		m.a.FaddD(d, fa, fb)
	case OpFSub:
		m.a.FsubD(d, fa, fb)
	case OpFMul:
		m.a.FmulD(d, fa, fb)
	case OpFDiv:
		m.a.FdivD(d, fa, fb)
	default:
		panic("jit: arm64: unsupported float operation " + op.String())
	}
}

func (m *ARM64) FUnary(op Op, dst, a int) {
	d, fa := m.f(dst), m.f(a)
	switch op {
	case OpFNeg:
		m.a.FnegD(d, fa)
	case OpFSqrt:
		m.a.FsqrtD(d, fa)
	case OpFAbs:
		m.a.FabsD(d, fa)
	case OpFFloor:
		m.a.FrintmD(d, fa)
	case OpFCeil:
		m.a.FrintpD(d, fa)
	default:
		panic("jit: arm64: unsupported float operation " + op.String())
	}
}

func (m *ARM64) IntToFloat(dst, src int) { m.a.ScvtfDR(m.f(dst), m.g(src)) }
func (m *ARM64) FloatToInt(dst, src int) { m.a.FcvtzsRD(m.g(dst), m.f(src)) }

func arm64Cond(c Cond) a64.Cond {
	switch c {
	case CondEq:
		return a64.CondEQ
	case CondNe:
		return a64.CondNE
	case CondLt:
		return a64.CondLT
	case CondGe:
		return a64.CondGE
	case CondLe:
		return a64.CondLE
	case CondGt:
		return a64.CondGT
	case CondULt:
		return a64.CondLO
	default:
		return a64.CondHS
	}
}

func (m *ARM64) CmpJump(c Cond, a, b int, target int) {
	m.a.CmpRR(m.g(a), m.g(b))
	m.a.Bcond(arm64Cond(c), a64.Label(target))
}

func (m *ARM64) CmpImmJump(c Cond, a int, imm int64, target int) bool {
	ra := m.g(a)
	t := a64.Label(target)
	switch {
	case imm == 0 && c == CondEq:
		m.a.Cbz(ra, t)
		return true
	case imm == 0 && c == CondNe:
		m.a.Cbnz(ra, t)
		return true
	case imm >= 0 && imm <= 1<<24 && a64.ImmAddSubOK(uint32(imm)):
		m.a.CmpRI(ra, uint32(imm))
	case imm < 0 && imm >= -(1<<24) && a64.ImmAddSubOK(uint32(-imm)):
		m.a.CmnRI(ra, uint32(-imm))
	default:
		return false
	}
	m.a.Bcond(arm64Cond(c), t)
	return true
}

func (m *ARM64) CmpSet(c Cond, dst, a, b int) {
	m.a.CmpRR(m.g(a), m.g(b))
	m.a.Cset(m.g(dst), arm64Cond(c))
}

// arm64FloatCond returns the condition that holds after FCMP a, b exactly
// when the relation op has the value want. Unordered operands make every
// relation except OpFNe false.
func arm64FloatCond(op Op, want bool) a64.Cond {
	var c a64.Cond
	switch op {
	case OpFLt:
		c = a64.CondMI
	case OpFLe:
		c = a64.CondLS
	case OpFEq:
		c = a64.CondEQ
	case OpFNe:
		c = a64.CondNE
	default:
		panic("jit: arm64: unsupported float comparison " + op.String())
	}
	if !want {
		c = c.Negate()
	}
	return c
}

func (m *ARM64) FCmpJump(op Op, a, b int, target int, want bool) {
	m.a.FcmpDD(m.f(a), m.f(b))
	m.a.Bcond(arm64FloatCond(op, want), a64.Label(target))
}

func (m *ARM64) FCmpSet(op Op, dst, a, b int) {
	m.a.FcmpDD(m.f(a), m.f(b))
	m.a.Cset(m.g(dst), arm64FloatCond(op, true))
}

func (m *ARM64) Jump(target int) { m.a.B(a64.Label(target)) }

func (m *ARM64) ExitStub(code uint32, common int) {
	m.a.MovRI(arm64Tmp, int64(code))
	m.a.StrRM(arm64Tmp, arm64Ctx, CtxExit)
	m.a.B(a64.Label(common))
}

func (m *ARM64) FuelCheck(slow int) {
	m.a.LdrRM(arm64Tmp, arm64Ctx, CtxFuel)
	m.a.SubsRI(arm64Tmp, arm64Tmp, 1)
	m.a.StrRM(arm64Tmp, arm64Ctx, CtxFuel)
	m.a.Bcond(a64.CondEQ, a64.Label(slow))
}

func (m *ARM64) SaveAllAndReturn() {
	for i := 0; i < arm64NumGPR; i++ {
		m.a.StrRM(a64.Reg(i), arm64Ctx, int32(CtxSaveG+8*i))
	}
	for i := 0; i < arm64NumFPR; i++ {
		m.a.StrDM(a64.VReg(i), arm64Ctx, int32(CtxSaveF+8*i))
	}
	m.a.Ret()
}

func (m *ARM64) Enter() {
	for i := 0; i < arm64NumGPR; i++ {
		m.a.LdrRM(a64.Reg(i), arm64Ctx, int32(CtxSaveG+8*i))
	}
	for i := 0; i < arm64NumFPR; i++ {
		m.a.LdrDM(a64.VReg(i), arm64Ctx, int32(CtxSaveF+8*i))
	}
	m.a.LdrRM(arm64Base, arm64Ctx, CtxRegBase)
	m.a.LdrRM(arm64Tmp, arm64Ctx, CtxTarget)
	m.a.Br(arm64Tmp)
}
