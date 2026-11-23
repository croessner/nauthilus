package amd64

import "math"

// aluOp is the /digit of the group-1 arithmetic instructions. The same value
// selects the opcode row of the register and memory forms (digit<<3 | form).
type aluOp uint8

// Group-1 arithmetic operations.
const (
	aluAdd aluOp = 0
	aluOr  aluOp = 1
	aluAnd aluOp = 4
	aluSub aluOp = 5
	aluXor aluOp = 6
	aluCmp aluOp = 7
)

// shiftOp is the /digit of the group-2 shift instructions.
type shiftOp uint8

// Group-2 shift operations.
const (
	shiftShl shiftOp = 4
	shiftShr shiftOp = 5
	shiftSar shiftOp = 7
)

// maxShift64 is the largest meaningful shift count for 64-bit operands.
const maxShift64 = 63

// condMax is the highest valid condition code.
const condMax = CondG

// MovRR emits mov dst, src (64-bit).
func (a *Assembler) MovRR(dst, src Reg) {
	a.regReg(op64(0x89), uint8(src), uint8(dst), false)
}

// MovRI loads the 64-bit constant imm into dst without modifying flags, using
// the shortest encoding: mov r32, imm32 (zero-extending) for 0..0xFFFFFFFF,
// mov r64, simm32 for values that fit in int32, otherwise movabs.
func (a *Assembler) MovRI(dst Reg, imm int64) {
	if dst > R15 {
		a.fail(ErrInvalidOperand, "register out of range")

		return
	}

	switch {
	case imm >= 0 && imm <= math.MaxUint32:
		a.head(op32(0xB8|byte(dst)&7), 0, 0, uint8(dst), false)
		a.emit32(uint32(imm))
	case imm >= math.MinInt32 && imm <= math.MaxInt32:
		a.regReg(op64(0xC7), 0, uint8(dst), false)
		a.emit32(uint32(imm))
	default:
		a.head(op64(0xB8|byte(dst)&7), 0, 0, uint8(dst), false)
		a.emit64(uint64(imm))
	}
}

// MovRM emits mov dst, qword [m].
func (a *Assembler) MovRM(dst Reg, m Mem) {
	a.regMem(op64(0x8B), uint8(dst), m)
}

// MovMR emits mov qword [m], src.
func (a *Assembler) MovMR(m Mem, src Reg) {
	a.regMem(op64(0x89), uint8(src), m)
}

// MovMI emits mov qword [m], imm (sign-extended imm32).
func (a *Assembler) MovMI(m Mem, imm int32) {
	if a.regMem(op64(0xC7), 0, m) {
		a.emit32(uint32(imm))
	}
}

// MovRM32 emits mov dst32, dword [m]; the upper half of dst is zeroed.
func (a *Assembler) MovRM32(dst Reg, m Mem) {
	a.regMem(op32(0x8B), uint8(dst), m)
}

// MovMR32 emits mov dword [m], src32.
func (a *Assembler) MovMR32(m Mem, src Reg) {
	a.regMem(op32(0x89), uint8(src), m)
}

// MovMI32 emits mov dword [m], imm32.
func (a *Assembler) MovMI32(m Mem, imm int32) {
	if a.regMem(op32(0xC7), 0, m) {
		a.emit32(uint32(imm))
	}
}

// MovzxRM8 emits movzx dst32, byte [m]; the upper bits of dst are zeroed.
func (a *Assembler) MovzxRM8(dst Reg, m Mem) {
	a.regMem(op0F(0xB6), uint8(dst), m)
}

// MovzxRR8 emits movzx dst32, src8 where src8 is the low byte of src. A REX
// prefix is forced for RSP/RBP/RSI/RDI so that SPL/BPL/SIL/DIL are addressed
// instead of AH/CH/DH/BH.
func (a *Assembler) MovzxRR8(dst, src Reg) {
	a.regReg(op0F(0xB6), uint8(dst), uint8(src), true)
}

// Lea emits lea dst, [m] (64-bit).
func (a *Assembler) Lea(dst Reg, m Mem) {
	a.regMem(op64(0x8D), uint8(dst), m)
}

// aluRR emits "op r/m64, r64" with dst in ModRM.rm.
func (a *Assembler) aluRR(op aluOp, dst, src Reg) {
	a.regReg(op64(byte(op)<<3|0x01), uint8(src), uint8(dst), false)
}

// aluRM emits "op r64, r/m64" with a memory source.
func (a *Assembler) aluRM(op aluOp, dst Reg, m Mem) {
	a.regMem(op64(byte(op)<<3|0x03), uint8(dst), m)
}

// aluImm selects the group-1 immediate opcode: 83 /n ib when imm fits in a
// sign-extended byte, otherwise 81 /n id.
func aluImm(w bool, imm int32) inst {
	if fitsInt8(imm) {
		return inst{op: 0x83, w: w}
	}

	return inst{op: 0x81, w: w}
}

// aluRI emits "op r64, imm".
func (a *Assembler) aluRI(op aluOp, dst Reg, imm int32) {
	if a.regReg(aluImm(true, imm), uint8(op), uint8(dst), false) {
		a.emitImm8or32(imm)
	}
}

// aluMI emits "op [m], imm" with 64-bit (w) or 32-bit operand size.
func (a *Assembler) aluMI(w bool, op aluOp, m Mem, imm int32) {
	if a.regMem(aluImm(w, imm), uint8(op), m) {
		a.emitImm8or32(imm)
	}
}

// AddRR emits add dst, src.
func (a *Assembler) AddRR(dst, src Reg) { a.aluRR(aluAdd, dst, src) }

// SubRR emits sub dst, src.
func (a *Assembler) SubRR(dst, src Reg) { a.aluRR(aluSub, dst, src) }

// AndRR emits and dst, src.
func (a *Assembler) AndRR(dst, src Reg) { a.aluRR(aluAnd, dst, src) }

// OrRR emits or dst, src.
func (a *Assembler) OrRR(dst, src Reg) { a.aluRR(aluOr, dst, src) }

// XorRR emits xor dst, src.
func (a *Assembler) XorRR(dst, src Reg) { a.aluRR(aluXor, dst, src) }

// CmpRR emits cmp dst, src (flags of dst - src).
func (a *Assembler) CmpRR(dst, src Reg) { a.aluRR(aluCmp, dst, src) }

// TestRR emits test dst, src.
func (a *Assembler) TestRR(dst, src Reg) {
	a.regReg(op64(0x85), uint8(src), uint8(dst), false)
}

// AddRI emits add dst, imm.
func (a *Assembler) AddRI(dst Reg, imm int32) { a.aluRI(aluAdd, dst, imm) }

// SubRI emits sub dst, imm.
func (a *Assembler) SubRI(dst Reg, imm int32) { a.aluRI(aluSub, dst, imm) }

// AndRI emits and dst, imm (imm is sign-extended to 64 bits).
func (a *Assembler) AndRI(dst Reg, imm int32) { a.aluRI(aluAnd, dst, imm) }

// OrRI emits or dst, imm (imm is sign-extended to 64 bits).
func (a *Assembler) OrRI(dst Reg, imm int32) { a.aluRI(aluOr, dst, imm) }

// XorRI emits xor dst, imm (imm is sign-extended to 64 bits).
func (a *Assembler) XorRI(dst Reg, imm int32) { a.aluRI(aluXor, dst, imm) }

// CmpRI emits cmp dst, imm.
func (a *Assembler) CmpRI(dst Reg, imm int32) { a.aluRI(aluCmp, dst, imm) }

// TestRI emits test dst, imm (imm is sign-extended to 64 bits).
func (a *Assembler) TestRI(dst Reg, imm int32) {
	if a.regReg(op64(0xF7), 0, uint8(dst), false) {
		a.emit32(uint32(imm))
	}
}

// AddRM emits add dst, qword [m].
func (a *Assembler) AddRM(dst Reg, m Mem) { a.aluRM(aluAdd, dst, m) }

// SubRM emits sub dst, qword [m].
func (a *Assembler) SubRM(dst Reg, m Mem) { a.aluRM(aluSub, dst, m) }

// CmpRM emits cmp dst, qword [m].
func (a *Assembler) CmpRM(dst Reg, m Mem) { a.aluRM(aluCmp, dst, m) }

// AddMI emits add qword [m], imm.
func (a *Assembler) AddMI(m Mem, imm int32) { a.aluMI(true, aluAdd, m, imm) }

// SubMI emits sub qword [m], imm.
func (a *Assembler) SubMI(m Mem, imm int32) { a.aluMI(true, aluSub, m, imm) }

// CmpMI emits cmp qword [m], imm.
func (a *Assembler) CmpMI(m Mem, imm int32) { a.aluMI(true, aluCmp, m, imm) }

// CmpMI32 emits cmp dword [m], imm. The sign-extended imm8 form is used when
// imm fits, which compares identically to the imm32 form.
func (a *Assembler) CmpMI32(m Mem, imm int32) { a.aluMI(false, aluCmp, m, imm) }

// IncM emits inc qword [m].
func (a *Assembler) IncM(m Mem) {
	a.regMem(op64(0xFF), 0, m)
}

// DecM emits dec qword [m].
func (a *Assembler) DecM(m Mem) {
	a.regMem(op64(0xFF), 1, m)
}

// ImulRR emits imul dst, src (64-bit, truncated product).
func (a *Assembler) ImulRR(dst, src Reg) {
	a.regReg(op0F64(0xAF), uint8(dst), uint8(src), false)
}

// ImulRRI emits imul dst, src, imm (dst = src * imm), using the imm8 form when
// imm fits in a sign-extended byte.
func (a *Assembler) ImulRRI(dst, src Reg, imm int32) {
	op := byte(0x69)
	if fitsInt8(imm) {
		op = 0x6B
	}

	if a.regReg(op64(op), uint8(dst), uint8(src), false) {
		a.emitImm8or32(imm)
	}
}

// NegR emits neg r.
func (a *Assembler) NegR(r Reg) {
	a.regReg(op64(0xF7), 3, uint8(r), false)
}

// NotR emits not r.
func (a *Assembler) NotR(r Reg) {
	a.regReg(op64(0xF7), 2, uint8(r), false)
}

// shiftRI emits a 64-bit shift of r by an immediate count in 0..63. A count
// of one uses the dedicated one-byte-shorter D1 form.
func (a *Assembler) shiftRI(op shiftOp, r Reg, imm uint8) {
	if imm > maxShift64 {
		a.fail(ErrInvalidOperand, "shift count out of range")

		return
	}

	if imm == 1 {
		a.regReg(op64(0xD1), uint8(op), uint8(r), false)

		return
	}

	if a.regReg(op64(0xC1), uint8(op), uint8(r), false) {
		a.emit1(imm)
	}
}

// shiftRCL emits a 64-bit shift of r by CL.
func (a *Assembler) shiftRCL(op shiftOp, r Reg) {
	a.regReg(op64(0xD3), uint8(op), uint8(r), false)
}

// ShlRI emits shl r, imm. imm must be in 0..63.
func (a *Assembler) ShlRI(r Reg, imm uint8) { a.shiftRI(shiftShl, r, imm) }

// ShrRI emits shr r, imm (logical). imm must be in 0..63.
func (a *Assembler) ShrRI(r Reg, imm uint8) { a.shiftRI(shiftShr, r, imm) }

// SarRI emits sar r, imm (arithmetic). imm must be in 0..63.
func (a *Assembler) SarRI(r Reg, imm uint8) { a.shiftRI(shiftSar, r, imm) }

// ShlRCL emits shl r, cl.
func (a *Assembler) ShlRCL(r Reg) { a.shiftRCL(shiftShl, r) }

// ShrRCL emits shr r, cl (logical).
func (a *Assembler) ShrRCL(r Reg) { a.shiftRCL(shiftShr, r) }

// SarRCL emits sar r, cl (arithmetic).
func (a *Assembler) SarRCL(r Reg) { a.shiftRCL(shiftSar, r) }

// Cqo sign-extends RAX into RDX:RAX.
func (a *Assembler) Cqo() {
	a.emit2(rexBase|rexW, 0x99)
}

// IdivR emits idiv r (signed RDX:RAX / r).
func (a *Assembler) IdivR(r Reg) {
	a.regReg(op64(0xF7), 7, uint8(r), false)
}

// DivR emits div r (unsigned RDX:RAX / r).
func (a *Assembler) DivR(r Reg) {
	a.regReg(op64(0xF7), 6, uint8(r), false)
}

// validCond records an error and returns false for an out-of-range condition.
func (a *Assembler) validCond(c Cond) bool {
	if c > condMax {
		a.fail(ErrInvalidOperand, "condition code out of range")

		return false
	}

	return true
}

// Setcc sets the low byte of dst to 1 if c holds and to 0 otherwise; the
// other bits of dst are left unchanged. A REX prefix is forced for
// RSP/RBP/RSI/RDI so that SPL/BPL/SIL/DIL are addressed.
func (a *Assembler) Setcc(c Cond, dst Reg) {
	if a.validCond(c) {
		a.regReg(op0F(0x90|byte(c)), 0, uint8(dst), true)
	}
}

// Cmovcc emits cmovcc dst, src (64-bit).
func (a *Assembler) Cmovcc(c Cond, dst, src Reg) {
	if a.validCond(c) {
		a.regReg(op0F64(0x40|byte(c)), uint8(dst), uint8(src), false)
	}
}

// JmpR emits jmp r (indirect through a register).
func (a *Assembler) JmpR(r Reg) {
	a.regReg(op32(0xFF), 4, uint8(r), false)
}

// JmpM emits jmp qword [m].
func (a *Assembler) JmpM(m Mem) {
	a.regMem(op32(0xFF), 4, m)
}

// Ret emits a near return.
func (a *Assembler) Ret() {
	a.emit1(0xC3)
}

// Ud2 emits the guaranteed-invalid opcode.
func (a *Assembler) Ud2() {
	a.emit2(0x0F, 0x0B)
}

// Int3 emits a breakpoint trap.
func (a *Assembler) Int3() {
	a.emit1(0xCC)
}

// Nop emits a one-byte no-op.
func (a *Assembler) Nop() {
	a.emit1(0x90)
}
