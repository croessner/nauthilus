package arm64

// Opcodes of the control flow and system instructions with all operand
// fields zero.
const (
	opB     = 0x14000000 // b imm26
	opBcond = 0x54000000 // b.cond imm19
	opCbz   = 0xB4000000 // cbz xt, imm19
	opCbnz  = 0xB5000000 // cbnz xt, imm19
	opBr    = 0xD61F0000 // br xn
	opRet   = 0xD65F0000 // ret xn
	opBrk   = 0xD4200000 // brk #imm16
	opNop   = 0xD503201F
)

// B emits an unconditional branch to l. The target must be within +-128 MiB;
// Bytes checks the range.
func (a *Assembler) B(l Label) {
	a.branch("B", opB, fixupImm26, l)
}

// Bcond emits b.c to l. The target must be within +-1 MiB; Bytes checks the
// range. CondAL encodes b.al, which always branches.
func (a *Assembler) Bcond(c Cond, l Label) {
	if c > CondAL {
		a.reject("Bcond", "condition %d out of range", uint8(c))

		return
	}

	a.branch("Bcond", opBcond|uint32(c), fixupImm19, l)
}

// Cbz emits cbz xr, l: branch if the 64-bit register is zero. The target must
// be within +-1 MiB; Bytes checks the range. Register 31 is XZR.
func (a *Assembler) Cbz(r Reg, l Label) {
	a.compareBranch("Cbz", opCbz, r, l)
}

// Cbnz emits cbnz xr, l: branch if the 64-bit register is not zero. The
// target must be within +-1 MiB; Bytes checks the range. Register 31 is XZR.
func (a *Assembler) Cbnz(r Reg, l Label) {
	a.compareBranch("Cbnz", opCbnz, r, l)
}

// Br emits br xr, an indirect branch. Register 31 is XZR.
func (a *Assembler) Br(r Reg) {
	a.regs3("Br", opBr, 0, uint8(r), 0)
}

// Ret emits ret (ret x30).
func (a *Assembler) Ret() {
	a.emit(opRet | uint32(X30)<<5)
}

// Brk emits brk #imm, a breakpoint exception.
func (a *Assembler) Brk(imm uint16) {
	a.emit(opBrk | uint32(imm)<<5)
}

// Nop emits nop.
func (a *Assembler) Nop() {
	a.emit(opNop)
}

// compareBranch emits a CBZ/CBNZ on the 64-bit register r.
func (a *Assembler) compareBranch(op string, opc uint32, r Reg, l Label) {
	if r > maxReg {
		a.reject(op, "register number out of range (%d)", uint8(r))

		return
	}

	a.branch(op, opc|uint32(r), fixupImm19, l)
}

// branch emits a PC-relative branch with a zero offset and records the fixup
// that Bytes patches once the position of l is known.
func (a *Assembler) branch(op string, opc uint32, kind fixupKind, l Label) {
	if !a.validLabel(l) {
		a.fail(ErrLabel, op, "label %d was not created by NewLabel", int(l))
		a.emit(undefinedInstr)

		return
	}

	a.fixups = append(a.fixups, fixup{off: len(a.buf), label: l, kind: kind})
	a.emit(opc)
}
