package amd64

import "math"

// Opcodes of the direct branches.
const (
	opJmpRel8  byte = 0xEB
	opJmpRel32 byte = 0xE9
	opJccRel8  byte = 0x70 // + condition
	opJccRel32 byte = 0x80 // + condition, after the 0F escape
)

// Jmp emits an unconditional jump to l. Unbound (forward) targets always use
// the rel32 form; bound (backward) targets use rel8 when in range.
func (a *Assembler) Jmp(l Label) {
	a.branch(l, opJmpRel8, 0, opJmpRel32)
}

// Jcc emits a conditional jump to l that is taken when c holds. Unbound
// (forward) targets always use the rel32 form; bound (backward) targets use
// rel8 when in range.
func (a *Assembler) Jcc(c Cond, l Label) {
	if a.validCond(c) {
		a.branch(l, opJccRel8|byte(c), 0x0F, opJccRel32|byte(c))
	}
}

// branch emits a direct branch to l. short is the rel8 opcode, near the rel32
// opcode and nearEsc an optional escape byte preceding near (0 for none).
func (a *Assembler) branch(l Label, short, nearEsc, near byte) {
	if !a.validLabel(l) {
		a.fail(ErrInvalidLabel, "branch target")

		return
	}

	target := a.labels[l]

	// Displacements are relative to the end of the branch instruction.
	if target != unbound {
		if rel := target - (len(a.buf) + 2); rel >= math.MinInt8 {
			a.emit2(short, byte(int8(rel)))

			return
		}
	}

	if nearEsc != 0 {
		a.emit1(nearEsc)
	}

	a.emit1(near)

	if target == unbound {
		a.fixups = append(a.fixups, fixup{pos: len(a.buf), label: l})
		a.emit32(0)

		return
	}

	rel := target - (len(a.buf) + 4)
	if rel < math.MinInt32 {
		// Roll back the opcode so that no partial instruction is left behind.
		a.buf = a.buf[:len(a.buf)-nearLen(nearEsc)]
		a.fail(ErrBranchRange, "branch target")

		return
	}

	a.emit32(uint32(int32(rel)))
}

// nearLen returns the number of opcode bytes of a rel32 branch.
func nearLen(nearEsc byte) int {
	if nearEsc != 0 {
		return 2
	}

	return 1
}
