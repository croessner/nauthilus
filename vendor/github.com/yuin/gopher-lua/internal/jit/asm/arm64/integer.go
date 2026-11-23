package arm64

// Opcodes of the 64-bit (sf=1) integer instructions, with all operand fields
// zero. Field layouts follow the Arm ARM A64 instruction set encoding tables.
const (
	// Shifted register forms with shift type LSL and amount 0.
	opAddReg  = 0x8B000000
	opAddsReg = 0xAB000000
	opSubReg  = 0xCB000000
	opSubsReg = 0xEB000000
	opAndReg  = 0x8A000000
	opOrrReg  = 0xAA000000
	opOrnReg  = 0xAA200000
	opEorReg  = 0xCA000000
	opAndsReg = 0xEA000000

	// Multiply and divide.
	opMadd = 0x9B000000
	opMsub = 0x9B008000
	opSdiv = 0x9AC00C00
	opUdiv = 0x9AC00800

	// Variable shifts.
	opLslv = 0x9AC02000
	opLsrv = 0x9AC02400
	opAsrv = 0x9AC02800

	// Bitfield moves with N=1, the base of the immediate shift aliases.
	opUbfm = 0xD3400000
	opSbfm = 0x93400000

	// Add/subtract immediate.
	opAddImm  = 0x91000000
	opAddsImm = 0xB1000000
	opSubImm  = 0xD1000000
	opSubsImm = 0xF1000000

	// Conditional select.
	opCsel  = 0x9A800000
	opCsinc = 0x9A800400

	// Move wide.
	opMovn = 0x92800000
	opMovz = 0xD2800000
	opMovk = 0xF2800000
)

const (
	// zr is register number 31 as a raw field value.
	zr = uint8(XZR)
	// maxShift is the largest immediate shift amount of a 64-bit register.
	maxShift = 63
	// imm12Max is the largest value of an unshifted add/subtract immediate.
	imm12Max = 0xFFF
	// chunkBits is the width of one move-wide immediate.
	chunkBits = 16
	// chunkMask selects one move-wide immediate.
	chunkMask = 0xFFFF
	// chunkCount is the number of move-wide immediates in a 64-bit value.
	chunkCount = 4
)

// ImmAddSubOK reports whether imm is encodable by AddRI, SubRI, AddsRI,
// SubsRI, CmpRI and CmnRI, that is as a 12-bit value optionally shifted left
// by 12.
func ImmAddSubOK(imm uint32) bool {
	return imm <= imm12Max || (imm&imm12Max == 0 && imm>>12 <= imm12Max)
}

// MovRR emits mov xd, xm (orr xd, xzr, xm). Register 31 is XZR for both
// operands; use AddRI(dst, SP, 0) or AddRI(SP, src, 0) to move from or to SP.
func (a *Assembler) MovRR(dst, src Reg) {
	a.regs3("MovRR", opOrrReg, uint8(dst), zr, uint8(src))
}

// MovRI loads the 64-bit constant imm into dst with the shortest
// MOVZ/MOVN + MOVK sequence (one to four instructions). Register 31 is XZR.
func (a *Assembler) MovRI(dst Reg, imm int64) {
	if dst > maxReg {
		a.reject("MovRI", "register number out of range (%d)", uint8(dst))

		return
	}

	value := uint64(imm)

	var zeros, ones int

	for i := range chunkCount {
		switch (value >> (i * chunkBits)) & chunkMask {
		case 0:
			zeros++
		case chunkMask:
			ones++
		}
	}

	// MOVZ leaves the other chunks zero and MOVN leaves them all ones, so the
	// first instruction is chosen by the more frequent filler chunk.
	first, filler := uint32(opMovz), uint64(0)
	if ones > zeros {
		first, filler = opMovn, chunkMask
	}

	a.movWide(first, filler, dst, value)
}

// movWide emits the move-wide sequence for value: first (MOVZ or MOVN) for
// the lowest chunk that differs from filler, then MOVK for every further such
// chunk. A value made of filler chunks only still needs one instruction.
func (a *Assembler) movWide(first uint32, filler uint64, dst Reg, value uint64) {
	opc := first

	for i := range chunkCount {
		chunk := (value >> (i * chunkBits)) & chunkMask
		if chunk == filler {
			continue
		}

		// MOVN encodes the inverted chunk; MOVZ and MOVK encode it verbatim.
		if opc == opMovn {
			chunk ^= chunkMask
		}

		a.emit(opc | uint32(i)<<21 | uint32(chunk)<<5 | uint32(dst))

		opc = opMovk
	}

	if opc == first {
		a.emit(first | uint32(dst))
	}
}

// AddRR emits add xd, xn, xm. Register 31 is XZR for all operands.
func (a *Assembler) AddRR(dst, n, m Reg) {
	a.regs3("AddRR", opAddReg, uint8(dst), uint8(n), uint8(m))
}

// SubRR emits sub xd, xn, xm (dst = n - m). Register 31 is XZR for all operands.
func (a *Assembler) SubRR(dst, n, m Reg) {
	a.regs3("SubRR", opSubReg, uint8(dst), uint8(n), uint8(m))
}

// AndRR emits and xd, xn, xm. Register 31 is XZR for all operands.
func (a *Assembler) AndRR(dst, n, m Reg) {
	a.regs3("AndRR", opAndReg, uint8(dst), uint8(n), uint8(m))
}

// OrrRR emits orr xd, xn, xm. Register 31 is XZR for all operands.
func (a *Assembler) OrrRR(dst, n, m Reg) {
	a.regs3("OrrRR", opOrrReg, uint8(dst), uint8(n), uint8(m))
}

// EorRR emits eor xd, xn, xm. Register 31 is XZR for all operands.
func (a *Assembler) EorRR(dst, n, m Reg) {
	a.regs3("EorRR", opEorReg, uint8(dst), uint8(n), uint8(m))
}

// AddsRR emits adds xd, xn, xm, setting NZCV. Register 31 is XZR for all operands.
func (a *Assembler) AddsRR(dst, n, m Reg) {
	a.regs3("AddsRR", opAddsReg, uint8(dst), uint8(n), uint8(m))
}

// SubsRR emits subs xd, xn, xm (dst = n - m), setting NZCV. Register 31 is
// XZR for all operands.
func (a *Assembler) SubsRR(dst, n, m Reg) {
	a.regs3("SubsRR", opSubsReg, uint8(dst), uint8(n), uint8(m))
}

// MulRR emits mul xd, xn, xm (madd xd, xn, xm, xzr). Register 31 is XZR for
// all operands.
func (a *Assembler) MulRR(dst, n, m Reg) {
	a.regs3("MulRR", opMadd|uint32(zr)<<10, uint8(dst), uint8(n), uint8(m))
}

// MsubRRRR emits msub xd, xn, xm, xa (dst = ra - n*m). Register 31 is XZR for
// all operands.
func (a *Assembler) MsubRRRR(dst, n, m, ra Reg) {
	if ra > maxReg {
		a.reject("MsubRRRR", "register number out of range (%d)", uint8(ra))

		return
	}

	a.regs3("MsubRRRR", opMsub|uint32(ra)<<10, uint8(dst), uint8(n), uint8(m))
}

// SdivRR emits sdiv xd, xn, xm (dst = n / m, signed). Register 31 is XZR for
// all operands.
func (a *Assembler) SdivRR(dst, n, m Reg) {
	a.regs3("SdivRR", opSdiv, uint8(dst), uint8(n), uint8(m))
}

// UdivRR emits udiv xd, xn, xm (dst = n / m, unsigned). Register 31 is XZR
// for all operands.
func (a *Assembler) UdivRR(dst, n, m Reg) {
	a.regs3("UdivRR", opUdiv, uint8(dst), uint8(n), uint8(m))
}

// NegRR emits neg xd, xm (sub xd, xzr, xm). Register 31 is XZR for both operands.
func (a *Assembler) NegRR(dst, m Reg) {
	a.regs3("NegRR", opSubReg, uint8(dst), zr, uint8(m))
}

// MvnRR emits mvn xd, xm (orn xd, xzr, xm). Register 31 is XZR for both operands.
func (a *Assembler) MvnRR(dst, m Reg) {
	a.regs3("MvnRR", opOrnReg, uint8(dst), zr, uint8(m))
}

// LslRR emits lsl xd, xn, xm (lslv; dst = n << (m & 63)). Register 31 is XZR
// for all operands.
func (a *Assembler) LslRR(dst, n, m Reg) {
	a.regs3("LslRR", opLslv, uint8(dst), uint8(n), uint8(m))
}

// LsrRR emits lsr xd, xn, xm (lsrv; logical dst = n >> (m & 63)). Register 31
// is XZR for all operands.
func (a *Assembler) LsrRR(dst, n, m Reg) {
	a.regs3("LsrRR", opLsrv, uint8(dst), uint8(n), uint8(m))
}

// AsrRR emits asr xd, xn, xm (asrv; arithmetic dst = n >> (m & 63)). Register
// 31 is XZR for all operands.
func (a *Assembler) AsrRR(dst, n, m Reg) {
	a.regs3("AsrRR", opAsrv, uint8(dst), uint8(n), uint8(m))
}

// LslRI emits lsl xd, xn, #shift (ubfm xd, xn, #(-shift mod 64), #(63-shift)).
// shift must be 0..63. Register 31 is XZR for both operands.
func (a *Assembler) LslRI(dst, n Reg, shift uint8) {
	a.bitfield("LslRI", opUbfm, dst, n, shift, (64-shift)&maxShift, maxShift-shift)
}

// LsrRI emits lsr xd, xn, #shift (ubfm xd, xn, #shift, #63). shift must be
// 0..63. Register 31 is XZR for both operands.
func (a *Assembler) LsrRI(dst, n Reg, shift uint8) {
	a.bitfield("LsrRI", opUbfm, dst, n, shift, shift, maxShift)
}

// AsrRI emits asr xd, xn, #shift (sbfm xd, xn, #shift, #63). shift must be
// 0..63. Register 31 is XZR for both operands.
func (a *Assembler) AsrRI(dst, n Reg, shift uint8) {
	a.bitfield("AsrRI", opSbfm, dst, n, shift, shift, maxShift)
}

// bitfield emits a UBFM/SBFM instruction with the given immr and imms fields
// after validating the shift amount the alias was derived from.
func (a *Assembler) bitfield(op string, opc uint32, dst, n Reg, shift, immr, imms uint8) {
	if shift > maxShift {
		a.reject(op, "shift amount %d exceeds %d", shift, maxShift)

		return
	}

	a.regs3(op, opc|uint32(immr)<<16|uint32(imms)<<10, uint8(dst), uint8(n), 0)
}

// AddRI emits add xd, xn, #imm. imm must satisfy ImmAddSubOK. Register 31 is
// SP for both dst and n.
func (a *Assembler) AddRI(dst, n Reg, imm uint32) {
	a.addSubImm("AddRI", opAddImm, dst, n, imm)
}

// SubRI emits sub xd, xn, #imm. imm must satisfy ImmAddSubOK. Register 31 is
// SP for both dst and n.
func (a *Assembler) SubRI(dst, n Reg, imm uint32) {
	a.addSubImm("SubRI", opSubImm, dst, n, imm)
}

// AddsRI emits adds xd, xn, #imm, setting NZCV. imm must satisfy ImmAddSubOK.
// Register 31 is SP for n and XZR for dst.
func (a *Assembler) AddsRI(dst, n Reg, imm uint32) {
	a.addSubImm("AddsRI", opAddsImm, dst, n, imm)
}

// SubsRI emits subs xd, xn, #imm, setting NZCV. imm must satisfy ImmAddSubOK.
// Register 31 is SP for n and XZR for dst.
func (a *Assembler) SubsRI(dst, n Reg, imm uint32) {
	a.addSubImm("SubsRI", opSubsImm, dst, n, imm)
}

// CmpRI emits cmp xn, #imm (subs xzr, xn, #imm). imm must satisfy
// ImmAddSubOK. Register 31 is SP for n.
func (a *Assembler) CmpRI(n Reg, imm uint32) {
	a.addSubImm("CmpRI", opSubsImm, XZR, n, imm)
}

// CmnRI emits cmn xn, #imm (adds xzr, xn, #imm). imm must satisfy
// ImmAddSubOK. Register 31 is SP for n.
func (a *Assembler) CmnRI(n Reg, imm uint32) {
	a.addSubImm("CmnRI", opAddsImm, XZR, n, imm)
}

// addSubImm emits an add/subtract immediate instruction, choosing the
// unshifted imm12 form when possible and the imm12<<12 form otherwise.
func (a *Assembler) addSubImm(op string, opc uint32, dst, n Reg, imm uint32) {
	switch {
	case imm <= imm12Max:
		opc |= imm << 10
	case ImmAddSubOK(imm):
		opc |= 1<<22 | (imm>>12)<<10
	default:
		a.reject(op, "immediate %#x is not an imm12 or imm12<<12", imm)

		return
	}

	a.regs3(op, opc, uint8(dst), uint8(n), 0)
}

// CmpRR emits cmp xn, xm (subs xzr, xn, xm). Register 31 is XZR for both
// operands; comparing SP needs CmpRI or a copy of SP.
func (a *Assembler) CmpRR(n, m Reg) {
	a.regs3("CmpRR", opSubsReg, zr, uint8(n), uint8(m))
}

// TstRR emits tst xn, xm (ands xzr, xn, xm). Register 31 is XZR for both operands.
func (a *Assembler) TstRR(n, m Reg) {
	a.regs3("TstRR", opAndsReg, zr, uint8(n), uint8(m))
}

// Cset emits cset xd, c (csinc xd, xzr, xzr, invert(c)): dst = 1 if c holds,
// else 0. CondAL is rejected because it has no inverse; load the constant 1
// with MovRI instead. Register 31 is XZR for dst.
func (a *Assembler) Cset(dst Reg, c Cond) {
	if c >= CondAL {
		a.reject("Cset", "condition %d has no inverse", uint8(c))

		return
	}

	a.regs3("Cset", opCsinc|uint32(c.Negate())<<12, uint8(dst), zr, zr)
}

// Csel emits csel xd, xn, xm, c: dst = n if c holds, else m. Register 31 is
// XZR for all operands.
func (a *Assembler) Csel(dst, n, m Reg, c Cond) {
	if c > CondAL {
		a.reject("Csel", "condition %d out of range", uint8(c))

		return
	}

	a.regs3("Csel", opCsel|uint32(c)<<12, uint8(dst), uint8(n), uint8(m))
}
