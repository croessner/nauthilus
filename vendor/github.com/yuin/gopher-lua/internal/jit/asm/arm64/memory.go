package arm64

// Opcodes of the load/store instructions with all operand fields zero. Each
// base+displacement access has a scaled unsigned-offset form (imm12 in bits
// 21:10, in units of the access size) and an unscaled form (signed imm9 in
// bits 20:12, in bytes; LDUR/STUR).
const (
	opLdrX   = 0xF9400000 // ldr xt, [xn, #pimm]
	opLdurX  = 0xF8400000 // ldur xt, [xn, #simm]
	opStrX   = 0xF9000000
	opSturX  = 0xF8000000
	opLdrW   = 0xB9400000 // ldr wt, [xn, #pimm]
	opLdurW  = 0xB8400000
	opStrW   = 0xB9000000
	opSturW  = 0xB8000000
	opLdrB   = 0x39400000 // ldrb wt, [xn, #pimm]
	opLdurB  = 0x38400000
	opLdrD   = 0xFD400000 // ldr dt, [xn, #pimm]
	opLdurD  = 0xFC400000
	opStrD   = 0xFD000000
	opSturD  = 0xFC000000
	opLdrXRR = 0xF8606800 // ldr xt, [xn, xm] (option=LSL, S=0)
	opStrXRR = 0xF8206800
	opLdrDRR = 0xFC606800 // ldr dt, [xn, xm]
	opStrDRR = 0xFC206800

	// idxScaleBit is the S bit of the register-offset forms: shift the index
	// left by log2 of the access size.
	idxScaleBit = 1 << 12
)

const (
	// Access size as log2 of the byte count, the scale of the unsigned-offset form.
	scaleByte = 0
	scaleWord = 2
	scaleQuad = 3

	// Limits of the two displacement forms.
	scaledImmMax = 0xFFF
	unscaledMin  = -256
	unscaledMax  = 255
	unscaledMask = 0x1FF
)

// offForm is the addressing form that can encode a displacement.
type offForm uint8

const (
	offNone offForm = iota
	offScaled
	offUnscaled
)

// classifyOff picks the addressing form for displacement off of an access of
// 1<<scale bytes: the scaled unsigned-offset form when off is a non-negative
// multiple of the access size up to 4095 units, else the unscaled form for
// -256..255, else none.
func classifyOff(off int32, scale uint) offForm {
	switch {
	case off >= 0 && off&(1<<scale-1) == 0 && off>>scale <= scaledImmMax:
		return offScaled
	case off >= unscaledMin && off <= unscaledMax:
		return offUnscaled
	default:
		return offNone
	}
}

// MemOffOK64 reports whether off is encodable by the 64-bit accesses LdrRM,
// StrRM, LdrDM and StrDM: a multiple of 8 in 0..32760, or any value in
// -256..255.
func MemOffOK64(off int32) bool {
	return classifyOff(off, scaleQuad) != offNone
}

// LdrRM emits a 64-bit load: ldr xt, [base, #off], or ldur when off is not a
// non-negative multiple of 8. off must satisfy MemOffOK64. Register 31 is SP
// for base and XZR for dst.
func (a *Assembler) LdrRM(dst, base Reg, off int32) {
	a.memOff("LdrRM", opLdrX, opLdurX, scaleQuad, uint8(dst), base, off)
}

// StrRM emits a 64-bit store: str xt, [base, #off], or stur. off must satisfy
// MemOffOK64. Register 31 is SP for base and XZR for src.
func (a *Assembler) StrRM(src, base Reg, off int32) {
	a.memOff("StrRM", opStrX, opSturX, scaleQuad, uint8(src), base, off)
}

// LdrRM32 emits a 32-bit zero-extending load: ldr wt, [base, #off] for
// multiples of 4 in 0..16380, else ldur for -256..255. Register 31 is SP for
// base and XZR for dst.
func (a *Assembler) LdrRM32(dst, base Reg, off int32) {
	a.memOff("LdrRM32", opLdrW, opLdurW, scaleWord, uint8(dst), base, off)
}

// StrRM32 emits a 32-bit store of the low half of src: str wt, [base, #off]
// for multiples of 4 in 0..16380, else stur for -256..255. Register 31 is SP
// for base and XZR for src.
func (a *Assembler) StrRM32(src, base Reg, off int32) {
	a.memOff("StrRM32", opStrW, opSturW, scaleWord, uint8(src), base, off)
}

// LdrbRM emits a zero-extending byte load: ldrb wt, [base, #off] for 0..4095,
// else ldurb for -256..-1. Register 31 is SP for base and XZR for dst.
func (a *Assembler) LdrbRM(dst, base Reg, off int32) {
	a.memOff("LdrbRM", opLdrB, opLdurB, scaleByte, uint8(dst), base, off)
}

// LdrRMIdx emits ldr xt, [base, index, lsl #3] if scaled, else
// ldr xt, [base, index]. Register 31 is SP for base and XZR for dst and index.
func (a *Assembler) LdrRMIdx(dst, base, index Reg, scaled bool) {
	a.memIdx("LdrRMIdx", opLdrXRR, uint8(dst), base, index, scaled)
}

// StrRMIdx emits str xt, [base, index, lsl #3] if scaled, else
// str xt, [base, index]. Register 31 is SP for base and XZR for src and index.
func (a *Assembler) StrRMIdx(src, base, index Reg, scaled bool) {
	a.memIdx("StrRMIdx", opStrXRR, uint8(src), base, index, scaled)
}

// memOff emits a base+displacement access of 1<<scale bytes for transfer
// register rt, using scaledOpc or unscaledOpc as classifyOff decides.
func (a *Assembler) memOff(op string, scaledOpc, unscaledOpc uint32, scale uint, rt uint8, base Reg, off int32) {
	switch classifyOff(off, scale) {
	case offScaled:
		a.regs3(op, scaledOpc|uint32(off>>scale)<<10, rt, uint8(base), 0)
	case offUnscaled:
		a.regs3(op, unscaledOpc|(uint32(off)&unscaledMask)<<12, rt, uint8(base), 0)
	default:
		a.reject(op, "displacement %d is not encodable for a %d-byte access", off, int(1)<<scale)
	}
}

// memIdx emits a base+index access for transfer register rt. The index is a
// 64-bit register, shifted left by the access size when scaled is set.
func (a *Assembler) memIdx(op string, opc uint32, rt uint8, base, index Reg, scaled bool) {
	if scaled {
		opc |= idxScaleBit
	}

	a.regs3(op, opc, rt, uint8(base), uint8(index))
}
