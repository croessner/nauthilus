package amd64

// roundModeMax is the highest ROUNDSD immediate with defined bits only
// (bits 0-1 rounding mode, bit 2 use MXCSR, bit 3 suppress precision).
const roundModeMax = 0x0F

// xmmRR emits an SSE instruction with dst in ModRM.reg and src in ModRM.rm.
func (a *Assembler) xmmRR(i inst, dst, src XReg) {
	a.regReg(i, uint8(dst), uint8(src), false)
}

// xmmRM emits an SSE instruction with x in ModRM.reg and a memory operand.
func (a *Assembler) xmmRM(i inst, x XReg, m Mem) {
	a.regMem(i, uint8(x), m)
}

// MovsdXX emits movsd dst, src; only the low 64 bits of dst are replaced.
func (a *Assembler) MovsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x10), dst, src) }

// MovapdXX emits movapd dst, src (full 128-bit register move).
func (a *Assembler) MovapdXX(dst, src XReg) { a.xmmRR(sse(pfx66, 0x28), dst, src) }

// MovsdXM emits movsd dst, qword [m]; the upper half of dst is zeroed.
func (a *Assembler) MovsdXM(dst XReg, m Mem) { a.xmmRM(sse(pfxF2, 0x10), dst, m) }

// MovsdMX emits movsd qword [m], src.
func (a *Assembler) MovsdMX(m Mem, src XReg) { a.xmmRM(sse(pfxF2, 0x11), src, m) }

// AddsdXX emits addsd dst, src.
func (a *Assembler) AddsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x58), dst, src) }

// SubsdXX emits subsd dst, src.
func (a *Assembler) SubsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x5C), dst, src) }

// MulsdXX emits mulsd dst, src.
func (a *Assembler) MulsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x59), dst, src) }

// DivsdXX emits divsd dst, src.
func (a *Assembler) DivsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x5E), dst, src) }

// SqrtsdXX emits sqrtsd dst, src.
func (a *Assembler) SqrtsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x51), dst, src) }

// UcomisdXX emits ucomisd dst, src (unordered compare setting ZF/PF/CF).
func (a *Assembler) UcomisdXX(dst, src XReg) { a.xmmRR(sse(pfx66, 0x2E), dst, src) }

// MinsdXX emits minsd dst, src.
func (a *Assembler) MinsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x5D), dst, src) }

// MaxsdXX emits maxsd dst, src.
func (a *Assembler) MaxsdXX(dst, src XReg) { a.xmmRR(sse(pfxF2, 0x5F), dst, src) }

// AddsdXM emits addsd dst, qword [m].
func (a *Assembler) AddsdXM(dst XReg, m Mem) { a.xmmRM(sse(pfxF2, 0x58), dst, m) }

// SubsdXM emits subsd dst, qword [m].
func (a *Assembler) SubsdXM(dst XReg, m Mem) { a.xmmRM(sse(pfxF2, 0x5C), dst, m) }

// MulsdXM emits mulsd dst, qword [m].
func (a *Assembler) MulsdXM(dst XReg, m Mem) { a.xmmRM(sse(pfxF2, 0x59), dst, m) }

// DivsdXM emits divsd dst, qword [m].
func (a *Assembler) DivsdXM(dst XReg, m Mem) { a.xmmRM(sse(pfxF2, 0x5E), dst, m) }

// UcomisdXM emits ucomisd dst, qword [m].
func (a *Assembler) UcomisdXM(dst XReg, m Mem) { a.xmmRM(sse(pfx66, 0x2E), dst, m) }

// Cvtsi2sdXR emits cvtsi2sd dst, src with a 64-bit integer source.
func (a *Assembler) Cvtsi2sdXR(dst XReg, src Reg) {
	a.regReg(sse64(pfxF2, 0x2A), uint8(dst), uint8(src), false)
}

// Cvttsd2siRX emits cvttsd2si dst, src (truncating) with a 64-bit integer
// destination.
func (a *Assembler) Cvttsd2siRX(dst Reg, src XReg) {
	a.regReg(sse64(pfxF2, 0x2C), uint8(dst), uint8(src), false)
}

// MovqXR emits movq dst, src: the 64 bits of src are copied into the low half
// of dst and the upper half is zeroed.
func (a *Assembler) MovqXR(dst XReg, src Reg) {
	a.regReg(sse64(pfx66, 0x6E), uint8(dst), uint8(src), false)
}

// MovqRX emits movq dst, src: the low 64 bits of src are copied into dst.
func (a *Assembler) MovqRX(dst Reg, src XReg) {
	a.regReg(sse64(pfx66, 0x7E), uint8(src), uint8(dst), false)
}

// XorpdXX emits xorpd dst, src.
func (a *Assembler) XorpdXX(dst, src XReg) { a.xmmRR(sse(pfx66, 0x57), dst, src) }

// AndpdXX emits andpd dst, src.
func (a *Assembler) AndpdXX(dst, src XReg) { a.xmmRR(sse(pfx66, 0x54), dst, src) }

// AndnpdXX emits andnpd dst, src (dst = ^dst & src).
func (a *Assembler) AndnpdXX(dst, src XReg) { a.xmmRR(sse(pfx66, 0x55), dst, src) }

// OrpdXX emits orpd dst, src.
func (a *Assembler) OrpdXX(dst, src XReg) { a.xmmRR(sse(pfx66, 0x56), dst, src) }

// RoundsdXXI emits roundsd dst, src, mode (SSE4.1). mode must be in 0..15.
func (a *Assembler) RoundsdXXI(dst, src XReg, mode uint8) {
	if mode > roundModeMax {
		a.fail(ErrInvalidOperand, "rounding mode out of range")

		return
	}

	if a.regReg(inst{pfx: pfx66, esc: esc0F3A, op: 0x0B}, uint8(dst), uint8(src), false) {
		a.emit1(mode)
	}
}
