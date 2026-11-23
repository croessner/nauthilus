package amd64

// Opcode escape sequences.
const (
	escNone byte = iota // one-byte opcode map
	esc0F               // two-byte opcode map (0F xx)
	esc0F3A             // three-byte opcode map (0F 3A xx)
)

// Legacy prefixes that act as mandatory prefixes of SSE instructions.
const (
	pfx66 byte = 0x66
	pfxF2 byte = 0xF2
)

// Bits of the REX prefix.
const (
	rexBase byte = 0x40
	rexW    byte = 0x08
)

// regMax is the highest valid register number for any register class.
const regMax = 15

// inst describes the fixed part of an instruction encoding: everything that
// precedes the ModRM byte except the operand-dependent REX.R/X/B bits.
type inst struct {
	pfx byte // mandatory prefix, 0 if none; always emitted before REX
	esc byte // opcode escape (escNone, esc0F, esc0F3A)
	op  byte // opcode byte
	w   bool // REX.W: 64-bit operand size
}

// op64 is a one-byte opcode with 64-bit operand size.
func op64(op byte) inst {
	return inst{op: op, w: true}
}

// op32 is a one-byte opcode with the default (32-bit) operand size.
func op32(op byte) inst {
	return inst{op: op}
}

// op0F is a two-byte (0F xx) opcode with the default operand size.
func op0F(op byte) inst {
	return inst{esc: esc0F, op: op}
}

// op0F64 is a two-byte (0F xx) opcode with 64-bit operand size.
func op0F64(op byte) inst {
	return inst{esc: esc0F, op: op, w: true}
}

// sse is a two-byte (0F xx) opcode with a mandatory prefix.
func sse(pfx, op byte) inst {
	return inst{pfx: pfx, esc: esc0F, op: op}
}

// sse64 is a two-byte (0F xx) opcode with a mandatory prefix and REX.W.
func sse64(pfx, op byte) inst {
	return inst{pfx: pfx, esc: esc0F, op: op, w: true}
}

// fitsInt8 reports whether v can be encoded as a sign-extended imm8/disp8.
func fitsInt8(v int32) bool {
	return v >= -128 && v <= 127
}

// emit1 appends one byte.
func (a *Assembler) emit1(b byte) {
	a.buf = append(a.buf, b)
}

// emit2 appends two bytes.
func (a *Assembler) emit2(b0, b1 byte) {
	a.buf = append(a.buf, b0, b1)
}

// emit32 appends a 32-bit little-endian value.
func (a *Assembler) emit32(v uint32) {
	a.buf = append(a.buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// emit64 appends a 64-bit little-endian value.
func (a *Assembler) emit64(v uint64) {
	a.buf = append(a.buf,
		byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

// emitImm8or32 appends imm as imm8 when it fits, otherwise as imm32. It must
// be paired with an opcode chosen by the same fitsInt8 test.
func (a *Assembler) emitImm8or32(imm int32) {
	if fitsInt8(imm) {
		a.emit1(byte(imm))

		return
	}

	a.emit32(uint32(imm))
}

// head emits the mandatory prefix, the REX prefix (when needed) and the opcode
// bytes. reg, index and base are full 4-bit register numbers whose high bits
// become REX.R, REX.X and REX.B. forceREX requests an otherwise empty REX
// prefix, which selects SPL/BPL/SIL/DIL instead of AH/CH/DH/BH for byte
// register operands numbered 4..7.
func (a *Assembler) head(i inst, reg, index, base uint8, forceREX bool) {
	if i.pfx != 0 {
		a.emit1(i.pfx)
	}

	rex := rexBase | (reg>>3)<<2 | (index>>3)<<1 | base>>3
	if i.w {
		rex |= rexW
	}

	if rex != rexBase || forceREX {
		a.emit1(rex)
	}

	switch i.esc {
	case esc0F:
		a.emit2(0x0F, i.op)
	case esc0F3A:
		a.buf = append(a.buf, 0x0F, 0x3A, i.op)
	default:
		a.emit1(i.op)
	}
}

// regReg encodes an instruction with a register-direct ModRM byte (mod=11).
// reg is the ModRM.reg operand (or the /digit opcode extension) and rm the
// ModRM.rm register. rmByte marks rm as an 8-bit register operand. It reports
// whether the instruction was emitted; on failure nothing is appended.
func (a *Assembler) regReg(i inst, reg, rm uint8, rmByte bool) bool {
	if reg > regMax || rm > regMax {
		a.fail(ErrInvalidOperand, "register out of range")

		return false
	}

	a.head(i, reg, 0, rm, rmByte && rm >= 4)
	a.emit1(0xC0 | (reg&7)<<3 | rm&7)

	return true
}

// regMem encodes an instruction whose ModRM.rm operand is the memory operand
// m, including the SIB byte and displacement. reg is the ModRM.reg operand (or
// the /digit opcode extension). It reports whether the instruction was
// emitted; on failure nothing is appended.
func (a *Assembler) regMem(i inst, reg uint8, m Mem) bool {
	if reg > regMax {
		a.fail(ErrInvalidOperand, "register out of range")

		return false
	}

	if !m.valid() {
		a.fail(ErrInvalidOperand, "memory operand")

		return false
	}

	base := uint8(m.Base)

	index := uint8(0)
	if m.hasIndex() {
		index = uint8(m.Index)
	}

	a.head(i, reg, index, base, false)

	// mod=00 with rm/base=101 means "no base, disp32" (RIP-relative without a
	// SIB byte), so RBP and R13 always need an explicit displacement.
	var mod byte

	switch {
	case m.Disp == 0 && base&7 != 5:
		mod = 0
	case fitsInt8(m.Disp):
		mod = 1
	default:
		mod = 2
	}

	regBits := (reg & 7) << 3

	// rm=100 selects a SIB byte, so RSP and R12 as base need one even without
	// an index register.
	if m.hasIndex() || base&7 == 4 {
		a.emit2(mod<<6|regBits|4, sib(m, index, base))
	} else {
		a.emit1(mod<<6 | regBits | base&7)
	}

	switch mod {
	case 1:
		a.emit1(byte(m.Disp))
	case 2:
		a.emit32(uint32(m.Disp))
	}

	return true
}

// sib builds the SIB byte for a validated memory operand. Index field 100
// means "no index"; with REX.X set the same field selects R12.
func sib(m Mem, index, base uint8) byte {
	if !m.hasIndex() {
		return 4<<3 | base&7
	}

	var ss byte

	switch m.Scale {
	case 2:
		ss = 1
	case 4:
		ss = 2
	case 8:
		ss = 3
	}

	return ss<<6 | (index&7)<<3 | base&7
}
