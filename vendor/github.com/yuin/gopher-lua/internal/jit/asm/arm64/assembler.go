// Package arm64 is a small, dependency-free AArch64 (A64) machine-code
// encoder. It appends little-endian 32-bit instruction words to a byte buffer
// and resolves label references when the final code is requested.
//
// The package only produces bytes, so it builds and runs on every GOARCH.
//
// Register number 31 is context dependent in A64: it names either the zero
// register (XZR) or the stack pointer (SP). Every emitter documents which of
// the two meanings applies to each of its operands.
//
// Invalid operands (unencodable immediates or offsets, out-of-range register
// numbers, shift amounts above 63, ...) never produce a wrong encoding. The
// emitter records the first such problem, appends a permanently undefined
// instruction (UDF #0) as a placeholder so that Len keeps advancing by one
// word, and Bytes reports the recorded error.
package arm64

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Reg is a general purpose register number. Values 0..30 name X0..X30; 31
// names XZR or SP depending on the instruction.
type Reg uint8

// General purpose registers X0..X30.
const (
	X0 Reg = iota
	X1
	X2
	X3
	X4
	X5
	X6
	X7
	X8
	X9
	X10
	X11
	X12
	X13
	X14
	X15
	X16
	X17
	X18
	X19
	X20
	X21
	X22
	X23
	X24
	X25
	X26
	X27
	X28
	X29
	X30
)

// Register number 31. XZR and SP share the encoding; the instruction decides
// which one is meant.
const (
	XZR Reg = 31
	SP  Reg = 31
)

// VReg is a SIMD and floating point register number, always used here as a
// scalar double precision (D) register.
type VReg uint8

// Floating point registers V0..V31.
const (
	V0 VReg = iota
	V1
	V2
	V3
	V4
	V5
	V6
	V7
	V8
	V9
	V10
	V11
	V12
	V13
	V14
	V15
	V16
	V17
	V18
	V19
	V20
	V21
	V22
	V23
	V24
	V25
	V26
	V27
	V28
	V29
	V30
	V31
)

// Cond is an A64 condition code.
type Cond uint8

// Condition codes in their A64 encoding.
const (
	CondEQ Cond = iota // equal
	CondNE             // not equal
	CondHS             // unsigned higher or same (carry set)
	CondLO             // unsigned lower (carry clear)
	CondMI             // negative
	CondPL             // positive or zero
	CondVS             // overflow
	CondVC             // no overflow
	CondHI             // unsigned higher
	CondLS             // unsigned lower or same
	CondGE             // signed greater or equal
	CondLT             // signed less
	CondGT             // signed greater
	CondLE             // signed less or equal
	CondAL             // always
)

// Negate returns the condition that holds exactly when c does not.
//
// CondAL has no negation: A64 has no "never" condition (encoding 0b1111 also
// means always). Negate therefore returns CondAL, and any other out-of-range
// value, unchanged; callers must not rely on negating CondAL.
func (c Cond) Negate() Cond {
	if c >= CondAL {
		return c
	}

	return c ^ 1
}

// Label identifies a code position that branches can refer to before or after
// it has been bound.
type Label int

// Errors wrapped by the error that Bytes returns.
var (
	// ErrOperand reports an operand that the requested instruction cannot encode.
	ErrOperand = errors.New("arm64: invalid operand")
	// ErrLabel reports a label that was never created or was bound twice.
	ErrLabel = errors.New("arm64: invalid label")
	// ErrUnboundLabel reports a branch to a label that was never bound.
	ErrUnboundLabel = errors.New("arm64: unbound label")
	// ErrBranchRange reports a branch whose target is too far away.
	ErrBranchRange = errors.New("arm64: branch out of range")
)

const (
	// instrSize is the size of every A64 instruction in bytes.
	instrSize = 4
	// maxReg is the highest valid register number.
	maxReg = 31
	// undefinedInstr is UDF #0, emitted in place of an unencodable instruction.
	undefinedInstr = 0x00000000
	// unbound marks a label without a position.
	unbound = -1
)

// fixupKind selects the immediate field a label reference is patched into.
type fixupKind uint8

const (
	// fixupImm26 is the B form: signed word offset in bits 25:0.
	fixupImm26 fixupKind = iota
	// fixupImm19 is the B.cond/CBZ/CBNZ form: signed word offset in bits 23:5.
	fixupImm19
)

// fixup records one label reference that Bytes resolves.
type fixup struct {
	off   int
	label Label
	kind  fixupKind
}

// Assembler accumulates A64 instructions. The zero value is not ready for
// use; create instances with New. An Assembler is not safe for concurrent use.
type Assembler struct {
	err    error
	buf    []byte
	labels []int
	fixups []fixup
}

// New returns an empty Assembler.
func New() *Assembler {
	return &Assembler{}
}

// Len returns the number of bytes emitted so far. It is always a multiple of 4.
func (a *Assembler) Len() int {
	return len(a.buf)
}

// Reset discards all code, labels, fixups and recorded errors while keeping
// the allocated buffers for reuse. Slices returned by earlier Bytes calls must
// not be used afterwards.
func (a *Assembler) Reset() {
	a.err = nil
	a.buf = a.buf[:0]
	a.labels = a.labels[:0]
	a.fixups = a.fixups[:0]
}

// Err returns the first encoding error recorded so far, or nil. It does not
// look at unresolved labels; only Bytes does.
func (a *Assembler) Err() error {
	return a.err
}

// NewLabel creates a new, unbound label.
func (a *Assembler) NewLabel() Label {
	a.labels = append(a.labels, unbound)

	return Label(len(a.labels) - 1)
}

// Bind binds l to the current end of the code. Binding an unknown label or
// binding a label twice records an error.
func (a *Assembler) Bind(l Label) {
	if !a.validLabel(l) {
		a.fail(ErrLabel, "Bind", "label %d was not created by NewLabel", int(l))

		return
	}

	if a.labels[l] != unbound {
		a.fail(ErrLabel, "Bind", "label %d is already bound at offset %d", int(l), a.labels[l])

		return
	}

	a.labels[l] = len(a.buf)
}

// LabelOffset returns the byte offset l is bound to, or -1 if l is unbound or
// unknown.
func (a *Assembler) LabelOffset(l Label) int {
	if !a.validLabel(l) {
		return unbound
	}

	return a.labels[l]
}

// Bytes resolves all label references and returns the encoded instructions.
//
// It returns an error if an emitter recorded an invalid operand, if a
// referenced label is unbound, or if a branch target is out of range. The
// returned slice aliases the internal buffer: it stays valid only until the
// next emitter call or Reset. Bytes may be called repeatedly.
func (a *Assembler) Bytes() ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}

	for i := range a.fixups {
		if err := a.resolve(&a.fixups[i]); err != nil {
			return nil, err
		}
	}

	return a.buf, nil
}

// Word appends a raw 32-bit word, for example literal data or an instruction
// this package has no emitter for.
func (a *Assembler) Word(w uint32) {
	a.emit(w)
}

// validLabel reports whether l was created by NewLabel since the last Reset.
func (a *Assembler) validLabel(l Label) bool {
	return l >= 0 && int(l) < len(a.labels)
}

// emit appends one little-endian instruction word.
func (a *Assembler) emit(w uint32) {
	a.buf = binary.LittleEndian.AppendUint32(a.buf, w)
}

// fail records the first error of the assembly session; later ones are dropped.
func (a *Assembler) fail(kind error, op, format string, args ...any) {
	if a.err != nil {
		return
	}

	a.err = fmt.Errorf("%w: %s at offset %d: %s", kind, op, len(a.buf), fmt.Sprintf(format, args...))
}

// reject records an operand error for op and emits the placeholder word that
// keeps the instruction count stable.
func (a *Assembler) reject(op, format string, args ...any) {
	a.fail(ErrOperand, op, format, args...)
	a.emit(undefinedInstr)
}

// regs3 emits opc with three 5-bit register fields: m in bits 20:16, n in
// bits 9:5 and d in bits 4:0. Callers pass 0 for fields that opc already fixes
// or does not have. Register numbers above 31 are rejected.
func (a *Assembler) regs3(op string, opc uint32, d, n, m uint8) {
	if d|n|m > maxReg {
		a.reject(op, "register number out of range (%d, %d, %d)", d, n, m)

		return
	}

	a.emit(opc | uint32(m)<<16 | uint32(n)<<5 | uint32(d))
}

// resolve patches the branch immediate of one fixup with the distance to its
// label, after checking that the label is bound and the distance fits.
func (a *Assembler) resolve(f *fixup) error {
	target := a.labels[f.label]
	if target == unbound {
		return fmt.Errorf("%w: label %d referenced at offset %d", ErrUnboundLabel, int(f.label), f.off)
	}

	bits, shift := uint(26), uint(0)
	if f.kind == fixupImm19 {
		bits, shift = 19, 5
	}

	words := (target - f.off) / instrSize
	limit := 1 << (bits - 1)

	if words < -limit || words >= limit {
		return fmt.Errorf("%w: offset %d to label %d at offset %d does not fit a signed %d-bit word offset",
			ErrBranchRange, f.off, int(f.label), target, bits)
	}

	mask := uint32(1)<<bits - 1
	pos := a.buf[f.off : f.off+instrSize]
	w := binary.LittleEndian.Uint32(pos)
	w = w&^(mask<<shift) | (uint32(words)&mask)<<shift
	binary.LittleEndian.PutUint32(pos, w)

	return nil
}
