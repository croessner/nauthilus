// Package amd64 implements a small, dependency-free x86-64 machine-code
// encoder for the JIT backend.
//
// Only 64-bit long mode is supported. Instructions are appended to an internal
// byte buffer; branch targets are expressed with labels that are resolved when
// Bytes is called. Encoding methods never return errors directly: the first
// invalid operand is recorded and reported by Bytes (or Err), and the offending
// instruction emits no bytes at all.
//
// Operand order follows Intel syntax: the destination comes first.
package amd64

import (
	"errors"
	"fmt"
	"math"
)

// Reg is a 64-bit general purpose register. The numeric value is the hardware
// register number used in ModRM/SIB/REX fields.
type Reg uint8

// General purpose registers.
const (
	RAX Reg = iota
	RCX
	RDX
	RBX
	RSP
	RBP
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

// XReg is an SSE register (XMM0..XMM15).
type XReg uint8

// SSE registers.
const (
	X0 XReg = iota
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
)

// Cond is an x86 condition code. The numeric value is the condition nibble
// that is added to the Jcc/SETcc/CMOVcc base opcodes.
type Cond uint8

// Condition codes.
const (
	CondO  Cond = iota // overflow
	CondNO             // no overflow
	CondB              // below (unsigned <), carry set
	CondAE             // above or equal (unsigned >=), carry clear
	CondE              // equal, zero set
	CondNE             // not equal, zero clear
	CondBE             // below or equal (unsigned <=)
	CondA              // above (unsigned >)
	CondS              // sign set
	CondNS             // sign clear
	CondP              // parity set (unordered after UCOMISD)
	CondNP             // parity clear
	CondL              // less (signed <)
	CondGE             // greater or equal (signed >=)
	CondLE             // less or equal (signed <=)
	CondG              // greater (signed >)
)

// Negate returns the condition that holds exactly when c does not hold.
func (c Cond) Negate() Cond {
	return c ^ 1
}

// Mem is a memory operand [Base + Index*Scale + Disp].
//
// Scale == 0 means "no index"; Index is ignored in that case. Valid scales are
// 0, 1, 2, 4 and 8. RSP cannot be used as an index register.
type Mem struct {
	Base  Reg
	Index Reg
	Scale uint8
	Disp  int32
}

// M returns the memory operand [base+disp].
func M(base Reg, disp int32) Mem {
	return Mem{Base: base, Disp: disp}
}

// MIdx returns the memory operand [base+index*scale+disp].
func MIdx(base, index Reg, scale uint8, disp int32) Mem {
	return Mem{Base: base, Index: index, Scale: scale, Disp: disp}
}

// hasIndex reports whether the operand uses an index register.
func (m Mem) hasIndex() bool {
	return m.Scale != 0
}

// valid reports whether the operand can be encoded.
func (m Mem) valid() bool {
	if m.Base > R15 {
		return false
	}

	switch m.Scale {
	case 0:
		return true
	case 1, 2, 4, 8:
		return m.Index <= R15 && m.Index != RSP
	default:
		return false
	}
}

// Label identifies a position in the code buffer that branches can target.
// Labels are created with NewLabel and are only valid for the Assembler that
// created them, until its next Reset.
type Label int

// Errors recorded by the Assembler. They are wrapped with positional detail;
// use errors.Is to test for them.
var (
	// ErrInvalidOperand reports an operand that has no valid encoding.
	ErrInvalidOperand = errors.New("amd64: invalid operand")
	// ErrInvalidLabel reports a label that was not created by NewLabel.
	ErrInvalidLabel = errors.New("amd64: invalid label")
	// ErrLabelRebound reports an attempt to bind a label twice.
	ErrLabelRebound = errors.New("amd64: label bound twice")
	// ErrUnboundLabel reports a branch whose target label was never bound.
	ErrUnboundLabel = errors.New("amd64: unbound label")
	// ErrBranchRange reports a branch displacement that does not fit in rel32.
	ErrBranchRange = errors.New("amd64: branch displacement out of range")
)

// unbound marks a label that has not been bound yet.
const unbound = -1

// fixup is a rel32 field that must be patched once its label is bound.
type fixup struct {
	pos   int // offset of the 4-byte displacement field
	label Label
}

// Assembler appends x86-64 machine code to a byte buffer.
//
// An Assembler is not safe for concurrent use. The zero value is ready to use.
type Assembler struct {
	buf    []byte
	labels []int
	fixups []fixup
	err    error
}

// New returns an empty Assembler.
func New() *Assembler {
	return &Assembler{}
}

// Len returns the number of bytes emitted so far.
func (a *Assembler) Len() int {
	return len(a.buf)
}

// Err returns the first encoding error recorded so far, if any.
func (a *Assembler) Err() error {
	return a.err
}

// Reset discards all emitted code, labels, fixups and recorded errors while
// keeping the allocated buffers for reuse.
func (a *Assembler) Reset() {
	a.buf = a.buf[:0]
	a.labels = a.labels[:0]
	a.fixups = a.fixups[:0]
	a.err = nil
}

// NewLabel creates a new, unbound label.
func (a *Assembler) NewLabel() Label {
	a.labels = append(a.labels, unbound)

	return Label(len(a.labels) - 1)
}

// Bind binds l to the current offset. Binding a label twice is an error.
func (a *Assembler) Bind(l Label) {
	if !a.validLabel(l) {
		a.fail(ErrInvalidLabel, "Bind")

		return
	}

	if a.labels[l] != unbound {
		a.fail(ErrLabelRebound, "Bind")

		return
	}

	a.labels[l] = len(a.buf)
}

// LabelOffset returns the offset l is bound to, or -1 if l is unbound or
// invalid.
func (a *Assembler) LabelOffset(l Label) int {
	if !a.validLabel(l) {
		return unbound
	}

	return a.labels[l]
}

// Bytes resolves all pending label references and returns the encoded code.
//
// It fails if any encoding error was recorded earlier or if a referenced label
// is still unbound. The returned slice aliases the internal buffer: it is valid
// until the next call that emits code or resets the Assembler. Bytes may be
// called repeatedly; more code may be emitted between calls.
func (a *Assembler) Bytes() ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}

	for _, f := range a.fixups {
		target := a.labels[f.label]
		if target == unbound {
			return nil, fmt.Errorf("%w: label %d referenced at offset %d", ErrUnboundLabel, f.label, f.pos)
		}

		rel := target - (f.pos + 4)
		if rel < math.MinInt32 || rel > math.MaxInt32 {
			return nil, fmt.Errorf("%w: label %d referenced at offset %d", ErrBranchRange, f.label, f.pos)
		}

		putUint32(a.buf[f.pos:f.pos+4], uint32(int32(rel)))
	}

	return a.buf, nil
}

// validLabel reports whether l was created by NewLabel since the last Reset.
func (a *Assembler) validLabel(l Label) bool {
	return l >= 0 && int(l) < len(a.labels)
}

// fail records the first encoding error. Later errors are dropped because they
// are usually consequences of the first one.
func (a *Assembler) fail(kind error, what string) {
	if a.err == nil {
		a.err = fmt.Errorf("%w: %s at offset %d", kind, what, len(a.buf))
	}
}

// putUint32 stores v in little-endian order into the first four bytes of b.
func putUint32(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
