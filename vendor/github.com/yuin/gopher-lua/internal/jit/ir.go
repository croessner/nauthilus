// Package jit contains the architecture independent parts of the native
// JIT compiler: a typed SSA intermediate representation, optimization
// passes, a linear scan register allocator and a code emitter that drives
// an architecture specific macro assembler.
//
// The package knows nothing about Lua. The front end (in the root
// package) translates bytecode into this IR; guards and other exits carry
// opaque snapshot descriptions that the front end interprets after an
// exit was taken.
package jit

import (
	"fmt"
	"math"
	"strings"
)

// Type is the machine level type of an SSA value.
type Type uint8

const (
	// TInt is a 64-bit integer (also used for booleans and raw addresses).
	TInt Type = iota + 1
	// TFloat is a 64-bit IEEE float.
	TFloat
)

func (t Type) String() string {
	if t == TFloat {
		return "float"
	}
	return "int"
}

// Op is an SSA operation.
type Op uint8

const (
	OpInvalid Op = iota

	OpConst   // Aux: value bits (int64 or float64 bits)
	OpPhi     // one argument per predecessor of the block
	OpCtx     // address of the context frame (pinned register)
	OpRegBase // address of the Lua register window (pinned register)

	// 64-bit integer arithmetic (wrapping)
	OpAdd
	OpSub
	OpMul
	OpAnd
	OpOr
	OpXor
	OpShl // logical shift left; count must be in 0..63
	OpShr // logical shift right; count must be in 0..63
	OpSar // arithmetic shift right; count must be in 0..63
	OpDiv // floor division; the divisor must not be zero
	OpMod // floor modulo; the divisor must not be zero
	OpNeg
	OpNot

	// 64-bit float arithmetic
	OpFAdd
	OpFSub
	OpFMul
	OpFDiv
	OpFNeg
	OpFSqrt
	OpFAbs
	OpFFloor
	OpFCeil

	// conversions
	OpIntToFloat
	OpFloatToInt // truncates toward zero (result undefined when out of range)

	// comparisons; the result is the integer 0 or 1
	OpEq
	OpNe
	OpLt  // signed
	OpLe  // signed
	OpULt // unsigned
	OpFEq // ordered (false if either operand is NaN)
	OpFNe // unordered or not equal
	OpFLt // ordered
	OpFLe // ordered

	// memory; Args[0] is the base address, Aux the displacement
	OpLoad64
	OpLoad32 // zero extends
	OpLoad8  // zero extends
	OpLoadF64
	OpStore64  // Args: base, value
	OpStoreF64 // Args: base, value

	// exits
	OpGuard   // Args[0]: condition that must be true; Exit: deoptimization
	OpCallout // Exit: leave to Go, then resume behind this instruction
	OpFuel    // Exit: count down the fuel counter; leave and resume at zero

	opCount
)

var opNames = [...]string{
	OpInvalid: "Invalid", OpConst: "Const", OpPhi: "Phi", OpCtx: "Ctx", OpRegBase: "RegBase",
	OpAdd: "Add", OpSub: "Sub", OpMul: "Mul", OpAnd: "And", OpOr: "Or", OpXor: "Xor",
	OpShl: "Shl", OpShr: "Shr", OpSar: "Sar", OpDiv: "Div", OpMod: "Mod", OpNeg: "Neg", OpNot: "Not",
	OpFAdd: "FAdd", OpFSub: "FSub", OpFMul: "FMul", OpFDiv: "FDiv", OpFNeg: "FNeg",
	OpFSqrt: "FSqrt", OpFAbs: "FAbs", OpFFloor: "FFloor", OpFCeil: "FCeil",
	OpIntToFloat: "IntToFloat", OpFloatToInt: "FloatToInt",
	OpEq: "Eq", OpNe: "Ne", OpLt: "Lt", OpLe: "Le", OpULt: "ULt",
	OpFEq: "FEq", OpFNe: "FNe", OpFLt: "FLt", OpFLe: "FLe",
	OpLoad64: "Load64", OpLoad32: "Load32", OpLoad8: "Load8", OpLoadF64: "LoadF64",
	OpStore64: "Store64", OpStoreF64: "StoreF64",
	OpGuard: "Guard", OpCallout: "Callout", OpFuel: "Fuel",
}

func (o Op) String() string {
	if int(o) < len(opNames) && opNames[o] != "" {
		return opNames[o]
	}
	return fmt.Sprintf("Op(%d)", int(o))
}

// IsCompare reports whether the operation is a comparison.
func (o Op) IsCompare() bool { return o >= OpEq && o <= OpFLe }

// IsFloatCompare reports whether the operation compares floats.
func (o Op) IsFloatCompare() bool { return o >= OpFEq && o <= OpFLe }

// IsLoad reports whether the operation reads memory.
func (o Op) IsLoad() bool { return o >= OpLoad64 && o <= OpLoadF64 }

// HasEffect reports whether the operation must be kept even if its result
// is unused.
func (o Op) HasEffect() bool {
	switch o {
	case OpStore64, OpStoreF64, OpGuard, OpCallout, OpFuel:
		return true
	}
	return false
}

// IsPure reports whether the operation depends only on its arguments.
func (o Op) IsPure() bool {
	if o.HasEffect() || o.IsLoad() {
		return false
	}
	switch o {
	case OpPhi, OpInvalid:
		return false
	}
	return true
}

// HasResult reports whether the operation produces a value.
func (o Op) HasResult() bool {
	return !o.HasEffect()
}

// ExitKind classifies an exit from native code.
type ExitKind uint8

const (
	// ExitDeopt abandons the native code; the interpreter continues.
	ExitDeopt ExitKind = iota
	// ExitCallout runs a Go service and resumes the native code.
	ExitCallout
	// ExitFuel is a safe point taken when the fuel counter reaches zero.
	ExitFuel
)

// SnapEntry describes one value that Go code needs after an exit. Slot and
// Tag are opaque to this package.
type SnapEntry struct {
	Slot int
	Tag  uint8
	Val  *Value
}

// Exit describes an exit point of the compiled code.
type Exit struct {
	ID   int
	Kind ExitKind
	// PC and Data are opaque front end data.
	PC   int
	Data int
	Snap []SnapEntry
}

// Value is an SSA value.
type Value struct {
	ID    int
	Op    Op
	Type  Type
	Args  []*Value
	Aux   int64
	Block *Block
	Exit  *Exit
	// Mem classifies the memory a load reads or a store writes (see the
	// Mem constants); it decides which loads can be reused.
	Mem uint8

	// analysis results
	uses  int
	fused bool // comparison emitted at its single use
	// register allocation
	loc        Loc
	start, end int
	hint       *Value
}

// Memory classes of loads and stores. A load can be replaced by an
// earlier load of the same address in the same block if no store of its
// class and no callout lies in between.
const (
	// MemNone is unclassified memory: such a load is never reused, such
	// a store invalidates every earlier load.
	MemNone uint8 = iota
	// MemStable is memory that compiled code never writes.
	MemStable
	// MemArrayLen is the length word of an unboxed array part.
	MemArrayLen
	// MemArray is an element of an unboxed array part.
	MemArray
	// MemField is the number or kind word of a table field.
	MemField
)

// BlockKind is the kind of a basic block terminator.
type BlockKind uint8

const (
	// BlockJump has one successor.
	BlockJump BlockKind = iota
	// BlockIf branches to Succs[0] if Control is non-zero, else to Succs[1].
	BlockIf
	// BlockExit leaves the native code unconditionally through Exit.
	BlockExit
)

// Block is a basic block.
type Block struct {
	ID      int
	Kind    BlockKind
	Values  []*Value
	Control *Value
	Exit    *Exit
	Succs   []*Block
	Preds   []*Block

	// analysis
	order           int
	liveIn, liveOut bitset
	start, end      int
}

// Func is a unit of compilation.
type Func struct {
	Name   string
	Blocks []*Block
	Entry  *Block
	Exits  []*Exit

	nextValue int
	nextBlock int
	ctx, base *Value
}

// NewFunc creates an empty function with an entry block.
func NewFunc(name string) *Func {
	f := &Func{Name: name}
	f.Entry = f.NewBlock()
	return f
}

// NewBlock appends a new block.
func (f *Func) NewBlock() *Block {
	b := &Block{ID: f.nextBlock}
	f.nextBlock++
	f.Blocks = append(f.Blocks, b)
	return b
}

// NewExit registers an exit description.
func (f *Func) NewExit(kind ExitKind, pc int) *Exit {
	e := &Exit{ID: len(f.Exits), Kind: kind, PC: pc}
	f.Exits = append(f.Exits, e)
	return e
}

func (f *Func) newValue(b *Block, op Op, typ Type, aux int64, args ...*Value) *Value {
	v := &Value{ID: f.nextValue, Op: op, Type: typ, Aux: aux, Block: b}
	f.nextValue++
	if len(args) > 0 {
		v.Args = append(make([]*Value, 0, len(args)), args...)
	}
	return v
}

// NewValue appends a value to block b.
func (f *Func) NewValue(b *Block, op Op, typ Type, aux int64, args ...*Value) *Value {
	v := f.newValue(b, op, typ, aux, args...)
	b.Values = append(b.Values, v)
	return v
}

// NewPhi inserts a phi at the start of block b (after other phis).
func (f *Func) NewPhi(b *Block, typ Type) *Value {
	v := f.newValue(b, OpPhi, typ, 0)
	i := 0
	for i < len(b.Values) && b.Values[i].Op == OpPhi {
		i++
	}
	b.Values = append(b.Values, nil)
	copy(b.Values[i+1:], b.Values[i:])
	b.Values[i] = v
	return v
}

// ConstInt creates an integer constant in block b.
func (f *Func) ConstInt(b *Block, c int64) *Value {
	return f.NewValue(b, OpConst, TInt, c)
}

// ConstFloat creates a float constant in block b.
func (f *Func) ConstFloat(b *Block, c float64) *Value {
	return f.NewValue(b, OpConst, TFloat, int64(math.Float64bits(c)))
}

// Ctx returns the value denoting the context frame address.
func (f *Func) Ctx() *Value {
	if f.ctx == nil {
		f.ctx = f.newValue(f.Entry, OpCtx, TInt, 0)
	}
	return f.ctx
}

// RegBase returns the value denoting the Lua register window address.
func (f *Func) RegBase() *Value {
	if f.base == nil {
		f.base = f.newValue(f.Entry, OpRegBase, TInt, 0)
	}
	return f.base
}

// AddEdge adds a control flow edge.
func AddEdge(from, to *Block) {
	from.Succs = append(from.Succs, to)
	to.Preds = append(to.Preds, from)
}

// IsConst reports whether v is a constant.
func (v *Value) IsConst() bool { return v.Op == OpConst }

// Float returns the float value of a float constant.
func (v *Value) Float() float64 { return math.Float64frombits(uint64(v.Aux)) }

func (v *Value) String() string {
	return fmt.Sprintf("v%d", v.ID)
}

// LongString returns a readable description of the value.
func (v *Value) LongString() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "v%d = %s", v.ID, v.Op)
	switch v.Op {
	case OpConst:
		if v.Type == TFloat {
			fmt.Fprintf(&sb, " %v", v.Float())
		} else {
			fmt.Fprintf(&sb, " %d", v.Aux)
		}
	default:
		if v.Aux != 0 {
			fmt.Fprintf(&sb, " [%d]", v.Aux)
		}
	}
	for _, a := range v.Args {
		fmt.Fprintf(&sb, " %s", a)
	}
	if v.Exit != nil {
		fmt.Fprintf(&sb, " exit#%d(pc=%d", v.Exit.ID, v.Exit.PC)
		for _, s := range v.Exit.Snap {
			fmt.Fprintf(&sb, " r%d:%s", s.Slot, s.Val)
		}
		sb.WriteString(")")
	}
	fmt.Fprintf(&sb, " <%s>", v.Type)
	if v.loc.Kind != LocNone {
		fmt.Fprintf(&sb, " @%s", v.loc)
	}
	return sb.String()
}

// String returns a readable dump of the function.
func (f *Func) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "func %s\n", f.Name)
	for _, b := range f.Blocks {
		fmt.Fprintf(&sb, "b%d:", b.ID)
		if len(b.Preds) > 0 {
			sb.WriteString(" <-")
			for _, p := range b.Preds {
				fmt.Fprintf(&sb, " b%d", p.ID)
			}
		}
		sb.WriteString("\n")
		for _, v := range b.Values {
			fmt.Fprintf(&sb, "  %s\n", v.LongString())
		}
		switch b.Kind {
		case BlockJump:
			if len(b.Succs) > 0 {
				fmt.Fprintf(&sb, "  jump b%d\n", b.Succs[0].ID)
			}
		case BlockIf:
			fmt.Fprintf(&sb, "  if %s then b%d else b%d\n", b.Control, b.Succs[0].ID, b.Succs[1].ID)
		case BlockExit:
			fmt.Fprintf(&sb, "  exit#%d(pc=%d)\n", b.Exit.ID, b.Exit.PC)
		}
	}
	return sb.String()
}

// Verify checks structural invariants of the function.
func (f *Func) Verify() error {
	defined := make(map[*Value]bool)
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Block != b {
				return fmt.Errorf("%s: value %s has wrong block", f.Name, v)
			}
			defined[v] = true
		}
	}
	if f.ctx != nil {
		defined[f.ctx] = true
	}
	if f.base != nil {
		defined[f.base] = true
	}
	checkArg := func(v, a *Value) error {
		if a == nil {
			return fmt.Errorf("%s: %s has a nil argument", f.Name, v.LongString())
		}
		if !defined[a] {
			return fmt.Errorf("%s: %s uses undefined %s", f.Name, v.LongString(), a)
		}
		return nil
	}
	for _, b := range f.Blocks {
		switch b.Kind {
		case BlockJump:
			if len(b.Succs) != 1 {
				return fmt.Errorf("%s: b%d: jump block needs one successor", f.Name, b.ID)
			}
		case BlockIf:
			if len(b.Succs) != 2 || b.Control == nil {
				return fmt.Errorf("%s: b%d: malformed if block", f.Name, b.ID)
			}
			if !defined[b.Control] {
				return fmt.Errorf("%s: b%d: undefined control", f.Name, b.ID)
			}
		case BlockExit:
			if len(b.Succs) != 0 || b.Exit == nil {
				return fmt.Errorf("%s: b%d: malformed exit block", f.Name, b.ID)
			}
		}
		seenNonPhi := false
		for _, v := range b.Values {
			if v.Op == OpPhi {
				if seenNonPhi {
					return fmt.Errorf("%s: b%d: phi %s after non-phi", f.Name, b.ID, v)
				}
				if len(v.Args) != len(b.Preds) {
					return fmt.Errorf("%s: b%d: phi %s has %d args for %d preds", f.Name, b.ID, v, len(v.Args), len(b.Preds))
				}
				for _, a := range v.Args {
					if err := checkArg(v, a); err != nil {
						return err
					}
					if a.Type != v.Type {
						return fmt.Errorf("%s: phi %s mixes types", f.Name, v)
					}
				}
				continue
			}
			seenNonPhi = true
			for _, a := range v.Args {
				if err := checkArg(v, a); err != nil {
					return err
				}
			}
			if v.Op.HasEffect() && v.Op != OpStore64 && v.Op != OpStoreF64 && v.Exit == nil {
				return fmt.Errorf("%s: %s has no exit", f.Name, v.LongString())
			}
			if v.Exit != nil {
				for _, s := range v.Exit.Snap {
					if s.Val == nil || !defined[s.Val] {
						return fmt.Errorf("%s: %s has an undefined snapshot value", f.Name, v.LongString())
					}
				}
			}
		}
		if b.Exit != nil {
			for _, s := range b.Exit.Snap {
				if s.Val == nil || !defined[s.Val] {
					return fmt.Errorf("%s: b%d exit has an undefined snapshot value", f.Name, b.ID)
				}
			}
		}
	}
	return nil
}

// bitset is a simple growable bit set indexed by value ID.
type bitset []uint64

func newBitset(n int) bitset { return make(bitset, (n+63)/64) }

func (s bitset) has(i int) bool { return s[i>>6]&(1<<(uint(i)&63)) != 0 }
func (s bitset) set(i int)      { s[i>>6] |= 1 << (uint(i) & 63) }
func (s bitset) clear(i int)    { s[i>>6] &^= 1 << (uint(i) & 63) }

// orWith merges o into s and reports whether s changed.
func (s bitset) orWith(o bitset) bool {
	changed := false
	for i, w := range o {
		if n := s[i] | w; n != s[i] {
			s[i] = n
			changed = true
		}
	}
	return changed
}

func (s bitset) copyFrom(o bitset) { copy(s, o) }
