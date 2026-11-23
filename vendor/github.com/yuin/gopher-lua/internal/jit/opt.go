package jit

import (
	"math"
	"math/bits"
)

// Optimize runs the optimization pipeline: unreachable code removal,
// constant folding and algebraic simplification (including strength
// reduction), common subexpression elimination, phi simplification and
// dead code elimination.
func Optimize(f *Func) {
	removeUnreachable(f)
	for round := 0; round < 4; round++ {
		changed := simplify(f)
		changed = cse(f) || changed
		changed = simplifyPhis(f) || changed
		if !changed {
			break
		}
	}
	deadCode(f)
}

// reversePostorder returns the blocks reachable from the entry in reverse
// postorder.
func reversePostorder(f *Func) []*Block {
	seen := make(map[*Block]bool, len(f.Blocks))
	var post []*Block
	type frame struct {
		b *Block
		i int
	}
	stack := []frame{{f.Entry, 0}}
	seen[f.Entry] = true
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.i < len(top.b.Succs) {
			s := top.b.Succs[top.i]
			top.i++
			if !seen[s] {
				seen[s] = true
				stack = append(stack, frame{s, 0})
			}
			continue
		}
		post = append(post, top.b)
		stack = stack[:len(stack)-1]
	}
	for i, j := 0, len(post)-1; i < j; i, j = i+1, j-1 {
		post[i], post[j] = post[j], post[i]
	}
	return post
}

// removeUnreachable drops blocks that cannot be reached from the entry
// and orders the remaining blocks in reverse postorder.
func removeUnreachable(f *Func) {
	rpo := reversePostorder(f)
	live := make(map[*Block]bool, len(rpo))
	for _, b := range rpo {
		live[b] = true
	}
	for _, b := range rpo {
		for i := 0; i < len(b.Preds); {
			if live[b.Preds[i]] {
				i++
				continue
			}
			removePred(b, i)
		}
	}
	f.Blocks = rpo
	for i, b := range f.Blocks {
		b.order = i
	}
}

// removePred removes the i-th predecessor of b together with the matching
// phi arguments.
func removePred(b *Block, i int) {
	b.Preds = append(b.Preds[:i], b.Preds[i+1:]...)
	for _, v := range b.Values {
		if v.Op != OpPhi {
			break
		}
		v.Args = append(v.Args[:i], v.Args[i+1:]...)
	}
}

// replaceUses rewrites every use of the keys of repl by their values.
func replaceUses(f *Func, repl map[*Value]*Value) {
	if len(repl) == 0 {
		return
	}
	resolve := func(v *Value) *Value {
		for {
			n, ok := repl[v]
			if !ok {
				return v
			}
			v = n
		}
	}
	fixExit := func(e *Exit) {
		if e == nil {
			return
		}
		for i := range e.Snap {
			e.Snap[i].Val = resolve(e.Snap[i].Val)
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for i, a := range v.Args {
				v.Args[i] = resolve(a)
			}
			fixExit(v.Exit)
		}
		if b.Control != nil {
			b.Control = resolve(b.Control)
		}
		fixExit(b.Exit)
	}
}

func isPowerOfTwo(c int64) bool { return c > 0 && c&(c-1) == 0 }

// foldConst evaluates a pure operation on constant arguments.
func foldConst(v *Value) (int64, bool) {
	args := v.Args
	for _, a := range args {
		if !a.IsConst() {
			return 0, false
		}
	}
	fbits := func(x float64) int64 { return int64(math.Float64bits(x)) }
	b2i := func(b bool) int64 {
		if b {
			return 1
		}
		return 0
	}
	switch v.Op {
	case OpAdd:
		return args[0].Aux + args[1].Aux, true
	case OpSub:
		return args[0].Aux - args[1].Aux, true
	case OpMul:
		return args[0].Aux * args[1].Aux, true
	case OpAnd:
		return args[0].Aux & args[1].Aux, true
	case OpOr:
		return args[0].Aux | args[1].Aux, true
	case OpXor:
		return args[0].Aux ^ args[1].Aux, true
	case OpShl:
		if c := args[1].Aux; c >= 0 && c < 64 {
			return int64(uint64(args[0].Aux) << uint(c)), true
		}
	case OpShr:
		if c := args[1].Aux; c >= 0 && c < 64 {
			return int64(uint64(args[0].Aux) >> uint(c)), true
		}
	case OpSar:
		if c := args[1].Aux; c >= 0 && c < 64 {
			return args[0].Aux >> uint(c), true
		}
	case OpDiv:
		if d := args[1].Aux; d != 0 {
			return floorDiv(args[0].Aux, d), true
		}
	case OpMod:
		if d := args[1].Aux; d != 0 {
			return floorMod(args[0].Aux, d), true
		}
	case OpNeg:
		return -args[0].Aux, true
	case OpNot:
		return ^args[0].Aux, true
	case OpFAdd:
		return fbits(args[0].Float() + args[1].Float()), true
	case OpFSub:
		return fbits(args[0].Float() - args[1].Float()), true
	case OpFMul:
		return fbits(args[0].Float() * args[1].Float()), true
	case OpFDiv:
		return fbits(args[0].Float() / args[1].Float()), true
	case OpFNeg:
		return fbits(-args[0].Float()), true
	case OpFSqrt:
		return fbits(math.Sqrt(args[0].Float())), true
	case OpFAbs:
		return fbits(math.Abs(args[0].Float())), true
	case OpFFloor:
		return fbits(math.Floor(args[0].Float())), true
	case OpFCeil:
		return fbits(math.Ceil(args[0].Float())), true
	case OpIntToFloat:
		return fbits(float64(args[0].Aux)), true
	case OpFloatToInt:
		if x := args[0].Float(); x >= -9223372036854775808.0 && x < 9223372036854775808.0 {
			return int64(x), true
		}
	case OpEq:
		return b2i(args[0].Aux == args[1].Aux), true
	case OpNe:
		return b2i(args[0].Aux != args[1].Aux), true
	case OpLt:
		return b2i(args[0].Aux < args[1].Aux), true
	case OpLe:
		return b2i(args[0].Aux <= args[1].Aux), true
	case OpULt:
		return b2i(uint64(args[0].Aux) < uint64(args[1].Aux)), true
	case OpFEq:
		return b2i(args[0].Float() == args[1].Float()), true
	case OpFNe:
		return b2i(args[0].Float() != args[1].Float()), true
	case OpFLt:
		return b2i(args[0].Float() < args[1].Float()), true
	case OpFLe:
		return b2i(args[0].Float() <= args[1].Float()), true
	}
	return 0, false
}

// floorDiv is integer division rounding toward negative infinity.
func floorDiv(a, b int64) int64 {
	if b == -1 {
		return -a
	}
	q := a / b
	if a%b != 0 && (a^b) < 0 {
		q--
	}
	return q
}

// floorMod is the remainder matching floorDiv.
func floorMod(a, b int64) int64 {
	if b == -1 {
		return 0
	}
	r := a % b
	if r != 0 && (r^b) < 0 {
		r += b
	}
	return r
}

// simplify performs constant folding, algebraic simplification and
// strength reduction. It reports whether anything changed.
func simplify(f *Func) bool {
	changed := false
	repl := make(map[*Value]*Value)
	toConst := func(v *Value, c int64) {
		v.Op = OpConst
		v.Args = nil
		v.Aux = c
		changed = true
	}
	isConstInt := func(v *Value, c int64) bool { return v.IsConst() && v.Type == TInt && v.Aux == c }
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if !v.Op.IsPure() || v.Op == OpConst || v.Op == OpCtx || v.Op == OpRegBase {
				continue
			}
			if c, ok := foldConst(v); ok {
				toConst(v, c)
				continue
			}
			if len(v.Args) != 2 {
				continue
			}
			x, y := v.Args[0], v.Args[1]
			switch v.Op {
			case OpAdd, OpOr, OpXor:
				// canonicalize constants to the right
				if x.IsConst() && !y.IsConst() {
					v.Args[0], v.Args[1] = y, x
					x, y = y, x
					changed = true
				}
				if isConstInt(y, 0) {
					repl[v] = x
					changed = true
				}
			case OpSub, OpShl, OpShr, OpSar:
				if isConstInt(y, 0) {
					repl[v] = x
					changed = true
				}
			case OpMul:
				if x.IsConst() && !y.IsConst() {
					v.Args[0], v.Args[1] = y, x
					x, y = y, x
					changed = true
				}
				switch {
				case isConstInt(y, 1):
					repl[v] = x
					changed = true
				case isConstInt(y, 0):
					toConst(v, 0)
				case y.IsConst() && isPowerOfTwo(y.Aux):
					// strength reduction: x * 2^k == x << k
					v.Op = OpShl
					v.Args[1] = f.insertConstBefore(v, int64(bits.TrailingZeros64(uint64(y.Aux))))
					changed = true
				}
			case OpAnd:
				if x.IsConst() && !y.IsConst() {
					v.Args[0], v.Args[1] = y, x
					x, y = y, x
					changed = true
				}
				if isConstInt(y, -1) {
					repl[v] = x
					changed = true
				} else if isConstInt(y, 0) {
					toConst(v, 0)
				}
			case OpDiv:
				switch {
				case isConstInt(y, 1):
					repl[v] = x
					changed = true
				case y.IsConst() && isPowerOfTwo(y.Aux):
					// floor division by 2^k is an arithmetic shift
					v.Op = OpSar
					v.Args[1] = f.insertConstBefore(v, int64(bits.TrailingZeros64(uint64(y.Aux))))
					changed = true
				}
			case OpMod:
				if y.IsConst() && isPowerOfTwo(y.Aux) {
					// floor modulo by 2^k is a mask
					v.Op = OpAnd
					v.Args[1] = f.insertConstBefore(v, y.Aux-1)
					changed = true
				}
			case OpFMul:
				if x.IsConst() && !y.IsConst() {
					v.Args[0], v.Args[1] = y, x
					changed = true
				}
			case OpFDiv:
				// division by a power of two is an exact multiplication
				if y.IsConst() {
					if frac, exp := math.Frexp(y.Float()); (frac == 0.5 || frac == -0.5) && exp > -1000 && exp < 1000 {
						v.Op = OpFMul
						v.Args[1] = f.insertConstFloatBefore(v, 1/y.Float())
						changed = true
					}
				}
			}
		}
		// guards on conditions that are known to hold are redundant
		n := 0
		for _, v := range b.Values {
			if v.Op == OpGuard && v.Args[0].IsConst() && v.Args[0].Aux != 0 {
				changed = true
				continue
			}
			b.Values[n] = v
			n++
		}
		b.Values = b.Values[:n]
		// fold branches on constants
		if b.Kind == BlockIf && b.Control.IsConst() {
			taken, dead := b.Succs[0], b.Succs[1]
			if b.Control.Aux == 0 {
				taken, dead = dead, taken
			}
			for i, p := range dead.Preds {
				if p == b {
					removePred(dead, i)
					break
				}
			}
			b.Kind = BlockJump
			b.Control = nil
			b.Succs = []*Block{taken}
			changed = true
		}
	}
	replaceUses(f, repl)
	if changed {
		removeUnreachable(f)
	}
	return changed
}

// insertConstBefore inserts an integer constant immediately before v.
func (f *Func) insertConstBefore(v *Value, c int64) *Value {
	n := f.newValue(v.Block, OpConst, TInt, c)
	f.insertBefore(v, n)
	return n
}

// insertConstFloatBefore inserts a float constant immediately before v.
func (f *Func) insertConstFloatBefore(v *Value, c float64) *Value {
	n := f.newValue(v.Block, OpConst, TFloat, int64(math.Float64bits(c)))
	f.insertBefore(v, n)
	return n
}

func (f *Func) insertBefore(v, n *Value) {
	b := v.Block
	for i, x := range b.Values {
		if x == v {
			b.Values = append(b.Values, nil)
			copy(b.Values[i+1:], b.Values[i:])
			b.Values[i] = n
			return
		}
	}
	panic("jit: insertBefore: value not in its block")
}

// dominators computes the immediate dominator of every block (blocks must
// be in reverse postorder with valid order fields).
func dominators(f *Func) []*Block {
	idom := make([]*Block, len(f.Blocks))
	idom[f.Entry.order] = f.Entry
	intersect := func(a, b *Block) *Block {
		for a != b {
			for a.order > b.order {
				a = idom[a.order]
			}
			for b.order > a.order {
				b = idom[b.order]
			}
		}
		return a
	}
	for changed := true; changed; {
		changed = false
		for _, b := range f.Blocks[1:] {
			var n *Block
			for _, p := range b.Preds {
				if idom[p.order] == nil {
					continue
				}
				if n == nil {
					n = p
				} else {
					n = intersect(p, n)
				}
			}
			if n != nil && idom[b.order] != n {
				idom[b.order] = n
				changed = true
			}
		}
	}
	return idom
}

type cseKey struct {
	op         Op
	typ        Type
	aux        int64
	arg0, arg1 int
}

// cse eliminates common subexpressions of pure operations along the
// dominator tree.
func cse(f *Func) bool {
	idom := dominators(f)
	children := make([][]*Block, len(f.Blocks))
	for _, b := range f.Blocks {
		if b != f.Entry && idom[b.order] != nil {
			p := idom[b.order]
			children[p.order] = append(children[p.order], b)
		}
	}
	repl := make(map[*Value]*Value)
	table := make(map[cseKey]*Value)
	resolve := func(v *Value) *Value {
		for {
			n, ok := repl[v]
			if !ok {
				return v
			}
			v = n
		}
	}
	var walk func(b *Block)
	walk = func(b *Block) {
		var added []cseKey
		for _, v := range b.Values {
			if !v.Op.IsPure() || v.Op == OpCtx || v.Op == OpRegBase || len(v.Args) > 2 {
				continue
			}
			key := cseKey{op: v.Op, typ: v.Type, aux: v.Aux, arg0: -1, arg1: -1}
			if len(v.Args) > 0 {
				key.arg0 = resolve(v.Args[0]).ID
			}
			if len(v.Args) > 1 {
				key.arg1 = resolve(v.Args[1]).ID
			}
			if prev, ok := table[key]; ok {
				repl[v] = prev
				continue
			}
			table[key] = v
			added = append(added, key)
		}
		for _, c := range children[b.order] {
			walk(c)
		}
		for _, k := range added {
			delete(table, k)
		}
	}
	walk(f.Entry)
	replaceUses(f, repl)
	return len(repl) > 0
}

// simplifyPhis removes phis whose arguments are all the same value.
func simplifyPhis(f *Func) bool {
	any := false
	for {
		repl := make(map[*Value]*Value)
		for _, b := range f.Blocks {
			for _, v := range b.Values {
				if v.Op != OpPhi {
					break
				}
				var same *Value
				trivial := true
				for _, a := range v.Args {
					if a == v || a == same {
						continue
					}
					if same != nil {
						trivial = false
						break
					}
					same = a
				}
				if trivial && same != nil {
					repl[v] = same
				}
			}
		}
		if len(repl) == 0 {
			return any
		}
		any = true
		replaceUses(f, repl)
		for _, b := range f.Blocks {
			n := 0
			for _, v := range b.Values {
				if _, dead := repl[v]; !dead {
					b.Values[n] = v
					n++
				}
			}
			b.Values = b.Values[:n]
		}
	}
}

// deadCode removes values whose results are never used and that have no
// effect.
func deadCode(f *Func) {
	live := make(map[*Value]bool)
	var work []*Value
	mark := func(v *Value) {
		if v != nil && !live[v] {
			live[v] = true
			work = append(work, v)
		}
	}
	markExit := func(e *Exit) {
		if e == nil {
			return
		}
		for _, s := range e.Snap {
			mark(s.Val)
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op.HasEffect() {
				mark(v)
			}
		}
		mark(b.Control)
		markExit(b.Exit)
	}
	for len(work) > 0 {
		v := work[len(work)-1]
		work = work[:len(work)-1]
		for _, a := range v.Args {
			mark(a)
		}
		markExit(v.Exit)
	}
	for _, b := range f.Blocks {
		n := 0
		for _, v := range b.Values {
			if live[v] {
				b.Values[n] = v
				n++
			}
		}
		b.Values = b.Values[:n]
	}
}
