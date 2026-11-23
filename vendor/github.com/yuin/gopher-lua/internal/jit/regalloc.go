package jit

import (
	"fmt"
	"sort"
)

// LocKind is the kind of a value location.
type LocKind uint8

const (
	// LocNone means the value has no location (constants, fused values).
	LocNone LocKind = iota
	// LocReg is an allocatable integer register.
	LocReg
	// LocFReg is an allocatable float register.
	LocFReg
	// LocSpill is a 64-bit slot in the context frame.
	LocSpill
	// LocConst is a constant (only used in exit descriptions).
	LocConst
	// LocRegBase is the address of the Lua register window (only used
	// in exit descriptions, for a value that is that address).
	LocRegBase
)

// Loc is the location of a value.
type Loc struct {
	Kind LocKind
	N    int
}

func (l Loc) String() string {
	switch l.Kind {
	case LocReg:
		return fmt.Sprintf("r%d", l.N)
	case LocFReg:
		return fmt.Sprintf("f%d", l.N)
	case LocSpill:
		return fmt.Sprintf("s%d", l.N)
	case LocConst:
		return "const"
	}
	return "-"
}

// needsLoc reports whether v needs a register or spill slot.
func needsLoc(v *Value) bool {
	if !v.Op.HasResult() || v.fused {
		return false
	}
	switch v.Op {
	case OpConst, OpCtx, OpRegBase:
		return false
	}
	return true
}

// splitCriticalEdges inserts an empty block on every edge from a block
// with several successors to a block with several predecessors, so that
// phi moves always have a place to live.
func splitCriticalEdges(f *Func) {
	for _, b := range append([]*Block(nil), f.Blocks...) {
		if len(b.Succs) < 2 {
			continue
		}
		for i, s := range b.Succs {
			if len(s.Preds) < 2 {
				continue
			}
			n := f.NewBlock()
			n.Kind = BlockJump
			n.Succs = []*Block{s}
			n.Preds = []*Block{b}
			b.Succs[i] = n
			for j, p := range s.Preds {
				if p == b {
					s.Preds[j] = n
					break
				}
			}
		}
	}
	f.Blocks = reversePostorder(f)
	for i, b := range f.Blocks {
		b.order = i
	}
}

// countUses computes the number of uses of every value and marks the
// comparisons that can be fused with their single user (the guard that
// immediately follows, or the branch that terminates the block).
func countUses(f *Func) {
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			v.uses = 0
			v.fused = false
		}
	}
	use := func(v *Value) {
		if v != nil {
			v.uses++
		}
	}
	useExit := func(e *Exit) {
		if e == nil {
			return
		}
		for _, s := range e.Snap {
			use(s.Val)
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				use(a)
			}
			useExit(v.Exit)
		}
		use(b.Control)
		useExit(b.Exit)
	}
	for _, b := range f.Blocks {
		n := len(b.Values)
		for i, v := range b.Values {
			if !v.Op.IsCompare() || v.uses != 1 {
				continue
			}
			if i+1 < n {
				if next := b.Values[i+1]; next.Op == OpGuard && next.Args[0] == v {
					v.fused = true
				}
			} else if b.Kind == BlockIf && b.Control == v {
				v.fused = true
			}
		}
	}
}

// operands calls fn for every value whose register content is read when
// v is emitted (arguments of fused comparisons are read by their user).
func operands(v *Value, fn func(*Value)) {
	for _, a := range v.Args {
		if a.fused {
			for _, aa := range a.Args {
				fn(aa)
			}
			continue
		}
		fn(a)
	}
	if v.Exit != nil {
		for _, s := range v.Exit.Snap {
			fn(s.Val)
		}
	}
}

// blockOperands calls fn for the values read by the terminator of b.
func blockOperands(b *Block, fn func(*Value)) {
	if b.Control != nil {
		if b.Control.fused {
			for _, a := range b.Control.Args {
				fn(a)
			}
		} else {
			fn(b.Control)
		}
	}
	if b.Exit != nil {
		for _, s := range b.Exit.Snap {
			fn(s.Val)
		}
	}
}

// liveness computes live-in and live-out sets of all blocks.
func liveness(f *Func) {
	n := f.nextValue
	for _, b := range f.Blocks {
		b.liveIn = newBitset(n)
		b.liveOut = newBitset(n)
	}
	tmp := newBitset(n)
	for changed := true; changed; {
		changed = false
		for i := len(f.Blocks) - 1; i >= 0; i-- {
			b := f.Blocks[i]
			// liveOut = union of successors' liveIn plus phi inputs
			for _, s := range b.Succs {
				if b.liveOut.orWith(s.liveIn) {
					changed = true
				}
				pi := predIndex(s, b)
				for _, v := range s.Values {
					if v.Op != OpPhi {
						break
					}
					if a := v.Args[pi]; needsLoc(a) && !b.liveOut.has(a.ID) {
						b.liveOut.set(a.ID)
						changed = true
					}
				}
			}
			tmp.copyFrom(b.liveOut)
			blockOperands(b, func(a *Value) {
				if needsLoc(a) {
					tmp.set(a.ID)
				}
			})
			for j := len(b.Values) - 1; j >= 0; j-- {
				v := b.Values[j]
				tmp.clear(v.ID)
				if v.Op == OpPhi {
					continue
				}
				operands(v, func(a *Value) {
					if needsLoc(a) {
						tmp.set(a.ID)
					}
				})
			}
			// phis are defined at the block start: they are not live-in
			if b.liveIn.orWith(tmp) {
				changed = true
			}
		}
	}
}

// predIndex returns the index of p among the predecessors of b.
func predIndex(b, p *Block) int {
	for i, x := range b.Preds {
		if x == p {
			return i
		}
	}
	panic("jit: predecessor not found")
}

// AllocResult describes the outcome of register allocation.
type AllocResult struct {
	// Spills is the number of spill slots used.
	Spills int
}

// allocate assigns a register or a spill slot to every value using a
// linear scan over live intervals. numG and numF are the numbers of
// allocatable integer and float registers.
func allocate(f *Func, numG, numF int) AllocResult {
	countUses(f)
	liveness(f)

	// number the positions
	byID := make([]*Value, f.nextValue)
	pos := 0
	for _, b := range f.Blocks {
		b.start = pos
		for _, v := range b.Values {
			byID[v.ID] = v
			v.start, v.end = -1, -1
			v.loc = Loc{}
			v.hint = nil
			if v.Op == OpPhi {
				continue // phis are defined at the block start
			}
			pos += 2
			v.start = pos
		}
		pos += 2
		b.end = pos
	}
	extend := func(v *Value, p int) {
		if !needsLoc(v) {
			return
		}
		if v.start < 0 || p < v.start {
			v.start = p
		}
		if p > v.end {
			v.end = p
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpPhi {
				extend(v, b.start)
				continue
			}
			if needsLoc(v) {
				extend(v, v.start)
			}
			p := v.start
			operands(v, func(a *Value) { extend(a, p) })
		}
		blockOperands(b, func(a *Value) { extend(a, b.end) })
		for id, v := range byID {
			if v == nil {
				continue
			}
			if b.liveIn.has(id) {
				extend(v, b.start)
			}
			if b.liveOut.has(id) {
				extend(v, b.end)
			}
		}
		// register hints: phi inputs prefer the register of the phi
		for _, s := range b.Succs {
			pi := predIndex(s, b)
			for _, v := range s.Values {
				if v.Op != OpPhi {
					break
				}
				a := v.Args[pi]
				if needsLoc(a) && a.hint == nil {
					a.hint = v
				}
				if v.hint == nil && needsLoc(a) {
					v.hint = a
				}
			}
		}
	}

	var intervals []*Value
	for _, v := range byID {
		if v != nil && needsLoc(v) && v.start >= 0 {
			intervals = append(intervals, v)
		}
	}
	sort.SliceStable(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].ID < intervals[j].ID
	})

	res := AllocResult{}
	type class struct {
		kind   LocKind
		free   []bool
		active []*Value
	}
	classes := [2]*class{
		{kind: LocReg, free: make([]bool, numG)},
		{kind: LocFReg, free: make([]bool, numF)},
	}
	for _, c := range classes {
		for i := range c.free {
			c.free[i] = true
		}
	}
	spill := func(v *Value) {
		v.loc = Loc{Kind: LocSpill, N: res.Spills}
		res.Spills++
	}
	for _, cur := range intervals {
		c := classes[0]
		if cur.Type == TFloat {
			c = classes[1]
		}
		// expire intervals that ended before cur starts
		n := 0
		for _, a := range c.active {
			if a.end <= cur.start {
				c.free[a.loc.N] = true
			} else {
				c.active[n] = a
				n++
			}
		}
		c.active = c.active[:n]

		reg := -1
		if h := cur.hint; h != nil && h.loc.Kind == c.kind && c.free[h.loc.N] {
			reg = h.loc.N
		}
		if reg < 0 {
			for i, fr := range c.free {
				if fr {
					reg = i
					break
				}
			}
		}
		if reg >= 0 {
			c.free[reg] = false
			cur.loc = Loc{Kind: c.kind, N: reg}
			c.active = append(c.active, cur)
			continue
		}
		// no free register: spill the interval that ends last
		victim := cur
		vi := -1
		for i, a := range c.active {
			if a.end > victim.end {
				victim = a
				vi = i
			}
		}
		if vi < 0 {
			spill(cur)
			continue
		}
		cur.loc = victim.loc
		spill(victim)
		c.active[vi] = cur
	}
	return res
}
