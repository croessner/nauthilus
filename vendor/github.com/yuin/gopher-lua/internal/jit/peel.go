package jit

/*
Loop peeling.

A loop repeats the checks that do not depend on its iteration: that a
register still holds a table, which array representation the table has,
where its elements are. Hoisting such checks out of the loop would need
proof that they are safe to execute earlier than the program does. Peeling
gets the same effect without such a proof: the body of the loop is copied
in front of the loop, so that the first iteration runs in the copy. Every
check of that iteration then dominates the loop, and the passes that
remove redundant computations along the dominator tree (cse, memCSE)
delete from the loop what the first iteration established and what
nothing in the loop can change. What depends on the iteration stays.

Only innermost loops without callouts are peeled: a callout lets Go code
change any memory, which leaves nothing to reuse.
*/

// Limits of the loops that are peeled: copying a loop doubles its code.
const (
	peelMaxValues = 400
	peelMaxBlocks = 48
)

// loop is a natural loop: the blocks that can reach a latch (a
// predecessor of the header inside the loop) without passing the header.
type loop struct {
	header  *Block
	body    map[*Block]bool
	latches []*Block
}

// dominates reports whether a dominates b.
func dominates(idom []*Block, a, b *Block) bool {
	for b.order > a.order {
		b = idom[b.order]
	}
	return a == b
}

// findLoops returns the natural loops of f, one per header.
func findLoops(f *Func, idom []*Block) []*loop {
	byHeader := make(map[*Block]*loop)
	var loops []*loop
	for _, b := range f.Blocks {
		for _, s := range b.Succs {
			if !dominates(idom, s, b) {
				continue
			}
			l := byHeader[s]
			if l == nil {
				l = &loop{header: s, body: map[*Block]bool{s: true}}
				byHeader[s] = l
				loops = append(loops, l)
			}
			l.latches = append(l.latches, b)
		}
	}
	for _, l := range loops {
		work := append([]*Block(nil), l.latches...)
		for len(work) > 0 {
			b := work[len(work)-1]
			work = work[:len(work)-1]
			if l.body[b] {
				continue
			}
			l.body[b] = true
			work = append(work, b.Preds...)
		}
	}
	return loops
}

// peelable reports whether the loop is an innermost loop that is worth
// copying and that the copying below can handle.
func peelable(l *loop, headers map[*Block]bool) bool {
	if len(l.body) > peelMaxBlocks {
		return false
	}
	outside, values := 0, 0
	for _, p := range l.header.Preds {
		if !l.body[p] {
			outside++
		}
	}
	if outside == 0 {
		return false
	}
	for b := range l.body {
		if b != l.header && headers[b] {
			return false // not an innermost loop
		}
		if len(b.Succs) == 2 && b.Succs[0] == b.Succs[1] {
			return false
		}
		values += len(b.Values)
		for _, v := range b.Values {
			if v.Op == OpCallout {
				return false
			}
		}
	}
	return values <= peelMaxValues
}

// peelLoops peels the innermost loops of f. It reports whether it
// changed the function.
func peelLoops(f *Func) bool {
	idom := dominators(f)
	loops := findLoops(f, idom)
	headers := make(map[*Block]bool, len(loops))
	for _, l := range loops {
		headers[l.header] = true
	}
	changed := false
	for _, l := range loops {
		if peelable(l, headers) {
			peel(f, l)
			changed = true
		}
	}
	if changed {
		removeUnreachable(f)
	}
	return changed
}

// peeler copies the blocks of one loop.
type peeler struct {
	f      *Func
	l      *loop
	region map[*Block]bool // the loop and its own exit blocks
	blocks map[*Block]*Block
	values map[*Value]*Value
}

// value returns the copy of a value of the region, or the value itself
// if it is defined elsewhere.
func (p *peeler) value(v *Value) *Value {
	if c, ok := p.values[v]; ok {
		return c
	}
	return v
}

// exit returns a copy of an exit for the copied code.
func (p *peeler) exit(e *Exit) *Exit {
	if e == nil {
		return nil
	}
	c := p.f.NewExit(e.Kind, e.PC)
	c.Data = e.Data
	c.Snap = make([]SnapEntry, len(e.Snap))
	for i, s := range e.Snap {
		c.Snap[i] = SnapEntry{Slot: s.Slot, Tag: s.Tag, Val: p.value(s.Val)}
	}
	return c
}

// peel copies the body of the loop l in front of it: control enters the
// copy, whose back-edges lead to the header of the loop.
func peel(f *Func, l *loop) {
	p := &peeler{f: f, l: l, region: make(map[*Block]bool), blocks: make(map[*Block]*Block), values: make(map[*Value]*Value)}
	h := l.header
	// the region in the order of the function: the loop and the exit
	// blocks that only the loop reaches, which are copied with it
	var region []*Block
	for _, b := range f.Blocks {
		if l.body[b] || p.ownExit(b) {
			p.region[b] = true
			region = append(region, b)
		}
	}
	isOutside := func(i int) bool { return !l.body[h.Preds[i]] }

	// copies of the blocks and of their values, arguments still missing
	for _, b := range region {
		c := f.NewBlock()
		c.Kind = b.Kind
		p.blocks[b] = c
		for _, v := range b.Values {
			n := f.newValue(c, v.Op, v.Type, v.Aux)
			n.Mem = v.Mem
			c.Values = append(c.Values, n)
			p.values[v] = n
		}
	}
	for _, b := range region {
		c := p.blocks[b]
		for i, v := range b.Values {
			n := c.Values[i]
			n.Exit = p.exit(v.Exit)
			for j, a := range v.Args {
				if b == h && v.Op == OpPhi && !isOutside(j) {
					continue // the copy of the header is only entered from outside
				}
				n.Args = append(n.Args, p.value(a))
			}
		}
		if b.Control != nil {
			c.Control = p.value(b.Control)
		}
		c.Exit = p.exit(b.Exit)
	}

	// edges of the copy
	for _, b := range region {
		c := p.blocks[b]
		for _, s := range b.Succs {
			switch {
			case s == h:
				c.Succs = append(c.Succs, h) // predecessors of h: below
			case p.region[s]:
				c.Succs = append(c.Succs, p.blocks[s])
			default:
				// the loop is left to a block that other code reaches too
				c.Succs = append(c.Succs, s)
				at := predIndex(s, b)
				s.Preds = append(s.Preds, c)
				for _, v := range s.Values {
					if v.Op != OpPhi {
						break
					}
					v.Args = append(v.Args, p.value(v.Args[at]))
				}
			}
		}
		if b != h {
			for _, q := range b.Preds {
				c.Preds = append(c.Preds, p.blocks[q])
			}
		}
	}

	// the copy of the header takes over the entering edges; the header
	// is reached from the latches of the copy and from its own
	hc := p.blocks[h]
	var latchArgs []int
	for i, q := range h.Preds {
		if isOutside(i) {
			hc.Preds = append(hc.Preds, q)
			for j, s := range q.Succs {
				if s == h {
					q.Succs[j] = hc
				}
			}
		} else {
			latchArgs = append(latchArgs, i)
		}
	}
	preds := make([]*Block, 0, 2*len(latchArgs))
	for _, i := range latchArgs {
		preds = append(preds, p.blocks[h.Preds[i]])
	}
	for _, i := range latchArgs {
		preds = append(preds, h.Preds[i])
	}
	for _, v := range h.Values {
		if v.Op != OpPhi {
			break
		}
		args := make([]*Value, 0, len(preds))
		for _, i := range latchArgs {
			args = append(args, p.value(v.Args[i]))
		}
		for _, i := range latchArgs {
			args = append(args, v.Args[i])
		}
		v.Args = args
	}
	h.Preds = preds

	p.repair()
}

// ownExit reports whether b is an exit block that only the loop reaches.
func (p *peeler) ownExit(b *Block) bool {
	if b.Kind != BlockExit || len(b.Preds) == 0 {
		return false
	}
	for _, q := range b.Preds {
		if !p.l.body[q] {
			return false
		}
	}
	return true
}

// repair restores the SSA property for the values of the loop that code
// behind the loop uses: such a value now comes either from the loop or
// from its copy, so the uses get phis where the two meet.
func (p *peeler) repair() {
	f := p.f
	inCopy := make(map[*Block]bool, len(p.blocks))
	for _, c := range p.blocks {
		inCopy[c] = true
	}
	local := func(b *Block) bool { return p.region[b] || inCopy[b] }
	// the values of the loop that are used elsewhere
	var escaping []*Value
	seen := make(map[*Value]bool)
	note := func(v *Value) {
		if _, ok := p.values[v]; ok && !seen[v] {
			seen[v] = true
			escaping = append(escaping, v)
		}
	}
	noteExit := func(e *Exit) {
		if e != nil {
			for _, s := range e.Snap {
				note(s.Val)
			}
		}
	}
	for _, b := range f.Blocks {
		if local(b) {
			continue
		}
		for _, v := range b.Values {
			for i, a := range v.Args {
				if v.Op == OpPhi && local(b.Preds[i]) {
					continue // delivered by an edge from the loop or its copy
				}
				note(a)
			}
			noteExit(v.Exit)
		}
		if b.Control != nil {
			note(b.Control)
		}
		noteExit(b.Exit)
	}
	if len(escaping) == 0 {
		return
	}

	removeUnreachable(f)
	idom := dominators(f)
	// dominance frontiers
	frontier := make([][]*Block, len(f.Blocks))
	for _, b := range f.Blocks {
		if len(b.Preds) < 2 {
			continue
		}
		for _, q := range b.Preds {
			for r := q; r != idom[b.order]; r = idom[r.order] {
				frontier[r.order] = append(frontier[r.order], b)
			}
		}
	}
	for _, v := range escaping {
		c := p.values[v]
		// phis at the iterated dominance frontier of the two definitions
		phis := make(map[*Block]*Value)
		work := []*Block{v.Block, c.Block}
		for len(work) > 0 {
			b := work[len(work)-1]
			work = work[:len(work)-1]
			for _, d := range frontier[b.order] {
				if phis[d] != nil || local(d) {
					continue
				}
				phis[d] = f.NewPhi(d, v.Type)
				work = append(work, d)
			}
		}
		// reaching returns the definition that is valid at the end of b
		reaching := func(b *Block) *Value {
			for {
				switch {
				case phis[b] != nil:
					return phis[b]
				case b == v.Block:
					return v
				case b == c.Block:
					return c
				case b == f.Entry:
					return nil
				}
				b = idom[b.order]
			}
		}
		for d, phi := range phis {
			for _, q := range d.Preds {
				a := reaching(q)
				if a == nil {
					// no definition on this path: the value is not used
					// on the paths through this edge
					a = f.insertConstAfterPhis(q, v.Type)
				}
				phi.Args = append(phi.Args, a)
			}
		}
		use := func(b *Block, a *Value) *Value {
			if a != v {
				return a
			}
			if r := reaching(b); r != nil {
				return r
			}
			return a
		}
		fixExit := func(b *Block, e *Exit) {
			if e != nil {
				for i := range e.Snap {
					e.Snap[i].Val = use(b, e.Snap[i].Val)
				}
			}
		}
		for _, b := range f.Blocks {
			if local(b) {
				continue
			}
			for _, w := range b.Values {
				if w.Op == OpPhi {
					if w == phis[b] {
						continue
					}
					for i, a := range w.Args {
						if a == v && !local(b.Preds[i]) {
							w.Args[i] = use(b.Preds[i], a)
						}
					}
					continue
				}
				for i, a := range w.Args {
					w.Args[i] = use(b, a)
				}
				fixExit(b, w.Exit)
			}
			if b.Control != nil {
				b.Control = use(b, b.Control)
			}
			fixExit(b, b.Exit)
		}
	}
}

// insertConstAfterPhis adds a zero constant of the given type to b, in
// front of the other values of the block.
func (f *Func) insertConstAfterPhis(b *Block, typ Type) *Value {
	c := f.newValue(b, OpConst, typ, 0)
	i := 0
	for i < len(b.Values) && b.Values[i].Op == OpPhi {
		i++
	}
	b.Values = append(b.Values, nil)
	copy(b.Values[i+1:], b.Values[i:])
	b.Values[i] = c
	return c
}
