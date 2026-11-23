package lua

import "sort"

/*
Sparse elements of the array part.

GopherLua stores every element with an integer key between 1 and
MaxArrayIndex in the array part, a slice: t[1000000] = v makes the slice a
million slots long. What a program can observe of the array part is the
content of its slots, not the slice: the border (the last slot that is not
nil), the order of a traversal (ascending), and that table.insert and
table.remove move and count slots.

This runtime keeps those observations and stores less. The array part of
a table is

	stored elements (array, iarr or farr), followed by
	tail slots, which hold nil unless the table has an entry for the
	slot in sparse.

An element that is assigned far behind the stored elements goes to
sparse instead of filling the slice with nil up to its position. Every
operation on the array part is defined on the slots, so the results are
the ones GopherLua computes on its slice. The slot right behind the
stored elements is never in sparse: an element that gets there is
appended to the stored elements (absorb), which keeps `stored length`
the end of the dense prefix that compiled code and ipairs rely on.
*/

// tableSparseGap is the distance behind the stored elements up to which
// an assignment fills the slots in between with nil, like GopherLua
// does. Elements beyond it are kept in the sparse map. (A variable: the
// tests lower it so that small tables use the sparse representation.)
var tableSparseGap = 64

// slotGet returns the content of a slot behind the stored elements.
func (tb *LTable) slotGet(index int) LValue {
	if s := tb.sparse; s != nil {
		if v, ok := s.elems[index]; ok {
			return v
		}
	}
	return LNil
}

// sparsePut stores an element in a slot behind the stored elements.
func (tb *LTable) sparsePut(index int, value LValue) {
	s := tb.sparse
	if s == nil {
		s = &tableSparse{elems: make(map[int]LValue), keys: make([]int, 0, 4), top: index, topOK: true}
		tb.sparse = s
	}
	if _, exists := s.elems[index]; !exists {
		// the sorted keys stay usable if the new one goes to their end
		if n := len(s.keys); s.keys != nil && (n == 0 || s.keys[n-1] < index) {
			s.keys = append(s.keys, index)
		} else {
			s.keys = nil
		}
	}
	s.elems[index] = value
	if s.topOK && index > s.top {
		s.top = index
	}
}

// sparseDelete empties a slot behind the stored elements.
func (tb *LTable) sparseDelete(index int) {
	s := tb.sparse
	if s == nil {
		return
	}
	if _, ok := s.elems[index]; !ok {
		return
	}
	delete(s.elems, index)
	if len(s.elems) == 0 {
		tb.sparse = nil
		return
	}
	// (the sorted keys may keep keys that are gone: readers skip them)
	if index == s.top {
		s.topOK = false
	}
}

// sparseSorted returns the indexes of the sparse elements in ascending
// order, possibly with indexes of elements that were removed since. The
// table must have sparse elements.
func (tb *LTable) sparseSorted() []int {
	s := tb.sparse
	if s.keys == nil {
		keys := make([]int, 0, len(s.elems))
		for k := range s.elems {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		s.keys = keys
	}
	return s.keys
}

// sparseLast returns the largest index of a sparse element. The table
// must have sparse elements.
func (tb *LTable) sparseLast() int {
	s := tb.sparse
	if !s.topOK {
		keys := tb.sparseSorted()
		for len(keys) > 0 {
			if _, ok := s.elems[keys[len(keys)-1]]; ok {
				break
			}
			keys = keys[:len(keys)-1]
		}
		s.keys = keys
		s.top, s.topOK = keys[len(keys)-1], true
	}
	return s.top
}

// sparseNext returns the first sparse element at or behind the slot
// index from. The table must have sparse elements.
func (tb *LTable) sparseNext(from int) (index int, value LValue, ok bool) {
	keys := tb.sparseSorted()
	for i := sort.SearchInts(keys, from); i < len(keys); i++ {
		if v, ok := tb.sparse.elems[keys[i]]; ok {
			return keys[i], v, true
		}
	}
	return 0, nil, false
}

// sparseShift moves the sparse elements at and behind the slot index
// from by delta slots (one up or one down).
func (tb *LTable) sparseShift(from, delta int) {
	s := tb.sparse
	if s == nil {
		return
	}
	moved := make(map[int]LValue, len(s.elems))
	for k, v := range s.elems {
		if k >= from {
			k += delta
		}
		moved[k] = v
	}
	s.elems, s.keys, s.topOK = moved, nil, false
}

// sparseSet handles an assignment to a slot at or behind the end of the
// n stored elements where the sparse representation is involved. It
// reports false if the assignment is left to the dense code.
func (tb *LTable) sparseSet(index, n int, value LValue) bool {
	if value == LNil {
		// the slot is emptied; the dense code counts it
		if tb.sparse != nil {
			tb.sparseDelete(index)
		}
		return false
	}
	if index == n {
		return false // appended to the stored elements
	}
	if tb.sparse == nil && index-n <= tableSparseGap && tb.tail <= tableSparseGap {
		return false // close enough: the slots in between are stored
	}
	tb.sparsePut(index, value)
	tb.nilSlot(index)
	return true
}

// absorb appends the sparse elements that have come to lie right behind
// the stored elements to them.
func (tb *LTable) absorb() {
	for tb.sparse != nil {
		n := tb.arrayLen()
		v, ok := tb.sparse.elems[n]
		if !ok {
			return
		}
		tb.sparseDelete(n)
		tb.arrayStore(n, v)
	}
}

// densify stores every slot of the array part, as GopherLua does, for
// operations that work on the slice (sorting).
func (tb *LTable) densify() {
	if tb.sparse == nil {
		return
	}
	tb.genericize()
	n := len(tb.array)
	for index := n; index < n+tb.tail; index++ {
		tb.array = append(tb.array, tb.slotGet(index))
	}
	tb.sparse, tb.tail = nil, 0
}

// insertSlot inserts value at the 0-based slot index i of an array part
// that uses, or would need, the sparse representation: the slots at and
// behind i move up by one.
func (tb *LTable) insertSlot(i int, value LValue) {
	tb.sparseShift(i, 1)
	if i <= tb.arrayLen() {
		tb.insertStored(i, value)
		return
	}
	tb.tail++
	if value != LNil {
		tb.sparsePut(i, value)
	}
}
