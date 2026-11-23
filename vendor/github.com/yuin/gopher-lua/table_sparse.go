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
	if tb.sparse != nil {
		if v, ok := tb.sparse[index]; ok {
			return v
		}
	}
	return LNil
}

// sparsePut stores an element in a slot behind the stored elements.
func (tb *LTable) sparsePut(index int, value LValue) {
	if tb.sparse == nil {
		tb.sparse = make(map[int]LValue)
		tb.sparseKeys, tb.sparseTop, tb.sparseTopOK = make([]int, 0, 4), index, true
	}
	if _, exists := tb.sparse[index]; !exists {
		// the sorted keys stay usable if the new one goes to their end
		if n := len(tb.sparseKeys); tb.sparseKeys != nil && (n == 0 || tb.sparseKeys[n-1] < index) {
			tb.sparseKeys = append(tb.sparseKeys, index)
		} else {
			tb.sparseKeys = nil
		}
	}
	tb.sparse[index] = value
	if tb.sparseTopOK && index > tb.sparseTop {
		tb.sparseTop = index
	}
}

// sparseDelete empties a slot behind the stored elements.
func (tb *LTable) sparseDelete(index int) {
	if _, ok := tb.sparse[index]; !ok {
		return
	}
	delete(tb.sparse, index)
	if len(tb.sparse) == 0 {
		tb.sparse, tb.sparseKeys = nil, nil
		return
	}
	// (the sorted keys may keep keys that are gone: readers skip them)
	if index == tb.sparseTop {
		tb.sparseTopOK = false
	}
}

// sparseSorted returns the indexes of the sparse elements in ascending
// order, possibly with indexes of elements that were removed since.
func (tb *LTable) sparseSorted() []int {
	if tb.sparseKeys == nil {
		keys := make([]int, 0, len(tb.sparse))
		for k := range tb.sparse {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		tb.sparseKeys = keys
	}
	return tb.sparseKeys
}

// sparseLast returns the largest index of a sparse element. The table
// must have sparse elements.
func (tb *LTable) sparseLast() int {
	if !tb.sparseTopOK {
		keys := tb.sparseSorted()
		for len(keys) > 0 {
			if _, ok := tb.sparse[keys[len(keys)-1]]; ok {
				break
			}
			keys = keys[:len(keys)-1]
		}
		tb.sparseKeys = keys
		tb.sparseTop, tb.sparseTopOK = keys[len(keys)-1], true
	}
	return tb.sparseTop
}

// sparseNext returns the first sparse element at or behind the slot
// index from.
func (tb *LTable) sparseNext(from int) (index int, value LValue, ok bool) {
	keys := tb.sparseSorted()
	for i := sort.SearchInts(keys, from); i < len(keys); i++ {
		if v, ok := tb.sparse[keys[i]]; ok {
			return keys[i], v, true
		}
	}
	return 0, nil, false
}

// sparseShift moves the sparse elements at and behind the slot index
// from by delta slots (one up or one down).
func (tb *LTable) sparseShift(from, delta int) {
	if tb.sparse == nil {
		return
	}
	moved := make(map[int]LValue, len(tb.sparse))
	for k, v := range tb.sparse {
		if k >= from {
			k += delta
		}
		moved[k] = v
	}
	tb.sparse, tb.sparseKeys, tb.sparseTopOK = moved, nil, false
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
		v, ok := tb.sparse[n]
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
	tb.sparse, tb.sparseKeys, tb.tail = nil, nil, 0
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
