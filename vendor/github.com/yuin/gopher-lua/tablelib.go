package lua

import (
	"math"
	"math/rand"
	"sort"
	"strings"
)

func OpenTable(L *LState) int {
	if L.is55() {
		L.Push(L.RegisterModule(TabLibName, table55Funcs))
		return 1
	}
	tabmod := L.RegisterModule(TabLibName, tableFuncs)
	L.Push(tabmod)
	return 1
}

var tableFuncs = map[string]LGFunction{
	"getn":   tableGetN,
	"concat": tableConcat,
	"insert": tableInsert,
	"maxn":   tableMaxN,
	"remove": tableRemove,
	"sort":   tableSort,
}

func tableSort(L *LState) int {
	tbl := L.CheckTable(1)
	tbl.genericize() // the sorter works on the generic array representation
	// (only the elements up to the border are sorted: the array part may
	// end with nil values after elements were removed by assignment)
	sorter := lValueArraySorter{L, nil, tbl.array[:tbl.Len()]}
	if L.GetTop() != 1 {
		sorter.Fn = L.CheckFunction(2)
	}
	sort.Sort(sorter)
	return 0
}

func tableGetN(L *LState) int {
	L.Push(LNumber(L.CheckTable(1).Len()))
	return 1
}

func tableMaxN(L *LState) int {
	L.Push(LNumber(L.CheckTable(1).MaxN()))
	return 1
}

func tableRemove(L *LState) int {
	tbl := L.CheckTable(1)
	if L.GetTop() == 1 {
		L.Push(tbl.Remove(-1))
	} else {
		L.Push(tbl.Remove(L.CheckInt(2)))
	}
	return 1
}

func tableConcat(L *LState) int {
	tbl := L.CheckTable(1)
	sep := LString(L.OptString(2, ""))
	i := L.OptInt(3, 1)
	j := L.OptInt(4, tbl.Len())
	if L.GetTop() == 3 {
		if i > tbl.Len() || i < 1 {
			L.Push(emptyLString)
			return 1
		}
	}
	i = intMax(intMin(i, tbl.Len()), 1)
	j = intMin(intMin(j, tbl.Len()), tbl.Len())
	if i > j {
		L.Push(emptyLString)
		return 1
	}
	//TODO should flushing?
	retbottom := L.GetTop()
	for ; i <= j; i++ {
		v := tbl.RawGetInt(i)
		if !LVCanConvToString(v) {
			L.RaiseError("invalid value (%s) at index %d in table for concat", v.Type().String(), i)
		}
		L.Push(v)
		if i != j {
			L.Push(sep)
		}
	}
	L.Push(stringConcat(L, L.GetTop()-retbottom, L.reg.Top()-1))
	return 1
}

func tableInsert(L *LState) int {
	tbl := L.CheckTable(1)
	nargs := L.GetTop()
	if nargs == 1 {
		L.RaiseError("wrong number of arguments")
	}

	if L.GetTop() == 2 {
		tbl.Append(L.Get(2))
		return 0
	}
	tbl.Insert(int(L.CheckInt(2)), L.CheckAny(3))
	return 0
}

/* Lua 5.5 profile {{{ */

var table55Funcs = map[string]LGFunction{
	"concat": table55Concat,
	"create": table55Create,
	"insert": table55Insert,
	"move":   table55Move,
	"pack":   table55Pack,
	"remove": table55Remove,
	"sort":   table55Sort,
	"unpack": table55Unpack,
}

// Operations a table-like argument must support (see tabCheck).
const (
	tabRead  = 1 << iota // __index
	tabWrite             // __newindex
	tabLen               // __len
)

// tabUnpackLimit bounds the number of results of table.unpack like the
// stack limit of the reference implementation.
const tabUnpackLimit = 1000000

// tabSortLimit is the largest array size table.sort accepts (INT_MAX in
// the reference implementation).
const tabSortLimit = math.MaxInt32

// tabCheck checks that argument n is a table or a value whose metatable
// provides the metamethods required by the operations in what.
func tabCheck(L *LState, n int, what int) {
	v := L.Get(n)
	if _, ok := v.(*LTable); ok {
		return
	}
	_, isString := v.(LString)
	if mt, ok := L.metatable(v, true).(*LTable); ok &&
		(what&tabRead == 0 || mt.RawGetString("__index") != LNil) &&
		(what&tabWrite == 0 || mt.RawGetString("__newindex") != LNil) &&
		(what&tabLen == 0 || isString || mt.RawGetString("__len") != LNil) {
		return
	}
	L.TypeError(n, LTTable)
}

// tabRaw returns the table behind v when it can be accessed without
// metamethods, else nil.
func tabRaw(v LValue) *LTable {
	if tb, ok := v.(*LTable); ok && tb.Metatable == LNil {
		return tb
	}
	return nil
}

// tabLength returns the length of v honoring __len; the result must be
// an integer.
func tabLength(L *LState, v LValue) int64 {
	if tb := tabRaw(v); tb != nil {
		return int64(tb.Len())
	}
	if num, ok := L.toNumberValue(objLen(L, v)); ok {
		if i, ok := LVAsInteger(num); ok {
			return i
		}
	}
	L.RaiseError("object length is not an integer")
	return 0
}

// tabCheckLen checks argument n like tabCheck (always requiring a length)
// and returns its length.
func tabCheckLen(L *LState, n int, what int) int64 {
	tabCheck(L, n, what|tabLen)
	return tabLength(L, L.Get(n))
}

// tabGet returns v[i] honoring metamethods.
func tabGet(L *LState, v LValue, i int64) LValue {
	if tb := tabRaw(v); tb != nil {
		return tb.RawGet(LInteger(i))
	}
	return L.GetTable(v, LInteger(i))
}

// tabSet performs v[i] = value honoring metamethods.
func tabSet(L *LState, v LValue, i int64, value LValue) {
	if tb := tabRaw(v); tb != nil {
		tb.RawSet(LInteger(i), value)
		return
	}
	L.SetTable(v, LInteger(i), value)
}

// table55Concat implements table.concat(list [, sep [, i [, j]]]).
func table55Concat(L *LState) int {
	last := tabCheckLen(L, 1, tabRead)
	t := L.Get(1)
	sep := optStringArg(L, 2, "")
	i := L.OptInt64(3, 1)
	last = L.OptInt64(4, last)
	var sb strings.Builder
	add := func(i int64) {
		v := tabGet(L, t, i)
		switch v.(type) {
		case LString, LNumber, LInteger:
			sb.WriteString(L.valueToString(v))
		default:
			L.RaiseError("invalid value (%s) at index %d in table for 'concat'", L.typeNameOf(v), i)
		}
	}
	for ; i < last; i++ {
		add(i)
		sb.WriteString(sep)
	}
	if i == last { // add the last value (if the interval was not empty)
		add(i)
	}
	L.Push(LString(sb.String()))
	return 1
}

// table55Create implements table.create(nseq [, nrec]).
func table55Create(L *LState) int {
	nseq := L.CheckInt64(1)
	nrec := L.OptInt64(2, 0)
	if nseq < 0 || nseq > math.MaxInt32 {
		L.ArgError(1, "out of range")
	}
	if nrec < 0 || nrec > math.MaxInt32 {
		L.ArgError(2, "out of range")
	}
	// The sizes are only hints: bound the eager allocation.
	const maxPrealloc = 1 << 16
	L.Push(L.CreateTable(int(min(nseq, maxPrealloc)), int(min(nrec, maxPrealloc))))
	return 1
}

// table55Insert implements table.insert(list, [pos,] value).
func table55Insert(L *LState) int {
	e := tabCheckLen(L, 1, tabRead|tabWrite) + 1 // first empty element
	t := L.Get(1)
	var pos int64
	switch L.GetTop() {
	case 2:
		pos = e
	case 3:
		pos = L.CheckInt64(2)
		// check whether pos is in [1, e]
		if uint64(pos)-1 >= uint64(e) {
			L.ArgError(2, "position out of bounds")
		}
		if tb := tabRaw(t); tb != nil && tb.arrayLen() == int(e-1) && pos < e {
			tb.Insert(int(pos), L.Get(3)) // dense array part: shift in place
			return 0
		}
		for i := e; i > pos; i-- { // move up elements
			tabSet(L, t, i, tabGet(L, t, i-1))
		}
	default:
		L.RaiseError("wrong number of arguments to 'insert'")
	}
	tabSet(L, t, pos, L.Get(L.GetTop()))
	return 0
}

// table55Move implements table.move(a1, f, e, t [, a2]).
func table55Move(L *LState) int {
	f := L.CheckInt64(2)
	e := L.CheckInt64(3)
	t := L.CheckInt64(4)
	tt := 1 // destination table
	if L.Get(5) != LNil {
		tt = 5
	}
	tabCheck(L, 1, tabRead)
	tabCheck(L, tt, tabWrite)
	src, dst := L.Get(1), L.Get(tt)
	if e >= f { // otherwise, nothing to move
		if !(f > 0 || e < maxInteger+f) {
			L.ArgError(3, "too many elements to move")
		}
		n := e - f + 1 // number of elements to move
		if t > maxInteger-n+1 {
			L.ArgError(4, "destination wrap around")
		}
		if t > e || t <= f || (tt != 1 && !L.Equal(src, dst)) {
			for i := int64(0); i < n; i++ {
				tabSet(L, dst, t+i, tabGet(L, src, f+i))
			}
		} else {
			for i := n - 1; i >= 0; i-- {
				tabSet(L, dst, t+i, tabGet(L, src, f+i))
			}
		}
	}
	L.Push(dst)
	return 1
}

// table55Pack implements table.pack(...).
func table55Pack(L *LState) int {
	n := L.GetTop()
	t := L.CreateTable(n, 1)
	for i := 1; i <= n; i++ {
		t.RawSetInt(i, L.Get(i))
	}
	t.RawSetString("n", LInteger(n))
	L.Push(t)
	return 1
}

// table55Remove implements table.remove(list [, pos]).
func table55Remove(L *LState) int {
	size := tabCheckLen(L, 1, tabRead|tabWrite)
	t := L.Get(1)
	pos := L.OptInt64(2, size)
	if pos != size && uint64(pos)-1 > uint64(size) {
		// pos must be in [1, size + 1]
		L.ArgError(2, "position out of bounds")
	}
	if tb := tabRaw(t); tb != nil && tb.arrayLen() == int(size) && pos >= 1 && pos <= size {
		L.Push(tb.Remove(int(pos))) // dense array part: shift in place
		return 1
	}
	L.Push(tabGet(L, t, pos))
	for ; pos < size; pos++ {
		tabSet(L, t, pos, tabGet(L, t, pos+1))
	}
	tabSet(L, t, pos, LNil) // remove entry t[pos]
	return 1
}

// table55Unpack implements table.unpack(list [, i [, j]]).
func table55Unpack(L *LState) int {
	tabCheck(L, 1, tabRead|tabLen)
	t := L.Get(1)
	i := L.OptInt64(2, 1)
	var e int64
	if L.Get(3) == LNil {
		e = tabLength(L, t)
	} else {
		e = L.CheckInt64(3)
	}
	if i > e {
		return 0 // empty range
	}
	n := uint64(e) - uint64(i) // number of elements minus 1 (avoids overflows)
	if n >= tabUnpackLimit || !tabStackRoom(L, int(n)+1) {
		L.RaiseError("too many results to unpack")
	}
	for ; i < e; i++ {
		L.Push(tabGet(L, t, i))
	}
	L.Push(tabGet(L, t, e))
	return int(n) + 1
}

// tabStackRoom reports whether n more values fit on the value stack of L.
func tabStackRoom(L *LState, n int) bool {
	rg := L.reg
	limit := max(rg.maxSize, cap(rg.array))
	return rg.top+n <= limit
}

// tableSorter sorts a table-like value in place with the quicksort of
// the reference implementation, so that the number and order of the
// comparisons (and the detection of inconsistent order functions) match.
type tableSorter struct {
	L  *LState
	t  LValue  // the sorted object
	tb *LTable // t if it is a table, else nil
	fn LValue  // order function or LNil
}

// less reports whether a must come before b.
func (s *tableSorter) less(a, b LValue) bool {
	if s.fn == LNil {
		return s.L.LessThan(a, b)
	}
	L := s.L
	L.Push(s.fn)
	L.Push(a)
	L.Push(b)
	L.Call(2, 1)
	return LVAsBool(L.reg.Pop())
}

// rawArray reports whether index i (always positive) can be accessed
// directly in the array part of the sorted table. The metatable is
// checked on every access because order functions may change it.
func (s *tableSorter) rawArray(i int64) bool {
	return s.tb != nil && s.tb.Metatable == LNil && i < int64(MaxArrayIndex)
}

// get returns t[i].
func (s *tableSorter) get(i int64) LValue {
	if s.rawArray(i) {
		return s.tb.RawGetInt(int(i))
	}
	return tabGet(s.L, s.t, i)
}

// set performs t[i] = v.
func (s *tableSorter) set(i int64, v LValue) {
	if s.rawArray(i) {
		s.tb.RawSetInt(int(i), v)
		return
	}
	tabSet(s.L, s.t, i, v)
}

// partition splits t[lo..up] around the pivot p stored in t[up-1] and
// returns the final position of the pivot.
func (s *tableSorter) partition(lo, up int64, p LValue) int64 {
	i := lo     // will be incremented before first use
	j := up - 1 // will be decremented before first use
	for {
		var vi, vj LValue
		// repeat ++i while t[i] < p
		for i++; ; i++ {
			if vi = s.get(i); !s.less(vi, p) {
				break
			}
			if i == up-1 { // t[i] < p but t[up - 1] == p
				s.L.RaiseError("invalid order function for sorting")
			}
		}
		// repeat --j while p < t[j]
		for j--; ; j-- {
			if vj = s.get(j); !s.less(p, vj) {
				break
			}
			if j < i { // j < i but t[j] > p
				s.L.RaiseError("invalid order function for sorting")
			}
		}
		if j < i { // no elements out of place
			// swap the pivot (t[up - 1]) with t[i]
			s.set(up-1, vi)
			s.set(i, p)
			return i
		}
		// swap t[i] and t[j] to restore the invariant and repeat
		s.set(i, vj)
		s.set(j, vi)
	}
}

// choosePivot picks a pivot index in the middle half of [lo, up] using
// the randomization value rnd.
func choosePivot(lo, up int64, rnd uint64) int64 {
	r4 := (up - lo) / 4 // range/4
	return int64(rnd%uint64(r4*2)) + lo + r4
}

// sortRandomLimit is the interval size above which the pivot selection
// may be randomized.
const sortRandomLimit = 100

// sort sorts t[lo..up].
func (s *tableSorter) sort(lo, up int64, rnd uint64) {
	for lo < up { // loop for tail recursion
		// sort elements lo, p and up
		vlo, vup := s.get(lo), s.get(up)
		if s.less(vup, vlo) { // t[up] < t[lo]?
			s.set(lo, vup)
			s.set(up, vlo)
		}
		if up-lo == 1 { // only 2 elements?
			return
		}
		var p int64
		if up-lo < sortRandomLimit || rnd == 0 {
			p = (lo + up) / 2
		} else {
			p = choosePivot(lo, up, rnd)
		}
		vp, vlo := s.get(p), s.get(lo)
		if s.less(vp, vlo) { // t[p] < t[lo]?
			s.set(p, vlo)
			s.set(lo, vp)
		} else {
			vup = s.get(up)
			if s.less(vup, vp) { // t[up] < t[p]?
				s.set(p, vup)
				s.set(up, vp)
			}
		}
		if up-lo == 2 { // only 3 elements?
			return
		}
		pivot := s.get(p)
		// swap the pivot with t[up - 1]
		s.set(p, s.get(up-1))
		s.set(up-1, pivot)
		p = s.partition(lo, up, pivot)
		// t[lo .. p - 1] <= t[p] == pivot <= t[p + 1 .. up]
		var n int64
		if p-lo < up-p { // lower interval is shorter?
			s.sort(lo, p-1, rnd)
			n = p - lo
			lo = p + 1
		} else {
			s.sort(p+1, up, rnd)
			n = up - p
			up = p - 1
		}
		if (up-lo)/128 > n { // partition too imbalanced?
			rnd = sortRandomSeed()
		}
	}
}

// sortRandomSeed returns a non-zero value used to randomize pivots after
// a badly imbalanced partition.
func sortRandomSeed() uint64 {
	return uint64(rand.Uint32()) | 1
}

// table55Sort implements table.sort(list [, comp]).
func table55Sort(L *LState) int {
	n := tabCheckLen(L, 1, tabRead|tabWrite)
	if n > 1 { // non-trivial interval?
		if n >= tabSortLimit {
			L.ArgError(1, "array too big")
		}
		fn := L.Get(2)
		if fn != LNil && fn.Type() != LTFunction {
			L.TypeError(2, LTFunction)
		}
		s := &tableSorter{L: L, t: L.Get(1), fn: fn}
		s.tb, _ = s.t.(*LTable)
		s.sort(1, n, 0)
	}
	return 0
}

/* }}} */

//
