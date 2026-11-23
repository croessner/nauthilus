package lua

import (
	"hash/maphash"
	"math"
	"unsafe"
)

// Initial capacities of the array and hash parts. Both parts are
// allocated on first use: most tables are small, and many use only one
// of the parts.
const defaultArrayCap = 4
const defaultHashCap = 4

// tableField is one string-keyed entry of a table. A removed entry keeps
// its position with the value LNil, so that the positions of the other
// entries and the iteration order stay stable.
type tableField struct {
	key   string
	value LValue
}

// fieldNum is the unboxed number of a string-keyed entry (kind fieldInt or
// fieldFloat), which lets JIT compiled code read and write number fields
// without touching pointers. The value of such an entry caches the boxed
// number; native code that writes num sets stale, and the box is rebuilt
// on the next read.
//
// The unboxed numbers live next to the entries, not in them, and only
// the tables of a state with the JIT on (typedOK) keep them: there the
// value of an entry is a number if and only if its kind is not
// fieldBoxed. Other tables, and tables that hold functions, strings and
// tables only, pay nothing for them.
type fieldNum struct {
	num   uint64
	kind  uint8
	stale bool
}

// Kinds of table fields.
const (
	fieldBoxed uint8 = iota // any value but a number, in value
	fieldInt                // an integer, as int64 bits in num
	fieldFloat              // a float, as float64 bits in num
)

// numAt returns the unboxed number of the entry at position i. The table
// must have unboxed numbers.
func (tb *LTable) numAt(i int) *fieldNum {
	return (*fieldNum)(unsafe.Add(unsafe.Pointer(tb.nums), uintptr(i)*unsafe.Sizeof(fieldNum{})))
}

// needNum returns the unboxed number of the entry at position i, giving
// the table unboxed numbers if it has none.
func (tb *LTable) needNum(i int) *fieldNum {
	if tb.nums == nil {
		tb.nums = unsafe.SliceData(make([]fieldNum, cap(tb.fields)))
	}
	return tb.numAt(i)
}

// regrowNums gives the unboxed numbers the capacity of the entries after
// the entries were moved, keeping those of the first n entries.
func (tb *LTable) regrowNums(n int) {
	if tb.nums == nil {
		return
	}
	nums := make([]fieldNum, cap(tb.fields))
	copy(nums, unsafe.Slice(tb.nums, n))
	tb.nums = unsafe.SliceData(nums)
}

// fieldKind returns the kind of the entry at position i.
func (tb *LTable) fieldKind(i int) uint8 {
	if tb.nums == nil {
		return fieldBoxed
	}
	return tb.numAt(i).kind
}

// fieldGet returns the value of the entry at position i.
func (tb *LTable) fieldGet(i int) LValue {
	if tb.nums != nil {
		tb.rebox(i)
	}
	return tb.fields[i].value
}

// rebox rebuilds the boxed value of the entry at position i if compiled
// code has written its number. (Kept out of line so that fieldGet is
// inlined: tables without unboxed numbers only pay for the check above.)
//
//go:noinline
func (tb *LTable) rebox(i int) {
	n := tb.numAt(i)
	if !n.stale {
		return
	}
	if n.kind == fieldInt {
		tb.fields[i].value = boxInt(int64(n.num))
	} else {
		tb.fields[i].value = LNumber(math.Float64frombits(n.num))
	}
	n.stale = false
}

// fieldSet stores a value in the entry at position i.
func (tb *LTable) fieldSet(i int, value LValue) {
	tb.fields[i].value = value
	if tb.typedOK {
		tb.setNum(i, value)
	}
}

// setNum keeps the unboxed number of the entry at position i in step
// with the value that was stored in it.
func (tb *LTable) setNum(i int, value LValue) {
	switch v := value.(type) {
	case LNumber:
		*tb.needNum(i) = fieldNum{num: math.Float64bits(float64(v)), kind: fieldFloat}
	case LInteger:
		*tb.needNum(i) = fieldNum{num: uint64(v), kind: fieldInt}
	default:
		if tb.nums != nil {
			*tb.numAt(i) = fieldNum{}
		}
	}
}

// enableTyped lets a table that was created before the JIT was switched
// on use the unboxed representations, like the tables created after it.
func (tb *LTable) enableTyped() {
	tb.typedOK = true
	for i := range tb.fields {
		tb.setNum(i, tb.fields[i].value)
	}
}

// fieldRemoved reports whether the entry at position i was removed from
// the table. (The value of a number entry is a number, also while stale.)
func (tb *LTable) fieldRemoved(i int) bool {
	return tb.fields[i].value == LNil
}

// appendField adds an entry for key behind the others and returns its
// position.
func (tb *LTable) appendField(key string) int {
	if tb.fields == nil {
		tb.fields = make([]tableField, 0, defaultHashCap)
	}
	room := cap(tb.fields)
	tb.fields = append(tb.fields, tableField{key: key})
	if cap(tb.fields) != room {
		tb.regrowNums(len(tb.fields) - 1)
	}
	return len(tb.fields) - 1
}

// fieldLinearMax is the number of string-keyed entries up to which a
// lookup scans the entries instead of using the hash index: comparing a
// handful of strings is faster than hashing one, and small tables need
// no index.
const fieldLinearMax = 8

// fieldSeed seeds the hash function of the field indexes of this process.
var fieldSeed = maphash.MakeSeed()

// Array part representations of a LTable.
//
// A table starts with a generic array part ([]LValue). When typed arrays are
// enabled for the table (see LState.newTable) and the first array element is
// a number, the array part is stored unboxed as []int64 or []float64. The
// unboxed representation is pointer free (cheap for the garbage collector)
// and can be read and written directly by JIT compiled code. Storing a value
// of another type converts the array part back to the generic form.
const (
	arrayKindGeneric uint8 = iota
	arrayKindInt
	arrayKindFloat
	// arrayKindBool stores booleans as the words 0 and 1 in the same
	// slice as arrayKindInt.
	arrayKindBool
)

// wordValue converts value to an element of the word array (iarr) of an
// array part of the given kind. It reports false if the value does not
// fit that kind.
func wordValue(kind uint8, value LValue) (int64, bool) {
	switch v := value.(type) {
	case LInteger:
		if kind == arrayKindInt {
			return int64(v), true
		}
	case LBool:
		if kind == arrayKindBool {
			if v {
				return 1, true
			}
			return 0, true
		}
	}
	return 0, false
}

// boxWord converts an element of the word array back to a value.
func (tb *LTable) boxWord(w int64) LValue {
	if tb.akind == arrayKindBool {
		return LBool(w != 0)
	}
	return boxInt(w)
}

type lValueArraySorter struct {
	L      *LState
	Fn     *LFunction
	Values []LValue
}

func (lv lValueArraySorter) Len() int {
	return len(lv.Values)
}

func (lv lValueArraySorter) Swap(i, j int) {
	lv.Values[i], lv.Values[j] = lv.Values[j], lv.Values[i]
}

func (lv lValueArraySorter) Less(i, j int) bool {
	if lv.Fn != nil {
		lv.L.Push(lv.Fn)
		lv.L.Push(lv.Values[i])
		lv.L.Push(lv.Values[j])
		lv.L.Call(2, 1)
		return LVAsBool(lv.L.reg.Pop())
	}
	return lessThan(lv.L, lv.Values[i], lv.Values[j])
}

func newLTable(acap int, hcap int) *LTable {
	if acap < 0 {
		acap = 0
	}
	if hcap < 0 {
		hcap = 0
	}
	tb := &LTable{}
	tb.Metatable = LNil
	if acap != 0 {
		tb.array = make([]LValue, 0, acap)
	}
	if hcap != 0 {
		tb.fields = make([]tableField, 0, hcap)
	}
	return tb
}

// newTable creates a table that follows the language profile and JIT
// configuration of this state.
func (ls *LState) newTable(acap int, hcap int) *LTable {
	tb := newLTable(acap, hcap)
	tb.intKeys = ls.lang55
	tb.typedOK = ls.typedArrays
	return tb
}

// boxInt converts an integer to a LValue, sharing preallocated values for
// small integers.
func boxInt(v int64) LValue {
	if v >= ipreloadMin && v <= ipreloadMax {
		return ipreloads[int(v)-ipreloadMin]
	}
	return LInteger(v)
}

// intKey returns the key value reported for the array index i.
func (tb *LTable) intKey(i int) LValue {
	if tb.intKeys {
		return boxInt(int64(i))
	}
	if i >= 0 && i < len(preloads) {
		return preloads[i]
	}
	return LNumber(i)
}

// needExtra returns the rarely used parts of the table, creating them.
func (tb *LTable) needExtra() *tableExtra {
	if tb.extra == nil {
		tb.extra = &tableExtra{}
	}
	return tb.extra
}

// beginWalk notes the start of a traversal. From the second traversal
// of a table on, the keys of its fields are kept as Lua values.
func (tb *LTable) beginWalk() {
	switch {
	case !tb.walked:
		tb.walked = true
	case len(tb.fields) > 0 && (tb.extra == nil || tb.extra.fieldKeys == nil):
		tb.needExtra().fieldKeys = make([]LValue, len(tb.fields))
	}
}

// fieldKey returns the key of the field at position i as a Lua value.
func (tb *LTable) fieldKey(i int) LValue {
	x := tb.extra
	if x == nil || x.fieldKeys == nil {
		return LString(tb.fields[i].key)
	}
	for len(x.fieldKeys) < len(tb.fields) {
		x.fieldKeys = append(x.fieldKeys, nil) // fields added since
	}
	key := x.fieldKeys[i]
	if key == nil {
		key = LString(tb.fields[i].key)
		x.fieldKeys[i] = key
	}
	return key
}

// normKey converts a number key to the canonical form used by the hash
// part: integral keys are LInteger for Lua 5.5 tables and LNumber otherwise.
func (tb *LTable) normKey(key LValue) LValue {
	switch k := key.(type) {
	case LNumber:
		if tb.intKeys {
			if i, ok := floatToInteger(float64(k)); ok {
				return LInteger(i)
			}
		}
	case LInteger:
		if !tb.intKeys {
			return LNumber(k)
		}
	}
	return key
}

// arrayLen returns the physical length of the array part.
func (tb *LTable) arrayLen() int {
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		return len(tb.iarr)
	case arrayKindFloat:
		return len(tb.farr)
	}
	return len(tb.array)
}

// slots returns the number of slots of the array part as GopherLua
// counts them: the stored elements and the nil slots behind them.
func (tb *LTable) slots() int {
	return tb.arrayLen() + tb.tail
}

// claimSlot accounts for an element that was appended to the stored
// part: it takes the first nil slot behind it, if there is one.
func (tb *LTable) claimSlot() {
	if tb.tail > 0 {
		tb.tail--
	}
}

// nilSlot accounts for nil being assigned to the 0-based index at or
// behind the end of the stored part: the array part reaches that slot.
func (tb *LTable) nilSlot(index int) {
	if n := index + 1 - tb.arrayLen(); n > tb.tail {
		tb.tail = n
	}
}

// storeTail turns the nil slots behind the stored part into stored
// elements of a generic array part.
func (tb *LTable) storeTail() {
	tb.genericize()
	for ; tb.tail > 0; tb.tail-- {
		tb.array = append(tb.array, LNil)
	}
}

// arrayGet returns the element at the 0-based index of the array part.
func (tb *LTable) arrayGet(index int) LValue {
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		return tb.boxWord(tb.iarr[index])
	case arrayKindFloat:
		return LNumber(tb.farr[index])
	}
	return tb.array[index]
}

// genericize converts an unboxed array part to the generic representation.
func (tb *LTable) genericize() {
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		arr := make([]LValue, len(tb.iarr), cap(tb.iarr)+1)
		for i, v := range tb.iarr {
			arr[i] = tb.boxWord(v)
		}
		tb.array = arr
		tb.iarr = nil
	case arrayKindFloat:
		arr := make([]LValue, len(tb.farr), cap(tb.farr)+1)
		for i, v := range tb.farr {
			arr[i] = LNumber(v)
		}
		tb.array = arr
		tb.farr = nil
	}
	tb.akind = arrayKindGeneric
}

// arraySet stores value in the slot with the 0-based index of the array
// part.
func (tb *LTable) arraySet(index int, value LValue) {
	n := tb.arrayLen()
	if index >= n && tb.sparseSet(index, n, value) {
		return
	}
	tb.arrayStore(index, value)
	if tb.sparse != nil && tb.arrayLen() > n {
		tb.absorb()
	}
}

// arrayStore stores value at the 0-based index of the stored elements,
// growing or converting them as needed. Behind their end it appends, or
// fills the slots in between with nil; a nil there is only counted.
func (tb *LTable) arrayStore(index int, value LValue) {
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		alen := len(tb.iarr)
		if v, ok := wordValue(tb.akind, value); ok {
			if index < alen {
				tb.iarr[index] = v
				return
			}
			if index == alen {
				tb.iarr = append(tb.iarr, v)
				tb.claimSlot()
				return
			}
		} else if value == LNil {
			if index == alen-1 {
				// (an unboxed array cannot hold nil: the slot of the
				// last element becomes a nil slot behind the array)
				tb.iarr = tb.iarr[:index]
				tb.tail++
				return
			}
			if index >= alen {
				tb.nilSlot(index)
				return
			}
		}
		tb.genericize()
	case arrayKindFloat:
		alen := len(tb.farr)
		if v, ok := value.(LNumber); ok {
			if index < alen {
				tb.farr[index] = float64(v)
				return
			}
			if index == alen {
				tb.farr = append(tb.farr, float64(v))
				tb.claimSlot()
				return
			}
		} else if value == LNil {
			if index == alen-1 {
				tb.farr = tb.farr[:index]
				tb.tail++
				return
			}
			if index >= alen {
				tb.nilSlot(index)
				return
			}
		}
		tb.genericize()
	}
	alen := len(tb.array)
	switch {
	case index >= alen && value == LNil:
		// nil at or behind the end: GopherLua appends nil slots up to
		// that position, which are counted instead of stored here
		tb.nilSlot(index)
	case index == alen:
		tb.claimSlot()
		if alen == 0 && tb.typedOK {
			switch v := value.(type) {
			case LInteger:
				tb.iarr = make([]int64, 1, typedCap(cap(tb.array)))
				tb.iarr[0] = int64(v)
				tb.array = nil
				tb.akind = arrayKindInt
				return
			case LNumber:
				tb.farr = make([]float64, 1, typedCap(cap(tb.array)))
				tb.farr[0] = float64(v)
				tb.array = nil
				tb.akind = arrayKindFloat
				return
			case LBool:
				tb.iarr = make([]int64, 1, typedCap(cap(tb.array)))
				tb.iarr[0], _ = wordValue(arrayKindBool, v)
				tb.array = nil
				tb.akind = arrayKindBool
				return
			}
		}
		if tb.array == nil {
			tb.array = make([]LValue, 0, defaultArrayCap)
		}
		tb.array = append(tb.array, value)
	case index > alen:
		// a value behind the end: the slots in between are stored
		if tb.array == nil {
			tb.array = make([]LValue, 0, defaultArrayCap)
		}
		tb.storeTail()
		if alen = len(tb.array); index < alen {
			tb.array[index] = value
			return
		}
		for i := 0; i < (index - alen); i++ {
			tb.array = append(tb.array, LNil)
		}
		tb.array = append(tb.array, value)
	default:
		tb.array[index] = value
	}
}

// typedCap returns the initial capacity of an unboxed array part.
func typedCap(c int) int {
	if c < 8 {
		return 8
	}
	return c
}

// Len returns length of this LTable without using __len.
func (tb *LTable) Len() int {
	if tb.sparse != nil {
		// (sparse elements lie behind the stored ones and are not nil)
		return tb.sparseLast() + 1
	}
	if tb.akind != arrayKindGeneric {
		return tb.arrayLen()
	}
	if tb.array == nil {
		return 0
	}
	for i := len(tb.array) - 1; i >= 0; i-- {
		if tb.array[i] != LNil {
			return i + 1
		}
	}
	return 0
}

// Append appends a given LValue to this LTable: behind the last slot of
// the array part or, if that slot holds nil, behind the last element
// that is not nil. Both are the position after the border Len reports.
func (tb *LTable) Append(value LValue) {
	if value == LNil {
		return
	}
	tb.arraySet(tb.Len(), value)
}

// Insert inserts a given LValue at position `i` in this table.
func (tb *LTable) Insert(i int, value LValue) {
	if i > tb.slots() {
		tb.RawSetInt(i, value)
		return
	}
	if i <= 0 {
		tb.RawSet(LNumber(i), value)
		return
	}
	i -= 1
	if tb.sparse != nil || (i > tb.arrayLen() && tb.tail > tableSparseGap) {
		tb.insertSlot(i, value)
		return
	}
	if i > tb.arrayLen() {
		// between the nil slots behind the stored elements
		tb.storeTail()
	}
	tb.insertStored(i, value)
}

// insertStored inserts value at the 0-based index i of the stored
// elements (at most their length).
func (tb *LTable) insertStored(i int, value LValue) {
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		if v, ok := wordValue(tb.akind, value); ok {
			tb.iarr = append(tb.iarr, 0)
			copy(tb.iarr[i+1:], tb.iarr[i:])
			tb.iarr[i] = v
			return
		}
		tb.genericize()
	case arrayKindFloat:
		if v, ok := value.(LNumber); ok {
			tb.farr = append(tb.farr, 0)
			copy(tb.farr[i+1:], tb.farr[i:])
			tb.farr[i] = float64(v)
			return
		}
		tb.genericize()
	}
	if tb.array == nil {
		tb.array = make([]LValue, 0, defaultArrayCap)
	}
	tb.array = append(tb.array, LNil)
	copy(tb.array[i+1:], tb.array[i:])
	tb.array[i] = value
}

// MaxN returns a maximum number key that nil value does not exist before it.
func (tb *LTable) MaxN() int {
	return tb.Len()
}

// Remove removes from this table the element at a given position.
func (tb *LTable) Remove(pos int) LValue {
	larray := tb.arrayLen()
	slots := larray + tb.tail
	if slots == 0 {
		return LNil
	}
	i := pos - 1
	if i >= slots {
		return LNil
	}
	if i < 0 {
		i = slots - 1 // the last slot
	}
	if i >= larray {
		// one of the slots behind the stored elements goes away; the
		// slots behind it move down
		oldval := tb.slotGet(i)
		if tb.sparse != nil {
			tb.sparseDelete(i)
			tb.sparseShift(i+1, -1)
		}
		tb.tail--
		tb.absorb()
		return oldval
	}
	oldval := tb.removeStored(i)
	tb.sparseShift(larray, -1)
	return oldval
}

// removeStored removes the stored element at the 0-based index i.
func (tb *LTable) removeStored(i int) LValue {
	larray := tb.arrayLen()
	oldval := LNil
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		switch {
		case i >= larray:
		case i == larray-1 || i < 0:
			oldval = tb.boxWord(tb.iarr[larray-1])
			tb.iarr = tb.iarr[:larray-1]
		default:
			oldval = tb.boxWord(tb.iarr[i])
			copy(tb.iarr[i:], tb.iarr[i+1:])
			tb.iarr = tb.iarr[:larray-1]
		}
		return oldval
	case arrayKindFloat:
		switch {
		case i >= larray:
		case i == larray-1 || i < 0:
			oldval = LNumber(tb.farr[larray-1])
			tb.farr = tb.farr[:larray-1]
		default:
			oldval = LNumber(tb.farr[i])
			copy(tb.farr[i:], tb.farr[i+1:])
			tb.farr = tb.farr[:larray-1]
		}
		return oldval
	}
	switch {
	case i >= larray:
		// nothing to do
	case i == larray-1 || i < 0:
		oldval = tb.array[larray-1]
		tb.array = tb.array[:larray-1]
	default:
		oldval = tb.array[i]
		copy(tb.array[i:], tb.array[i+1:])
		tb.array[larray-1] = nil
		tb.array = tb.array[:larray-1]
	}
	return oldval
}

// RawSet sets a given LValue to a given index without the __newindex metamethod.
// It is recommended to use `RawSetString` or `RawSetInt` for performance
// if you already know the given LValue is a string or number.
func (tb *LTable) RawSet(key LValue, value LValue) {
	switch v := key.(type) {
	case LNumber:
		if isArrayKey(v) {
			tb.arraySet(int(v)-1, value)
			return
		}
	case LInteger:
		if v >= 1 && v < LInteger(MaxArrayIndex) {
			tb.arraySet(int(v)-1, value)
			return
		}
	case LString:
		tb.RawSetString(string(v), value)
		return
	}
	tb.RawSetH(key, value)
}

// RawSetInt sets a given LValue at a position `key` without the __newindex metamethod.
func (tb *LTable) RawSetInt(key int, value LValue) {
	if key < 1 || key >= MaxArrayIndex {
		tb.RawSetH(LNumber(key), value)
		return
	}
	tb.arraySet(key-1, value)
}

// RawSetString sets a given LValue to a given string index without the __newindex metamethod.
func (tb *LTable) RawSetString(key string, value LValue) {
	i := tb.findField(key)
	if i >= 0 {
		if old := tb.fields[i].value; tb.watched && old != value && tb.fieldKind(i) == fieldBoxed {
			tb.noteFieldChange(old)
		}
		tb.fieldSet(i, value)
		return
	}
	if value == LNil {
		return
	}
	tb.fieldSet(tb.appendField(key), value)
	if tb.watchedKeys {
		// compiled code relies on the key being absent
		tb.version++
	}
	switch n := len(tb.fields); {
	case n <= fieldLinearMax:
	case 2*n > len(tb.fieldIndex):
		tb.indexFields(n)
	default:
		tb.indexField(n - 1)
	}
}

// reserveFields makes room for n more string-keyed entries.
func (tb *LTable) reserveFields(n int) {
	if need := len(tb.fields) + n; need > cap(tb.fields) {
		fields := make([]tableField, len(tb.fields), need)
		copy(fields, tb.fields)
		tb.fields = fields
		tb.regrowNums(len(fields))
	}
}

// indexFields rebuilds the hash index for a table that is going to hold
// n string-keyed entries. The index is an open-addressing table of entry
// positions plus one (zero marks a free slot) that is at most half full.
// Entries are never removed from tb.fields, so neither are index slots.
func (tb *LTable) indexFields(n int) {
	size := 4 * fieldLinearMax
	for size < 2*n {
		size *= 2
	}
	if cap(tb.fields) > n {
		// the table was sized in advance: do the same for its index
		for size < 2*cap(tb.fields) {
			size *= 2
		}
	}
	tb.fieldIndex = make([]uint32, size)
	for i := range tb.fields {
		tb.indexField(i)
	}
}

// indexField adds the entry at position i to the hash index.
func (tb *LTable) indexField(i int) {
	mask := uint64(len(tb.fieldIndex) - 1)
	slot := maphash.String(fieldSeed, tb.fields[i].key) & mask
	for tb.fieldIndex[slot] != 0 {
		slot = (slot + 1) & mask
	}
	tb.fieldIndex[slot] = uint32(i + 1)
}

// findField returns the position of the string-keyed entry key in
// tb.fields (which may hold LNil if the entry was removed), or -1.
func (tb *LTable) findField(key string) int {
	if tb.fieldIndex == nil {
		for i := range tb.fields {
			if tb.fields[i].key == key {
				return i
			}
		}
		return -1
	}
	mask := uint64(len(tb.fieldIndex) - 1)
	for slot := maphash.String(fieldSeed, key) & mask; ; slot = (slot + 1) & mask {
		pos := tb.fieldIndex[slot]
		if pos == 0 {
			return -1
		}
		if tb.fields[pos-1].key == key {
			return int(pos - 1)
		}
	}
}

// noteFieldChange bumps the table version when a watched table replaces
// or removes an entry that JIT compiled code may have speculated on.
func (tb *LTable) noteFieldChange(old LValue) {
	switch old.(type) {
	case *LFunction, *LTable:
		tb.version++
	}
}

// RawSetH sets a given LValue to a given index without the __newindex metamethod.
func (tb *LTable) RawSetH(key LValue, value LValue) {
	if s, ok := key.(LString); ok {
		tb.RawSetString(string(s), value)
		return
	}
	key = tb.normKey(key)
	x := tb.extra
	if value == LNil {
		// TODO keys and k2i should also be removed
		if x != nil {
			delete(x.dict, key)
		}
		return
	}
	if x == nil {
		x = tb.needExtra()
	}
	if x.dict == nil {
		x.dict = make(map[LValue]LValue)
		x.keys = []LValue{}
		x.k2i = map[LValue]int{}
	}
	x.dict[key] = value
	if _, ok := x.k2i[key]; !ok {
		x.k2i[key] = len(x.keys)
		x.keys = append(x.keys, key)
	}
}

// dictGet returns the value of an entry whose key is neither a string
// nor an array index.
func (tb *LTable) dictGet(key LValue) LValue {
	if x := tb.extra; x != nil {
		if v, ok := x.dict[key]; ok {
			return v
		}
	}
	return LNil
}

// keyIndex returns the position of key among the keys that are neither
// strings nor array indexes, and whether the table has ever held it.
func (tb *LTable) keyIndex(key LValue) (int, bool) {
	if x := tb.extra; x != nil {
		i, ok := x.k2i[tb.normKey(key)]
		return i, ok
	}
	return 0, false
}

// RawGet returns an LValue associated with a given key without __index metamethod.
func (tb *LTable) RawGet(key LValue) LValue {
	switch v := key.(type) {
	case LNumber:
		if isArrayKey(v) {
			index := int(v) - 1
			if index >= tb.arrayLen() {
				return tb.slotGet(index)
			}
			return tb.arrayGet(index)
		}
		key = tb.normKey(key)
	case LInteger:
		if v >= 1 && v < LInteger(MaxArrayIndex) {
			index := int(v) - 1
			if index >= tb.arrayLen() {
				return tb.slotGet(index)
			}
			return tb.arrayGet(index)
		}
		key = tb.normKey(key)
	case LString:
		return tb.RawGetString(string(v))
	}
	return tb.dictGet(key)
}

// RawGetInt returns an LValue at position `key` without __index metamethod.
func (tb *LTable) RawGetInt(key int) LValue {
	index := int(key) - 1
	if index < 0 {
		return LNil
	}
	if index >= tb.arrayLen() {
		return tb.slotGet(index)
	}
	return tb.arrayGet(index)
}

// RawGet returns an LValue associated with a given key without __index metamethod.
func (tb *LTable) RawGetH(key LValue) LValue {
	if s, sok := key.(LString); sok {
		return tb.RawGetString(string(s))
	}
	return tb.dictGet(tb.normKey(key))
}

// RawGetString returns an LValue associated with a given key without __index metamethod.
func (tb *LTable) RawGetString(key string) LValue {
	if i := tb.findField(key); i >= 0 {
		return tb.fieldGet(i)
	}
	return LNil
}

// ForEach iterates over this table of elements, yielding each in turn to a given function.
func (tb *LTable) ForEach(cb func(LValue, LValue)) {
	tb.beginWalk()
	switch tb.akind {
	case arrayKindInt, arrayKindBool:
		for i := 0; i < len(tb.iarr); i++ {
			cb(tb.intKey(i+1), tb.boxWord(tb.iarr[i]))
		}
	case arrayKindFloat:
		for i := 0; i < len(tb.farr); i++ {
			cb(tb.intKey(i+1), LNumber(tb.farr[i]))
		}
	default:
		for i, v := range tb.array {
			if v != LNil {
				cb(tb.intKey(i+1), v)
			}
		}
	}
	if tb.sparse != nil {
		for _, index := range append([]int(nil), tb.sparseSorted()...) {
			// (the callback may have changed the table)
			if v := tb.slotGet(index); v != LNil {
				cb(tb.intKey(index+1), v)
			}
		}
	}
	for i := 0; i < len(tb.fields); i++ {
		if !tb.fieldRemoved(i) {
			cb(tb.fieldKey(i), tb.fieldGet(i))
		}
	}
	// (the other keys in the order in which they were added, like Next)
	if x := tb.extra; x != nil {
		for i := 0; i < len(x.keys); i++ {
			key := x.keys[i]
			if v, ok := x.dict[key]; ok && v != LNil {
				cb(key, v)
			}
		}
	}
}

// This function is equivalent to lua_next ( http://www.lua.org/manual/5.1/manual.html#lua_next ).
func (tb *LTable) Next(key LValue) (LValue, LValue) {
	idx := -1
	if key == LNil {
		idx = 0
		tb.beginWalk()
	} else {
		switch k := key.(type) {
		case LNumber:
			if k > 0 && isInteger(k) && k < LNumber(MaxArrayIndex) {
				idx = int(k)
			}
		case LInteger:
			if k > 0 && k < LInteger(MaxArrayIndex) {
				idx = int(k)
			}
		}
	}
	if idx >= 0 {
		n := tb.arrayLen()
		for ; idx < n; idx++ {
			if v := tb.arrayGet(idx); v != LNil {
				return tb.intKey(idx + 1), v
			}
		}
		if tb.sparse != nil {
			if index, v, ok := tb.sparseNext(idx); ok {
				return tb.intKey(index + 1), v
			}
		}
		return tb.nextField(0)
	}
	if s, ok := key.(LString); ok {
		if i := tb.findField(string(s)); i >= 0 {
			return tb.nextField(i + 1)
		}
		return LNil, LNil
	}
	i, _ := tb.keyIndex(key)
	return tb.nextKey(i + 1)
}

// nextField continues a traversal at position i of the string-keyed
// entries, followed by the other hash keys.
func (tb *LTable) nextField(i int) (LValue, LValue) {
	for ; i < len(tb.fields); i++ {
		if !tb.fieldRemoved(i) {
			return tb.fieldKey(i), tb.fieldGet(i)
		}
	}
	return tb.nextKey(0)
}

// nextKey continues a traversal at position i of the hash keys that are
// not strings.
func (tb *LTable) nextKey(i int) (LValue, LValue) {
	x := tb.extra
	if x == nil {
		return LNil, LNil
	}
	for ; i < len(x.keys); i++ {
		key := x.keys[i]
		if v := x.dict[key]; v != nil && v != LNil {
			return key, v
		}
	}
	return LNil, LNil
}

// Clone returns a shallow copy of the table: the copy holds the same keys
// and values, but not the metatable. It is equivalent to creating a table
// and raw-setting every entry, without the intermediate allocations.
func (tb *LTable) Clone() *LTable {
	c := &LTable{Metatable: LNil, akind: tb.akind, typedOK: tb.typedOK, intKeys: tb.intKeys, tail: tb.tail}
	if len(tb.array) > 0 {
		c.array = append(make([]LValue, 0, len(tb.array)), tb.array...)
	}
	if s := tb.sparse; s != nil {
		c.sparse = &tableSparse{elems: make(map[int]LValue, len(s.elems))}
		for k, v := range s.elems {
			c.sparse.elems[k] = v
		}
	}
	if len(tb.iarr) > 0 {
		c.iarr = append(make([]int64, 0, len(tb.iarr)), tb.iarr...)
	}
	if len(tb.farr) > 0 {
		c.farr = append(make([]float64, 0, len(tb.farr)), tb.farr...)
	}
	if len(tb.fields) > 0 {
		c.fields = make([]tableField, 0, len(tb.fields))
		for i := range tb.fields {
			// removed entries are dropped: nothing refers to their positions
			if !tb.fieldRemoved(i) {
				c.fields = append(c.fields, tableField{key: tb.fields[i].key})
				c.fieldSet(len(c.fields)-1, tb.fieldGet(i))
			}
		}
		if len(c.fields) > fieldLinearMax {
			c.indexFields(len(c.fields))
		}
	}
	if x := tb.extra; x != nil {
		for _, key := range x.keys {
			if v := x.dict[key]; v != nil && v != LNil {
				c.RawSetH(key, v)
			}
		}
	}
	return c
}
