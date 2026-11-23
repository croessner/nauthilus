package lua

import "hash/maphash"

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
)

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
	return LNumber(i)
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
	case arrayKindInt:
		return len(tb.iarr)
	case arrayKindFloat:
		return len(tb.farr)
	}
	return len(tb.array)
}

// arrayGet returns the element at the 0-based index of the array part.
func (tb *LTable) arrayGet(index int) LValue {
	switch tb.akind {
	case arrayKindInt:
		return boxInt(tb.iarr[index])
	case arrayKindFloat:
		return LNumber(tb.farr[index])
	}
	return tb.array[index]
}

// genericize converts an unboxed array part to the generic representation.
func (tb *LTable) genericize() {
	switch tb.akind {
	case arrayKindInt:
		arr := make([]LValue, len(tb.iarr), cap(tb.iarr)+1)
		for i, v := range tb.iarr {
			arr[i] = boxInt(v)
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

// arraySet stores value at the 0-based index of the array part, growing
// or converting the array part as needed.
func (tb *LTable) arraySet(index int, value LValue) {
	switch tb.akind {
	case arrayKindInt:
		alen := len(tb.iarr)
		if v, ok := value.(LInteger); ok {
			if index < alen {
				tb.iarr[index] = int64(v)
				return
			}
			if index == alen {
				tb.iarr = append(tb.iarr, int64(v))
				return
			}
		} else if value == LNil {
			if index == alen-1 {
				tb.iarr = tb.iarr[:index]
				return
			}
			if index >= alen {
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
				return
			}
		} else if value == LNil {
			if index == alen-1 {
				tb.farr = tb.farr[:index]
				return
			}
			if index >= alen {
				return
			}
		}
		tb.genericize()
	}
	alen := len(tb.array)
	switch {
	case index == alen:
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
			}
		}
		if tb.array == nil {
			tb.array = make([]LValue, 0, defaultArrayCap)
		}
		tb.array = append(tb.array, value)
	case index > alen:
		if value == LNil && tb.typedOK {
			return
		}
		if tb.array == nil {
			tb.array = make([]LValue, 0, defaultArrayCap)
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

// Append appends a given LValue to this LTable.
func (tb *LTable) Append(value LValue) {
	if value == LNil {
		return
	}
	if tb.akind != arrayKindGeneric {
		tb.arraySet(tb.arrayLen(), value)
		return
	}
	if len(tb.array) == 0 || tb.array[len(tb.array)-1] != LNil {
		tb.arraySet(len(tb.array), value)
	} else {
		i := len(tb.array) - 2
		for ; i >= 0; i-- {
			if tb.array[i] != LNil {
				break
			}
		}
		tb.array[i+1] = value
	}
}

// Insert inserts a given LValue at position `i` in this table.
func (tb *LTable) Insert(i int, value LValue) {
	alen := tb.arrayLen()
	if i > alen {
		tb.RawSetInt(i, value)
		return
	}
	if i <= 0 {
		tb.RawSet(LNumber(i), value)
		return
	}
	i -= 1
	switch tb.akind {
	case arrayKindInt:
		if v, ok := value.(LInteger); ok {
			tb.iarr = append(tb.iarr, 0)
			copy(tb.iarr[i+1:], tb.iarr[i:])
			tb.iarr[i] = int64(v)
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
	if larray == 0 {
		return LNil
	}
	i := pos - 1
	oldval := LNil
	switch tb.akind {
	case arrayKindInt:
		switch {
		case i >= larray:
		case i == larray-1 || i < 0:
			oldval = boxInt(tb.iarr[larray-1])
			tb.iarr = tb.iarr[:larray-1]
		default:
			oldval = boxInt(tb.iarr[i])
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
		f := &tb.fields[i]
		if tb.watched && f.value != value {
			tb.noteFieldChange(f.value)
		}
		f.value = value
		return
	}
	if value == LNil {
		return
	}
	if tb.fields == nil {
		tb.fields = make([]tableField, 0, defaultHashCap)
	}
	tb.fields = append(tb.fields, tableField{key: key, value: value})
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
	if tb.dict == nil {
		tb.dict = make(map[LValue]LValue)
	}
	if tb.keys == nil {
		tb.keys = []LValue{}
		tb.k2i = map[LValue]int{}
	}

	if value == LNil {
		// TODO tb.keys and tb.k2i should also be removed
		delete(tb.dict, key)
	} else {
		tb.dict[key] = value
		if _, ok := tb.k2i[key]; !ok {
			tb.k2i[key] = len(tb.keys)
			tb.keys = append(tb.keys, key)
		}
	}
}

// RawGet returns an LValue associated with a given key without __index metamethod.
func (tb *LTable) RawGet(key LValue) LValue {
	switch v := key.(type) {
	case LNumber:
		if isArrayKey(v) {
			index := int(v) - 1
			if index >= tb.arrayLen() {
				return LNil
			}
			return tb.arrayGet(index)
		}
		key = tb.normKey(key)
	case LInteger:
		if v >= 1 && v < LInteger(MaxArrayIndex) {
			index := int(v) - 1
			if index >= tb.arrayLen() {
				return LNil
			}
			return tb.arrayGet(index)
		}
		key = tb.normKey(key)
	case LString:
		return tb.RawGetString(string(v))
	}
	if tb.dict == nil {
		return LNil
	}
	if v, ok := tb.dict[key]; ok {
		return v
	}
	return LNil
}

// RawGetInt returns an LValue at position `key` without __index metamethod.
func (tb *LTable) RawGetInt(key int) LValue {
	index := int(key) - 1
	if index < 0 || index >= tb.arrayLen() {
		return LNil
	}
	return tb.arrayGet(index)
}

// RawGet returns an LValue associated with a given key without __index metamethod.
func (tb *LTable) RawGetH(key LValue) LValue {
	if s, sok := key.(LString); sok {
		return tb.RawGetString(string(s))
	}
	if tb.dict == nil {
		return LNil
	}
	if v, ok := tb.dict[tb.normKey(key)]; ok {
		return v
	}
	return LNil
}

// RawGetString returns an LValue associated with a given key without __index metamethod.
func (tb *LTable) RawGetString(key string) LValue {
	if i := tb.findField(key); i >= 0 {
		return tb.fields[i].value
	}
	return LNil
}

// ForEach iterates over this table of elements, yielding each in turn to a given function.
func (tb *LTable) ForEach(cb func(LValue, LValue)) {
	switch tb.akind {
	case arrayKindInt:
		for i := 0; i < len(tb.iarr); i++ {
			cb(tb.intKey(i+1), boxInt(tb.iarr[i]))
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
	for i := 0; i < len(tb.fields); i++ {
		if f := tb.fields[i]; f.value != LNil {
			cb(LString(f.key), f.value)
		}
	}
	if tb.dict != nil {
		for k, v := range tb.dict {
			if v != LNil {
				cb(k, v)
			}
		}
	}
}

// This function is equivalent to lua_next ( http://www.lua.org/manual/5.1/manual.html#lua_next ).
func (tb *LTable) Next(key LValue) (LValue, LValue) {
	idx := -1
	if key == LNil {
		idx = 0
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
		return tb.nextField(0)
	}
	if s, ok := key.(LString); ok {
		if i := tb.findField(string(s)); i >= 0 {
			return tb.nextField(i + 1)
		}
		return LNil, LNil
	}
	return tb.nextKey(tb.k2i[tb.normKey(key)] + 1)
}

// nextField continues a traversal at position i of the string-keyed
// entries, followed by the other hash keys.
func (tb *LTable) nextField(i int) (LValue, LValue) {
	for ; i < len(tb.fields); i++ {
		if f := &tb.fields[i]; f.value != LNil {
			return LString(f.key), f.value
		}
	}
	return tb.nextKey(0)
}

// nextKey continues a traversal at position i of the hash keys that are
// not strings.
func (tb *LTable) nextKey(i int) (LValue, LValue) {
	for ; i < len(tb.keys); i++ {
		key := tb.keys[i]
		if v := tb.dict[key]; v != nil && v != LNil {
			return key, v
		}
	}
	return LNil, LNil
}

// Clone returns a shallow copy of the table: the copy holds the same keys
// and values, but not the metatable. It is equivalent to creating a table
// and raw-setting every entry, without the intermediate allocations.
func (tb *LTable) Clone() *LTable {
	c := &LTable{Metatable: LNil, akind: tb.akind, typedOK: tb.typedOK, intKeys: tb.intKeys}
	if len(tb.array) > 0 {
		c.array = append(make([]LValue, 0, len(tb.array)), tb.array...)
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
			if tb.fields[i].value != LNil {
				c.fields = append(c.fields, tb.fields[i])
			}
		}
		if len(c.fields) > fieldLinearMax {
			c.indexFields(len(c.fields))
		}
	}
	for _, key := range tb.keys {
		if v := tb.dict[key]; v != nil && v != LNil {
			c.RawSetH(key, v)
		}
	}
	return c
}
