package lua

// This file implements the utf8 library of the Lua 5.5 profile (a port of
// the reference lutf8lib.c).

const (
	utf8MaxUnicode = 0x10FFFF
	utf8MaxUTF     = 0x7FFFFFFF
	utf8MsgInvalid = "invalid UTF-8 code"
	// utf8CharPattern matches exactly one UTF-8 byte sequence.
	utf8CharPattern = "[\x00-\x7F\xC2-\xFD][\x80-\xBF]*"
)

// OpenUtf8 opens the utf8 library. OpenLibs opens it only in the Lua 5.5
// language profile.
func OpenUtf8(L *LState) int {
	mod := L.RegisterModule(Utf8LibName, utf8Funcs).(*LTable)
	mod.RawSetString("charpattern", LString(utf8CharPattern))
	L.Push(mod)
	return 1
}

var utf8Funcs = map[string]LGFunction{
	"char":      utf8Char,
	"codepoint": utf8Codepoint,
	"codes":     utf8Codes,
	"len":       utf8Len,
	"offset":    utf8Offset,
}

// utf8IsCont reports whether c is a UTF-8 continuation byte.
func utf8IsCont(c byte) bool { return c&0xC0 == 0x80 }

// utf8ByteAt returns s[i], or 0 for the position just behind the string
// (the terminating NUL the reference implementation relies on).
func utf8ByteAt(s string, i int64) byte {
	if i >= 0 && i < int64(len(s)) {
		return s[i]
	}
	return 0
}

// utf8PosRelat translates a relative string position: negative means back
// from the end; positions before the start yield 0.
func utf8PosRelat(pos int64, l int) int64 {
	switch {
	case pos >= 0:
		return pos
	case -pos > int64(l) || pos == minInteger:
		return 0
	}
	return int64(l) + pos + 1
}

// utf8Decode decodes the UTF-8 sequence starting at s[i] (i must be a
// valid index). It returns the code point and the index behind the
// sequence; ok is false for an invalid sequence. Strict decoding rejects
// surrogates and values above 10FFFF.
func utf8Decode(s string, i int64, strict bool) (code uint32, next int64, ok bool) {
	limits := [...]uint32{^uint32(0), 0x80, 0x800, 0x10000, 0x200000, 0x4000000}
	c := uint32(s[i])
	res := uint32(0)
	if c < 0x80 { // ASCII?
		res = c
	} else {
		count := 0                   // number of continuation bytes
		for ; c&0x40 != 0; c <<= 1 { // while it needs continuation bytes...
			count++
			cc := utf8ByteAt(s, i+int64(count)) // read next byte
			if !utf8IsCont(cc) {                // not a continuation byte?
				return 0, 0, false // invalid byte sequence
			}
			res = res<<6 | uint32(cc&0x3F) // add lower 6 bits from cont. byte
		}
		if count > 5 {
			return 0, 0, false
		}
		res |= (c & 0x7F) << (uint(count) * 5) // add first byte
		if res > utf8MaxUTF || res < limits[count] {
			return 0, 0, false // invalid byte sequence
		}
		i += int64(count) // skip continuation bytes read
	}
	if strict {
		// check for invalid code points; too large or surrogates
		if res > utf8MaxUnicode || (0xD800 <= res && res <= 0xDFFF) {
			return 0, 0, false
		}
	}
	return res, i + 1, true // +1 to include first byte
}

// utf8Encode appends the (extended) UTF-8 encoding of x, which must not
// exceed 7FFFFFFF.
func utf8Encode(buf []byte, x uint32) []byte {
	if x < 0x80 { // ASCII?
		return append(buf, byte(x))
	}
	var tmp [8]byte
	n := 1              // number of bytes put in tmp (backwards)
	mfb := uint32(0x3f) // maximum that fits in first byte
	for {               // add continuation bytes
		tmp[len(tmp)-n] = byte(0x80 | (x & 0x3f))
		n++
		x >>= 6   // remove added bits
		mfb >>= 1 // now there is one less bit available in first byte
		if x <= mfb {
			break
		}
	}
	tmp[len(tmp)-n] = byte((^mfb << 1) | x) // add first byte
	return append(buf, tmp[len(tmp)-n:]...)
}

// utf8Len implements utf8.len(s [, i [, j [, lax]]]): the number of
// characters that start between positions i and j, or fail plus the
// position of the first invalid byte.
func utf8Len(L *LState) int {
	s := strArg55(L, 1)
	slen := int64(len(s))
	posi := utf8PosRelat(L.OptInt64(2, 1), len(s))
	posj := utf8PosRelat(L.OptInt64(3, -1), len(s))
	lax := LVAsBool(L.Get(4))
	if !(1 <= posi && posi-1 <= slen) {
		L.ArgError(2, "initial position out of bounds")
	}
	posi--
	posj--
	if posj >= slen {
		L.ArgError(3, "final position out of bounds")
	}
	n := int64(0)
	for posi <= posj {
		_, next, ok := utf8Decode(s, posi, !lax)
		if !ok { // conversion error?
			L.Push(LNil)               // return fail ...
			L.Push(L.newInt(posi + 1)) // ... and current position
			return 2
		}
		posi = next
		n++
	}
	L.Push(L.newInt(n))
	return 1
}

// utf8Codepoint implements utf8.codepoint(s [, i [, j [, lax]]]): the code
// points of all characters that start between positions i and j.
func utf8Codepoint(L *LState) int {
	s := strArg55(L, 1)
	slen := int64(len(s))
	posi := utf8PosRelat(L.OptInt64(2, 1), len(s))
	pose := utf8PosRelat(L.OptInt64(3, posi), len(s))
	lax := LVAsBool(L.Get(4))
	if posi < 1 {
		L.ArgError(2, "out of bounds")
	}
	if pose > slen {
		L.ArgError(3, "out of bounds")
	}
	if posi > pose {
		return 0 // empty interval; return no values
	}
	if pose-posi >= maxSlice55 {
		L.RaiseError("string slice too long")
	}
	checkStack55(L, int(pose-posi)+1, "string slice too long")
	n := 0
	for i := posi - 1; i < pose; {
		code, next, ok := utf8Decode(s, i, !lax)
		if !ok {
			L.RaiseError(utf8MsgInvalid)
		}
		L.Push(L.newInt(int64(code)))
		i = next
		n++
	}
	return n
}

// utf8Char implements utf8.char(...): the concatenated UTF-8 encodings of its integer
// arguments.
func utf8Char(L *LState) int {
	n := L.GetTop()
	buf := make([]byte, 0, n)
	for i := 1; i <= n; i++ {
		code := uint64(L.CheckInt64(i))
		if code > utf8MaxUTF {
			L.ArgError(i, "value out of range")
		}
		buf = utf8Encode(buf, uint32(code))
	}
	L.Push(LString(buf))
	return 1
}

// utf8Offset implements utf8.offset(s, n [, i]): the start and end
// positions of the n-th character counting from position i (0 means the
// character at i).
func utf8Offset(L *LState) int {
	s := strArg55(L, 1)
	slen := int64(len(s))
	n := L.CheckInt64(2)
	posi := slen + 1
	if n >= 0 {
		posi = 1
	}
	posi = utf8PosRelat(L.OptInt64(3, posi), len(s))
	if !(1 <= posi && posi-1 <= slen) {
		L.ArgError(3, "position out of bounds")
	}
	posi--
	if n == 0 {
		// find beginning of current byte sequence
		for posi > 0 && utf8IsCont(utf8ByteAt(s, posi)) {
			posi--
		}
	} else {
		if utf8IsCont(utf8ByteAt(s, posi)) {
			L.RaiseError("initial position is a continuation byte")
		}
		if n < 0 {
			for n < 0 && posi > 0 { // move back
				for { // find beginning of previous character
					posi--
					if !(posi > 0 && utf8IsCont(utf8ByteAt(s, posi))) {
						break
					}
				}
				n++
			}
		} else {
			n-- // do not move for 1st character
			for n > 0 && posi < slen {
				for { // find beginning of next character
					posi++
					if !utf8IsCont(utf8ByteAt(s, posi)) { // (cannot pass final '\0')
						break
					}
				}
				n--
			}
		}
	}
	if n != 0 { // did not find given character?
		L.Push(LNil)
		return 1
	}
	L.Push(L.newInt(posi + 1))         // initial position
	if utf8ByteAt(s, posi)&0x80 != 0 { // multi-byte character?
		if utf8IsCont(utf8ByteAt(s, posi)) {
			L.RaiseError("initial position is a continuation byte")
		}
		for utf8IsCont(utf8ByteAt(s, posi+1)) {
			posi++ // skip to last continuation byte
		}
	}
	// else one-byte character: final position is the initial one
	L.Push(L.newInt(posi + 1)) // 'posi' now is the final position
	return 2
}

// utf8CodesIter is the iterator behind utf8.codes: given the string and
// the position of the previous character it returns the position and the
// code point of the next one.
func utf8CodesIter(L *LState, strict bool) int {
	s := strArg55(L, 1)
	slen := uint64(len(s))
	i, _ := L.toNumberValue(L.Get(2))
	pos, _ := LVAsInteger(i)
	n := uint64(pos)
	if n < slen {
		for utf8IsCont(utf8ByteAt(s, int64(n))) {
			n++ // go to next character
		}
	}
	if n >= slen { // (also handles original 'n' being negative)
		return 0 // no more values for iteration
	}
	code, next, ok := utf8Decode(s, int64(n), strict)
	if !ok || utf8IsCont(utf8ByteAt(s, next)) {
		L.RaiseError(utf8MsgInvalid)
	}
	L.Push(L.newInt(int64(n) + 1))
	L.Push(L.newInt(int64(code)))
	return 2
}

// utf8Codes implements utf8.codes(s [, lax]): an iterator over the characters of s.
func utf8Codes(L *LState) int {
	lax := LVAsBool(L.Get(2))
	s := strArg55(L, 1)
	if utf8IsCont(utf8ByteAt(s, 0)) {
		L.ArgError(1, utf8MsgInvalid)
	}
	L.Push(L.NewFunction(func(L *LState) int { return utf8CodesIter(L, !lax) }))
	L.Push(LString(s))
	L.Push(L.newInt(0))
	return 3
}
