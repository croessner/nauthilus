package lua

import (
	"math"
	"strings"
	"unsafe"
)

// This file implements string.pack, string.packsize and string.unpack of
// the Lua 5.5 profile (a port of the reference lstrlib.c).

const (
	// packMaxIntSize is the maximum size of a packed integer in bytes.
	packMaxIntSize = 16
	// packIntSize is the size of a Lua integer in bytes.
	packIntSize = 8
	// packMaxSize is the largest size the format language can express.
	packMaxSize = math.MaxInt64

	// native sizes (in bytes) of the C types behind the format options;
	// they follow the LP64 data model of the reference build.
	packSizeShort  = 2
	packSizeInt    = 4
	packSizeLong   = 8
	packSizeSizeT  = 8
	packSizeFloat  = 4
	packSizeDouble = 8
	// packNativeAlign is the native maximum alignment ("!" without size);
	// the reference build aligns to its largest scalar type (long double).
	packNativeAlign = 16
)

// packOption classifies one item of a pack format.
type packOption int

const (
	packInt       packOption = iota // signed integers
	packUint                        // unsigned integers
	packFloat                       // single-precision floats
	packNumber                      // Lua floats
	packDouble                      // double-precision floats
	packChar                        // fixed-length strings
	packString                      // strings with prefixed length
	packZstr                        // zero-terminated strings
	packPadding                     // padding
	packPaddAlign                   // padding for alignment
	packNop                         // no-op (configuration or spaces)
)

// packNativeLittle reports whether the host is little endian.
var packNativeLittle = func() bool {
	x := uint16(1)
	return *(*byte)(unsafe.Pointer(&x)) == 1
}()

// packHeader is the state of a format string being interpreted.
type packHeader struct {
	L        *LState
	fmt      string
	pos      int
	little   bool
	maxAlign int64
}

// newPackHeader returns the initial state for format argument 1. Like the
// reference implementation, the format ends at the first NUL byte.
func newPackHeader(L *LState) *packHeader {
	format := strArg55(L, 1)
	if i := strings.IndexByte(format, 0); i >= 0 {
		format = format[:i]
	}
	return &packHeader{L: L, fmt: format, little: packNativeLittle, maxAlign: 1}
}

// more reports whether format items are left.
func (h *packHeader) more() bool { return h.pos < len(h.fmt) }

// isDigit reports whether the next format character is a decimal digit.
func (h *packHeader) isDigit() bool {
	return h.pos < len(h.fmt) && '0' <= h.fmt[h.pos] && h.fmt[h.pos] <= '9'
}

// getNum reads an optional decimal number; df is returned if there is
// none.
func (h *packHeader) getNum(df int64) int64 {
	if !h.isDigit() {
		return df
	}
	a := int64(0)
	for {
		a = a*10 + int64(h.fmt[h.pos]-'0')
		h.pos++
		if !h.isDigit() || a > (packMaxSize-9)/10 {
			break
		}
	}
	return a
}

// getNumLimit reads an optional integral size and checks its limits.
func (h *packHeader) getNumLimit(df int64) int64 {
	sz := h.getNum(df)
	if sz > packMaxIntSize || sz <= 0 {
		h.L.RaiseError("integral size (%d) out of limits [1,%d]", sz, packMaxIntSize)
	}
	return sz
}

// getOption reads the next format option and returns its kind and size.
func (h *packHeader) getOption() (packOption, int64) {
	opt := h.fmt[h.pos]
	h.pos++
	switch opt {
	case 'b':
		return packInt, 1
	case 'B':
		return packUint, 1
	case 'h':
		return packInt, packSizeShort
	case 'H':
		return packUint, packSizeShort
	case 'l':
		return packInt, packSizeLong
	case 'L':
		return packUint, packSizeLong
	case 'j':
		return packInt, packIntSize
	case 'J':
		return packUint, packIntSize
	case 'T':
		return packUint, packSizeSizeT
	case 'f':
		return packFloat, packSizeFloat
	case 'n':
		return packNumber, packSizeDouble
	case 'd':
		return packDouble, packSizeDouble
	case 'i':
		return packInt, h.getNumLimit(packSizeInt)
	case 'I':
		return packUint, h.getNumLimit(packSizeInt)
	case 's':
		return packString, h.getNumLimit(packSizeSizeT)
	case 'c':
		size := h.getNum(-1)
		if size == -1 {
			h.L.RaiseError("missing size for format option 'c'")
		}
		return packChar, size
	case 'z':
		return packZstr, 0
	case 'x':
		return packPadding, 1
	case 'X':
		return packPaddAlign, 0
	case ' ':
	case '<':
		h.little = true
	case '>':
		h.little = false
	case '=':
		h.little = packNativeLittle
	case '!':
		h.maxAlign = h.getNumLimit(packNativeAlign)
	default:
		h.L.RaiseError("invalid format option '%c'", opt)
	}
	return packNop, 0
}

// getDetails reads the next option and computes, besides its kind and
// size, the padding needed to align it at offset totalSize.
func (h *packHeader) getDetails(totalSize int64) (opt packOption, size int64, ntoalign int64) {
	opt, size = h.getOption()
	align := size             // usually, alignment follows size
	if opt == packPaddAlign { // 'X' gets alignment from following option
		invalid := !h.more()
		if !invalid {
			var next packOption
			next, align = h.getOption()
			invalid = next == packChar || align == 0
		}
		if invalid {
			h.L.ArgError(1, "invalid next option for option 'X'")
		}
	}
	if align <= 1 || opt == packChar { // need no alignment?
		return opt, size, 0
	}
	if align > h.maxAlign { // enforce maximum alignment
		align = h.maxAlign
	}
	if align&(align-1) != 0 { // not a power of 2?
		h.L.ArgError(1, "format asks for alignment not power of 2")
	}
	return opt, size, (align - (totalSize & (align - 1))) & (align - 1)
}

// appendPackedInt appends the size low bytes of n in the given byte
// order; a negative value wider than a Lua integer is sign extended.
func appendPackedInt(buf []byte, n uint64, little bool, size int, neg bool) []byte {
	start := len(buf)
	buf = append(buf, make([]byte, size)...)
	out := buf[start:]
	for i := 0; i < size; i++ {
		b := byte(n)
		n >>= 8
		if neg && i >= packIntSize {
			b = 0xff
		}
		if little {
			out[i] = b
		} else {
			out[size-1-i] = b
		}
	}
	return buf
}

// unpackInt reads a size byte integer from data in the given byte order.
func unpackInt(L *LState, data string, little bool, size int, signed bool) int64 {
	at := func(i int) byte {
		if little {
			return data[i]
		}
		return data[size-1-i]
	}
	limit := size
	if limit > packIntSize {
		limit = packIntSize
	}
	res := uint64(0)
	for i := limit - 1; i >= 0; i-- {
		res = res<<8 | uint64(at(i))
	}
	if size < packIntSize { // real size smaller than a Lua integer?
		if signed { // needs sign extension?
			mask := uint64(1) << (uint(size)*8 - 1)
			res = (res ^ mask) - mask
		}
	} else if size > packIntSize { // must check unread bytes
		mask := byte(0)
		if signed && int64(res) < 0 {
			mask = 0xff
		}
		for i := limit; i < size; i++ {
			if at(i) != mask {
				L.RaiseError("%d-byte integer does not fit into Lua Integer", size)
			}
		}
	}
	return int64(res)
}

// appendPackedFloat appends the IEEE 754 representation of f using size
// bytes (4 or 8).
func appendPackedFloat(buf []byte, f float64, little bool, size int) []byte {
	if size == packSizeFloat {
		return appendPackedInt(buf, uint64(math.Float32bits(float32(f))), little, size, false)
	}
	return appendPackedInt(buf, math.Float64bits(f), little, size, false)
}

// packItem appends the packed form of argument arg for option opt and
// returns the buffer and the number of bytes added beyond size.
func packItem(L *LState, buf []byte, opt packOption, size int64, little bool, arg int) ([]byte, int64) {
	switch opt {
	case packInt: // signed integers
		n := L.CheckInt64(arg)
		if size < packIntSize { // need overflow check?
			lim := int64(1) << (uint(size)*8 - 1)
			if !(-lim <= n && n < lim) {
				L.ArgError(arg, "integer overflow")
			}
		}
		return appendPackedInt(buf, uint64(n), little, int(size), n < 0), 0
	case packUint: // unsigned integers
		n := L.CheckInt64(arg)
		if size < packIntSize && uint64(n) >= uint64(1)<<(uint(size)*8) {
			L.ArgError(arg, "unsigned overflow")
		}
		return appendPackedInt(buf, uint64(n), little, int(size), false), 0
	case packFloat, packNumber, packDouble:
		return appendPackedFloat(buf, float64(L.CheckNumber(arg)), little, int(size)), 0
	case packChar: // fixed-size string
		s := strArg55(L, arg)
		if int64(len(s)) > size {
			L.ArgError(arg, "string longer than given size")
		}
		buf = append(buf, s...)
		return append(buf, make([]byte, int(size)-len(s))...), 0 // padding
	case packString: // strings with length count
		s := strArg55(L, arg)
		if size < packIntSize && uint64(len(s)) >= uint64(1)<<(uint(size)*8) {
			L.ArgError(arg, "string length does not fit in given size")
		}
		buf = appendPackedInt(buf, uint64(len(s)), little, int(size), false)
		return append(buf, s...), int64(len(s))
	case packZstr: // zero-terminated string
		s := strArg55(L, arg)
		if strings.IndexByte(s, 0) >= 0 {
			L.ArgError(arg, "string contains zeros")
		}
		buf = append(buf, s...)
		return append(buf, 0), int64(len(s)) + 1
	case packPadding:
		buf = append(buf, 0)
	}
	return buf, 0
}

// str55Pack implements string.pack(fmt, v1, v2, ...).
func str55Pack(L *LState) int {
	h := newPackHeader(L)
	L.Push(LNil) // like the reference: a missing argument is reported as nil
	arg := 1     // current argument to pack
	totalSize := int64(0)
	var buf []byte
	for h.more() {
		opt, size, ntoalign := h.getDetails(totalSize)
		if size > maxStringSize55-totalSize || ntoalign > maxStringSize55-totalSize-size {
			L.ArgError(arg, "result too long")
		}
		totalSize += ntoalign + size
		buf = append(buf, make([]byte, ntoalign)...) // fill alignment
		if opt != packPadding && opt != packPaddAlign && opt != packNop {
			arg++
		}
		var extra int64
		buf, extra = packItem(L, buf, opt, size, h.little, arg)
		totalSize += extra
	}
	L.Push(LString(buf))
	return 1
}

// str55PackSize implements string.packsize(fmt) for fixed-size formats.
func str55PackSize(L *LState) int {
	h := newPackHeader(L)
	totalSize := int64(0)
	for h.more() {
		opt, size, ntoalign := h.getDetails(totalSize)
		if opt == packString || opt == packZstr {
			L.ArgError(1, "variable-length format")
		}
		size += ntoalign // total space used by option
		if totalSize > packMaxSize-size {
			L.ArgError(1, "format result too large")
		}
		totalSize += size
	}
	L.Push(L.newInt(totalSize))
	return 1
}

// unpackFloat reads a float of size bytes (4 or 8) from data.
func unpackFloat(L *LState, data string, little bool, size int) LNumber {
	bits := uint64(unpackInt(L, data, little, size, false))
	if size == packSizeFloat {
		return LNumber(math.Float32frombits(uint32(bits)))
	}
	return LNumber(math.Float64frombits(bits))
}

// str55Unpack implements string.unpack(fmt, s [, pos]); the position
// behind the last read item is returned as an extra result.
func str55Unpack(L *LState) int {
	h := newPackHeader(L)
	data := strArg55(L, 2)
	ld := int64(len(data))
	pos := posRelatI55(L.OptInt64(3, 1), len(data)) - 1
	if pos > ld {
		L.ArgError(3, "initial position out of string")
	}
	n := 0 // number of results
	for h.more() {
		opt, size, ntoalign := h.getDetails(pos)
		if size > ld-pos || ntoalign > ld-pos-size {
			L.ArgError(2, "data string too short")
		}
		pos += ntoalign                        // skip alignment
		checkStack55(L, 2, "too many results") // item + next position
		item := data[pos : pos+size]
		n++
		switch opt {
		case packInt, packUint:
			L.Push(L.newInt(unpackInt(L, item, h.little, int(size), opt == packInt)))
		case packFloat, packNumber, packDouble:
			L.Push(unpackFloat(L, item, h.little, int(size)))
		case packChar:
			L.Push(LString(item))
		case packString:
			slen := uint64(unpackInt(L, item, h.little, int(size), false))
			if slen > uint64(ld-pos-size) {
				L.ArgError(2, "data string too short")
			}
			L.Push(LString(data[pos+size : pos+size+int64(slen)]))
			pos += int64(slen) // skip string
		case packZstr:
			slen := strings.IndexByte(data[pos:], 0)
			if slen < 0 {
				L.ArgError(2, "unfinished string for format 'z'")
			}
			L.Push(LString(data[pos : pos+int64(slen)]))
			pos += int64(slen) + 1 // skip string plus final '\0'
		default: // padding and configuration options yield no value
			n--
		}
		pos += size
	}
	L.Push(L.newInt(pos + 1)) // next position
	return n + 1
}
