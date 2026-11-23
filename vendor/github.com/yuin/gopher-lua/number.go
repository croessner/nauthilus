package lua

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// LanguageVersion selects the Lua language profile of a LState.
//
// The zero value is Lua51, which keeps the exact behavior of upstream
// GopherLua (all numbers are float64 LNumber values). Lua55 enables the
// integer subtype (LInteger), bitwise operators, integer division, _ENV,
// to-be-closed variables and the Lua 5.5 standard library.
type LanguageVersion int

const (
	// Lua51 is the GopherLua compatible Lua 5.1 profile (default).
	Lua51 LanguageVersion = iota
	// Lua55 is the Lua 5.5 profile.
	Lua55
)

func (v LanguageVersion) String() string {
	if v == Lua55 {
		return "Lua 5.5"
	}
	return "Lua 5.1"
}

// LInteger is the integer subtype of Lua numbers (Lua 5.3+). Its Type() is
// LTNumber. Values of this type are only produced by the runtime in the
// Lua55 language profile, but Go code may push them in any profile.
type LInteger int64

func (i LInteger) String() string   { return strconv.FormatInt(int64(i), 10) }
func (i LInteger) Type() LValueType { return LTNumber }

// Format implements fmt.Formatter.
func (i LInteger) Format(f fmt.State, c rune) {
	switch c {
	case 'q', 's':
		defaultFormat(i.String(), f, c)
	case 'b', 'c', 'd', 'o', 'x', 'X', 'U':
		defaultFormat(int64(i), f, c)
	case 'e', 'E', 'f', 'F', 'g', 'G':
		defaultFormat(float64(i), f, c)
	case 'i':
		defaultFormat(int64(i), f, 'd')
	default:
		defaultFormat(int64(i), f, c)
	}
}

// LVIsInteger reports whether v is a number with the integer subtype.
func LVIsInteger(v LValue) bool {
	_, ok := v.(LInteger)
	return ok
}

// LVAsInteger converts a number LValue to an int64. Floats are converted
// only if they have an exact integer representation. The second result
// reports whether the conversion succeeded.
func LVAsInteger(v LValue) (int64, bool) {
	switch n := v.(type) {
	case LInteger:
		return int64(n), true
	case LNumber:
		return floatToInteger(float64(n))
	}
	return 0, false
}

const (
	maxInteger = math.MaxInt64
	minInteger = math.MinInt64
)

// floatToInteger converts f to an int64 if it has an exact representation.
func floatToInteger(f float64) (int64, bool) {
	if f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
		i := int64(f)
		if float64(i) == f {
			return i, true
		}
	}
	return 0, false
}

// floatToIntegerFloor converts floor(f) to an int64 if it fits.
func floatToIntegerFloor(f float64) (int64, bool) {
	f = math.Floor(f)
	if f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
		return int64(f), true
	}
	return 0, false
}

// floatToIntegerCeil converts ceil(f) to an int64 if it fits.
func floatToIntegerCeil(f float64) (int64, bool) {
	f = math.Ceil(f)
	if f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
		return int64(f), true
	}
	return 0, false
}

// intFloorDiv implements Lua integer floor division. b must not be zero.
func intFloorDiv(a, b int64) int64 {
	if b == -1 {
		return -a // wraps for minInteger, like the reference implementation
	}
	q := a / b
	if (a%b != 0) && ((a ^ b) < 0) {
		q--
	}
	return q
}

// intMod implements Lua integer modulo. b must not be zero.
func intMod(a, b int64) int64 {
	if b == -1 {
		return 0
	}
	r := a % b
	if r != 0 && (r^b) < 0 {
		r += b
	}
	return r
}

// floatMod implements Lua float modulo (result has the sign of b).
func floatMod(a, b float64) float64 {
	m := math.Mod(a, b)
	if m > 0 {
		if b < 0 {
			m += b
		}
	} else if m < 0 && b != m {
		if b > 0 {
			m += b
		}
	}
	return m
}

// intShiftLeft implements the Lua logical shift. Negative n shifts right.
func intShiftLeft(a, n int64) int64 {
	if n <= -64 || n >= 64 {
		return 0
	}
	if n >= 0 {
		return int64(uint64(a) << uint(n))
	}
	return int64(uint64(a) >> uint(-n))
}

// intPow computes a^b for floats the way Lua does (always float).
func numPow(a, b float64) float64 {
	if b == 2 {
		return a * a
	}
	return math.Pow(a, b)
}

/* comparisons between integers and floats (exact, see lvm.c) {{{ */

func intFitsFloat(i int64) bool {
	return -(1<<53) <= i && i <= (1<<53)
}

func ltIntFloat(i int64, f float64) bool {
	if intFitsFloat(i) {
		return float64(i) < f
	}
	if fi, ok := floatToIntegerCeil(f); ok {
		return i < fi
	}
	return f > 0 // false for NaN and for f below every integer
}

func leIntFloat(i int64, f float64) bool {
	if intFitsFloat(i) {
		return float64(i) <= f
	}
	if fi, ok := floatToIntegerFloor(f); ok {
		return i <= fi
	}
	return f > 0
}

func ltFloatInt(f float64, i int64) bool {
	if intFitsFloat(i) {
		return f < float64(i)
	}
	if fi, ok := floatToIntegerFloor(f); ok {
		return fi < i
	}
	return f < 0
}

func leFloatInt(f float64, i int64) bool {
	if intFitsFloat(i) {
		return f <= float64(i)
	}
	if fi, ok := floatToIntegerCeil(f); ok {
		return fi <= i
	}
	return f < 0
}

// numLess reports lhs < rhs for two number values; ok is false if either
// operand is not a number.
func numLess(lhs, rhs LValue) (result bool, ok bool) {
	switch l := lhs.(type) {
	case LNumber:
		switch r := rhs.(type) {
		case LNumber:
			return l < r, true
		case LInteger:
			return ltFloatInt(float64(l), int64(r)), true
		}
	case LInteger:
		switch r := rhs.(type) {
		case LInteger:
			return l < r, true
		case LNumber:
			return ltIntFloat(int64(l), float64(r)), true
		}
	}
	return false, false
}

// numLessEq reports lhs <= rhs for two number values.
func numLessEq(lhs, rhs LValue) (result bool, ok bool) {
	switch l := lhs.(type) {
	case LNumber:
		switch r := rhs.(type) {
		case LNumber:
			return l <= r, true
		case LInteger:
			return leFloatInt(float64(l), int64(r)), true
		}
	case LInteger:
		switch r := rhs.(type) {
		case LInteger:
			return l <= r, true
		case LNumber:
			return leIntFloat(int64(l), float64(r)), true
		}
	}
	return false, false
}

// numEquals compares two number values mathematically.
func numEquals(lhs, rhs LValue) bool {
	switch l := lhs.(type) {
	case LNumber:
		switch r := rhs.(type) {
		case LNumber:
			return l == r
		case LInteger:
			fi, ok := floatToInteger(float64(l))
			return ok && fi == int64(r)
		}
	case LInteger:
		switch r := rhs.(type) {
		case LInteger:
			return l == r
		case LNumber:
			fi, ok := floatToInteger(float64(r))
			return ok && fi == int64(l)
		}
	}
	return false
}

/* }}} */

/* number <-> string conversions {{{ */

// fmtFloat55 formats a float the way Lua 5.5 does ("%.15g", falling back
// to "%.17g" when the short form does not round-trip, plus a ".0" suffix
// for integral values).
func fmtFloat55(f float64) string {
	if math.IsInf(f, 0) {
		if f > 0 {
			return "inf"
		}
		return "-inf"
	}
	if math.IsNaN(f) {
		return "nan"
	}
	s := strconv.FormatFloat(f, 'g', 15, 64)
	if v, err := strconv.ParseFloat(s, 64); err != nil || v != f {
		s = strconv.FormatFloat(f, 'g', 17, 64)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '-' && (c < '0' || c > '9') {
			return s
		}
	}
	return s + ".0"
}

// fmtFloat14 formats a float with "%.14g" (the Lua 5.1 - 5.4 number format).
func fmtFloat14(f float64) string {
	if math.IsInf(f, 0) {
		if f > 0 {
			return "inf"
		}
		return "-inf"
	}
	if math.IsNaN(f) {
		return "nan"
	}
	return strconv.FormatFloat(f, 'g', 14, 64)
}

func isLuaSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

func hexDigitValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// str2Integer converts a string to an integer following Lua 5.5 rules
// (decimal without overflow, or hexadecimal with wrap-around).
func str2Integer(s string) (int64, bool) {
	i, n := 0, len(s)
	for i < n && isLuaSpace(s[i]) {
		i++
	}
	neg := false
	if i < n && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	var a uint64
	empty := true
	if i+1 < n && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		i += 2
		for ; i < n; i++ {
			d, ok := hexDigitValue(s[i])
			if !ok {
				break
			}
			a = a*16 + uint64(d)
			empty = false
		}
	} else {
		for ; i < n && s[i] >= '0' && s[i] <= '9'; i++ {
			d := uint64(s[i] - '0')
			if a >= maxInteger/10 && (a > maxInteger/10 || d > maxInteger%10+boolToUint64(neg)) {
				return 0, false // overflow: not representable as integer
			}
			a = a*10 + d
			empty = false
		}
	}
	for i < n && isLuaSpace(s[i]) {
		i++
	}
	if empty || i != n {
		return 0, false
	}
	if neg {
		return int64(0 - a), true
	}
	return int64(a), true
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// str2Float converts a string to a float following Lua 5.5 rules (decimal
// or hexadecimal floats; "inf" and "nan" are rejected).
func str2Float(s string) (float64, bool) {
	s = strings.TrimFunc(s, func(r rune) bool { return r < 128 && isLuaSpace(byte(r)) })
	if len(s) == 0 {
		return 0, false
	}
	body := s
	if body[0] == '-' || body[0] == '+' {
		body = body[1:]
	}
	if len(body) > 1 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X') {
		return parseHexFloat(s)
	}
	digits := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
			digits = true
		case c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-':
		default:
			return 0, false
		}
	}
	if !digits {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f, true
		}
		return 0, false
	}
	return f, true
}

// parseHexFloat parses a C99 hexadecimal float where the binary exponent
// is optional (as accepted by Lua).
func parseHexFloat(s string) (float64, bool) {
	i, n := 0, len(s)
	neg := false
	if s[i] == '-' || s[i] == '+' {
		neg = s[i] == '-'
		i++
	}
	i += 2 // skip 0x
	var mant float64
	exp := 0
	anyDigit, seenDot := false, false
	for ; i < n; i++ {
		c := s[i]
		if c == '.' {
			if seenDot {
				return 0, false
			}
			seenDot = true
			continue
		}
		d, ok := hexDigitValue(c)
		if !ok {
			break
		}
		anyDigit = true
		mant = mant*16 + float64(d)
		if seenDot {
			exp -= 4
		}
	}
	if !anyDigit {
		return 0, false
	}
	if i < n && (s[i] == 'p' || s[i] == 'P') {
		i++
		eneg := false
		if i < n && (s[i] == '-' || s[i] == '+') {
			eneg = s[i] == '-'
			i++
		}
		if i >= n {
			return 0, false
		}
		e := 0
		for ; i < n && s[i] >= '0' && s[i] <= '9'; i++ {
			if e < 100000 {
				e = e*10 + int(s[i]-'0')
			}
		}
		if eneg {
			e = -e
		}
		exp += e
	}
	if i != n {
		return 0, false
	}
	f := math.Ldexp(mant, exp)
	if neg {
		f = -f
	}
	return f, true
}

// str2Number55 converts a string to a number value following Lua 5.5
// rules: an LInteger if the string denotes an integer, else an LNumber.
func str2Number55(s string) (LValue, bool) {
	if i, ok := str2Integer(s); ok {
		return LInteger(i), true
	}
	if f, ok := str2Float(s); ok {
		return LNumber(f), true
	}
	return nil, false
}

/* }}} */

/* profile dependent helpers on LState {{{ */

// is55 reports whether this state runs the Lua 5.5 language profile.
func (ls *LState) is55() bool { return ls.lang55 }

// newInt returns the number value used by this language profile for an
// integral quantity: an LInteger in Lua 5.5, an LNumber otherwise.
func (ls *LState) newInt(i int64) LValue {
	if ls.lang55 {
		return LInteger(i)
	}
	return LNumber(i)
}

// numToString converts a number value to its string representation in
// this language profile.
func (ls *LState) numToString(v LValue) string {
	switch n := v.(type) {
	case LInteger:
		return strconv.FormatInt(int64(n), 10)
	case LNumber:
		if ls.lang55 {
			return fmtFloat55(float64(n))
		}
		return n.String()
	}
	return v.String()
}

// valueToString converts strings and numbers to a string in this language
// profile (the counterpart of LVAsString).
func (ls *LState) valueToString(v LValue) string {
	switch n := v.(type) {
	case LString:
		return string(n)
	case LInteger:
		return strconv.FormatInt(int64(n), 10)
	case LNumber:
		if ls.lang55 {
			return fmtFloat55(float64(n))
		}
		return n.String()
	}
	return ""
}

// strToNumber converts a string to a number in this language profile.
func (ls *LState) strToNumber(s string) (LValue, bool) {
	if ls.lang55 {
		return str2Number55(s)
	}
	if n, err := parseNumber(s); err == nil {
		return n, true
	}
	return nil, false
}

// toNumberValue coerces a number or numeric string to a number value.
func (ls *LState) toNumberValue(v LValue) (LValue, bool) {
	switch n := v.(type) {
	case LNumber, LInteger:
		return v, true
	case LString:
		return ls.strToNumber(string(n))
	}
	return nil, false
}

/* }}} */
