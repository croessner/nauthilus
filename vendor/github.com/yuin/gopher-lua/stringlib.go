package lua

import (
	"fmt"
	"hash/fnv"
	"math"
	"strconv"
	"strings"

	"github.com/yuin/gopher-lua/pm"
)

const emptyLString LString = LString("")

func OpenString(L *LState) int {
	if L.is55() {
		return openString55(L)
	}
	var mod *LTable
	//_, ok := L.G.builtinMts[int(LTString)]
	//if !ok {
	mod = L.RegisterModule(StringLibName, strFuncs).(*LTable)
	gmatch := L.NewClosure(strGmatch, L.NewFunction(strGmatchIter))
	mod.RawSetString("gmatch", gmatch)
	mod.RawSetString("gfind", gmatch)
	mod.RawSetString("__index", mod)
	L.G.builtinMts[int(LTString)] = mod
	//}
	L.Push(mod)
	return 1
}

var strFuncs = map[string]LGFunction{
	"byte":    strByte,
	"char":    strChar,
	"dump":    strDump,
	"find":    strFind,
	"format":  strFormat,
	"gsub":    strGsub,
	"len":     strLen,
	"lower":   strLower,
	"match":   strMatch,
	"rep":     strRep,
	"reverse": strReverse,
	"sub":     strSub,
	"upper":   strUpper,
}

func strByte(L *LState) int {
	str := L.CheckString(1)
	start := L.OptInt(2, 1) - 1
	end := L.OptInt(3, -1)
	l := len(str)
	if start < 0 {
		start = l + start + 1
	}
	if end < 0 {
		end = l + end + 1
	}

	if L.GetTop() == 2 {
		if start < 0 || start >= l {
			return 0
		}
		L.Push(LNumber(str[start]))
		return 1
	}

	start = intMax(start, 0)
	end = intMin(end, l)
	if end < 0 || end <= start || start >= l {
		return 0
	}

	for i := start; i < end; i++ {
		L.Push(LNumber(str[i]))
	}
	return end - start
}

func strChar(L *LState) int {
	top := L.GetTop()
	bytes := make([]byte, L.GetTop())
	for i := 1; i <= top; i++ {
		bytes[i-1] = uint8(L.CheckInt(i))
	}
	L.Push(LString(string(bytes)))
	return 1
}

func strDump(L *LState) int {
	L.RaiseError("GopherLua does not support the string.dump")
	return 0
}

func strFind(L *LState) int {
	str := L.CheckString(1)
	pattern := L.CheckString(2)
	if len(pattern) == 0 {
		L.Push(LNumber(1))
		L.Push(LNumber(0))
		return 2
	}
	init := luaIndex2StringIndex(str, L.OptInt(3, 1), true)
	plain := false
	if L.GetTop() == 4 {
		plain = LVAsBool(L.Get(4))
	}

	if plain {
		pos := strings.Index(str[init:], pattern)
		if pos < 0 {
			L.Push(LNil)
			return 1
		}
		L.Push(LNumber(init+pos) + 1)
		L.Push(LNumber(init + pos + len(pattern)))
		return 2
	}

	mds, err := pm.Find(pattern, unsafeFastStringToReadOnlyBytes(str), init, 1)
	if err != nil {
		L.RaiseError(err.Error())
	}
	if len(mds) == 0 {
		L.Push(LNil)
		return 1
	}
	md := mds[0]
	L.Push(LNumber(md.Capture(0) + 1))
	L.Push(LNumber(md.Capture(1)))
	for i := 2; i < md.CaptureLength(); i += 2 {
		if md.IsPosCapture(i) {
			L.Push(LNumber(md.Capture(i)))
		} else {
			L.Push(LString(str[md.Capture(i):md.Capture(i+1)]))
		}
	}
	return md.CaptureLength()/2 + 1
}

func strFormat(L *LState) int {
	str := L.CheckString(1)
	args := make([]interface{}, L.GetTop()-1)
	top := L.GetTop()
	for i := 2; i <= top; i++ {
		args[i-2] = L.Get(i)
	}
	npat := strings.Count(str, "%") - strings.Count(str, "%%")
	L.Push(LString(fmt.Sprintf(str, args[:intMin(npat, len(args))]...)))
	return 1
}

func strGsub(L *LState) int {
	str := L.CheckString(1)
	pat := L.CheckString(2)
	L.CheckTypes(3, LTString, LTTable, LTFunction)
	repl := L.CheckAny(3)
	limit := L.OptInt(4, -1)

	mds, err := pm.Find(pat, unsafeFastStringToReadOnlyBytes(str), 0, limit)
	if err != nil {
		L.RaiseError(err.Error())
	}
	if len(mds) == 0 {
		L.SetTop(1)
		L.Push(LNumber(0))
		return 2
	}
	switch lv := repl.(type) {
	case LString:
		L.Push(LString(strGsubStr(L, str, string(lv), mds)))
	case *LTable:
		L.Push(LString(strGsubTable(L, str, lv, mds)))
	case *LFunction:
		L.Push(LString(strGsubFunc(L, str, lv, mds)))
	}
	L.Push(LNumber(len(mds)))
	return 2
}

type replaceInfo struct {
	Indicies []int
	String   string
}

func checkCaptureIndex(L *LState, m *pm.MatchData, idx int) {
	if idx <= 2 {
		return
	}
	if idx >= m.CaptureLength() {
		L.RaiseError("invalid capture index")
	}
}

func capturedString(L *LState, m *pm.MatchData, str string, idx int) string {
	checkCaptureIndex(L, m, idx)
	if idx >= m.CaptureLength() && idx == 2 {
		idx = 0
	}
	if m.IsPosCapture(idx) {
		return fmt.Sprint(m.Capture(idx))
	} else {
		return str[m.Capture(idx):m.Capture(idx+1)]
	}

}

func strGsubDoReplace(str string, info []replaceInfo) string {
	offset := 0
	buf := []byte(str)
	for _, replace := range info {
		oldlen := len(buf)
		b1 := append([]byte(""), buf[0:offset+replace.Indicies[0]]...)
		b2 := []byte("")
		index2 := offset + replace.Indicies[1]
		if index2 <= len(buf) {
			b2 = append(b2, buf[index2:len(buf)]...)
		}
		buf = append(b1, replace.String...)
		buf = append(buf, b2...)
		offset += len(buf) - oldlen
	}
	return string(buf)
}

func strGsubStr(L *LState, str string, repl string, matches []*pm.MatchData) string {
	infoList := make([]replaceInfo, 0, len(matches))
	for _, match := range matches {
		start, end := match.Capture(0), match.Capture(1)
		sc := newFlagScanner('%', "", "", repl)
		for c, eos := sc.Next(); !eos; c, eos = sc.Next() {
			if !sc.ChangeFlag {
				if sc.HasFlag {
					if c >= '0' && c <= '9' {
						sc.AppendString(capturedString(L, match, str, 2*(int(c)-48)))
					} else {
						sc.AppendChar('%')
						sc.AppendChar(c)
					}
					sc.HasFlag = false
				} else {
					sc.AppendChar(c)
				}
			}
		}
		infoList = append(infoList, replaceInfo{[]int{start, end}, sc.String()})
	}

	return strGsubDoReplace(str, infoList)
}

func strGsubTable(L *LState, str string, repl *LTable, matches []*pm.MatchData) string {
	infoList := make([]replaceInfo, 0, len(matches))
	for _, match := range matches {
		idx := 0
		if match.CaptureLength() > 2 { // has captures
			idx = 2
		}
		var value LValue
		if match.IsPosCapture(idx) {
			value = L.GetTable(repl, LNumber(match.Capture(idx)))
		} else {
			value = L.GetField(repl, str[match.Capture(idx):match.Capture(idx+1)])
		}
		if !LVIsFalse(value) {
			infoList = append(infoList, replaceInfo{[]int{match.Capture(0), match.Capture(1)}, LVAsString(value)})
		}
	}
	return strGsubDoReplace(str, infoList)
}

func strGsubFunc(L *LState, str string, repl *LFunction, matches []*pm.MatchData) string {
	infoList := make([]replaceInfo, 0, len(matches))
	for _, match := range matches {
		start, end := match.Capture(0), match.Capture(1)
		L.Push(repl)
		nargs := 0
		if match.CaptureLength() > 2 { // has captures
			for i := 2; i < match.CaptureLength(); i += 2 {
				if match.IsPosCapture(i) {
					L.Push(LNumber(match.Capture(i)))
				} else {
					L.Push(LString(capturedString(L, match, str, i)))
				}
				nargs++
			}
		} else {
			L.Push(LString(capturedString(L, match, str, 0)))
			nargs++
		}
		L.Call(nargs, 1)
		ret := L.reg.Pop()
		if !LVIsFalse(ret) {
			infoList = append(infoList, replaceInfo{[]int{start, end}, LVAsString(ret)})
		}
	}
	return strGsubDoReplace(str, infoList)
}

type strMatchData struct {
	str     string
	pos     int
	matches []*pm.MatchData
}

func strGmatchIter(L *LState) int {
	md := L.CheckUserData(1).Value.(*strMatchData)
	str := md.str
	matches := md.matches
	idx := md.pos
	md.pos += 1
	if idx == len(matches) {
		return 0
	}
	L.Push(L.Get(1))
	match := matches[idx]
	if match.CaptureLength() == 2 {
		L.Push(LString(str[match.Capture(0):match.Capture(1)]))
		return 1
	}

	for i := 2; i < match.CaptureLength(); i += 2 {
		if match.IsPosCapture(i) {
			L.Push(LNumber(match.Capture(i)))
		} else {
			L.Push(LString(str[match.Capture(i):match.Capture(i+1)]))
		}
	}
	return match.CaptureLength()/2 - 1
}

func strGmatch(L *LState) int {
	str := L.CheckString(1)
	pattern := L.CheckString(2)
	mds, err := pm.Find(pattern, []byte(str), 0, -1)
	if err != nil {
		L.RaiseError(err.Error())
	}
	L.Push(L.Get(UpvalueIndex(1)))
	ud := L.NewUserData()
	ud.Value = &strMatchData{str, 0, mds}
	L.Push(ud)
	return 2
}

func strLen(L *LState) int {
	str := L.CheckString(1)
	L.Push(LNumber(len(str)))
	return 1
}

func strLower(L *LState) int {
	str := L.CheckString(1)
	L.Push(LString(strings.ToLower(str)))
	return 1
}

func strMatch(L *LState) int {
	str := L.CheckString(1)
	pattern := L.CheckString(2)
	offset := L.OptInt(3, 1)
	l := len(str)
	if offset < 0 {
		offset = l + offset + 1
	}
	offset--
	if offset < 0 {
		offset = 0
	}

	mds, err := pm.Find(pattern, unsafeFastStringToReadOnlyBytes(str), offset, 1)
	if err != nil {
		L.RaiseError(err.Error())
	}
	if len(mds) == 0 {
		L.Push(LNil)
		return 0
	}
	md := mds[0]
	nsubs := md.CaptureLength() / 2
	switch nsubs {
	case 1:
		L.Push(LString(str[md.Capture(0):md.Capture(1)]))
		return 1
	default:
		for i := 2; i < md.CaptureLength(); i += 2 {
			if md.IsPosCapture(i) {
				L.Push(LNumber(md.Capture(i)))
			} else {
				L.Push(LString(str[md.Capture(i):md.Capture(i+1)]))
			}
		}
		return nsubs - 1
	}
}

func strRep(L *LState) int {
	str := L.CheckString(1)
	n := L.CheckInt(2)
	if n < 0 {
		L.Push(emptyLString)
	} else {
		L.Push(LString(strings.Repeat(str, n)))
	}
	return 1
}

func strReverse(L *LState) int {
	str := L.CheckString(1)
	bts := []byte(str)
	out := make([]byte, len(bts))
	for i, j := 0, len(bts)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = bts[j]
	}
	L.Push(LString(string(out)))
	return 1
}

func strSub(L *LState) int {
	str := L.CheckString(1)
	start := luaIndex2StringIndex(str, L.CheckInt(2), true)
	end := luaIndex2StringIndex(str, L.OptInt(3, -1), false)
	l := len(str)
	if start >= l || end < start {
		L.Push(emptyLString)
	} else {
		L.Push(LString(str[start:end]))
	}
	return 1
}

func strUpper(L *LState) int {
	str := L.CheckString(1)
	L.Push(LString(strings.ToUpper(str)))
	return 1
}

func luaIndex2StringIndex(str string, i int, start bool) int {
	if start && i != 0 {
		i -= 1
	}
	l := len(str)
	if i < 0 {
		i = l + i + 1
	}
	i = intMax(0, i)
	if !start && i > l {
		i = l
	}
	return i
}

/* Lua 5.5 profile {{{ */

const (
	// maxStringSize55 bounds the size of strings built by string.rep and
	// string.pack. The reference implementation only fails on arithmetic
	// overflow and then relies on the allocator; a Go allocation failure
	// cannot be turned into a Lua error, so the limit is checked up front.
	maxStringSize55 = math.MaxInt32
	// maxSlice55 bounds the number of values string.byte and
	// utf8.codepoint may return.
	maxSlice55 = math.MaxInt32
	// patSpecials55 lists the pattern characters that disable the plain
	// search shortcut of string.find.
	patSpecials55 = "^$*+?.([%-"
)

var strFuncs55 = map[string]LGFunction{
	"byte":     str55Byte,
	"char":     str55Char,
	"dump":     str55Dump,
	"find":     str55Find,
	"format":   str55Format,
	"gmatch":   str55Gmatch,
	"gsub":     str55Gsub,
	"len":      str55Len,
	"lower":    str55Lower,
	"match":    str55Match,
	"pack":     str55Pack,
	"packsize": str55PackSize,
	"rep":      str55Rep,
	"reverse":  str55Reverse,
	"sub":      str55Sub,
	"unpack":   str55Unpack,
	"upper":    str55Upper,
}

// openString55 opens the Lua 5.5 string library. The metatable shared by
// all strings is a separate table whose __index is the library table.
func openString55(L *LState) int {
	mod := L.RegisterModule(StringLibName, strFuncs55).(*LTable)
	mt := L.NewTable()
	mt.RawSetString("__index", mod)
	L.G.builtinMts[int(LTString)] = mt
	L.Push(mod)
	return 1
}

// strArg55 returns argument n as a string. Numbers are converted with the
// Lua 5.5 number format (floats keep their ".0" suffix).
func strArg55(L *LState, n int) string {
	switch v := L.Get(n).(type) {
	case LString:
		return string(v)
	case LNumber, LInteger:
		return L.valueToString(v)
	}
	L.TypeError(n, LTString)
	return ""
}

// optStrArg55 returns argument n as a string, or d if it is absent or nil.
func optStrArg55(L *LState, n int, d string) string {
	if L.Get(n) == LNil {
		return d
	}
	return strArg55(L, n)
}

// checkStack55 raises a stack overflow error if n more values do not fit
// on the value stack.
func checkStack55(L *LState, n int, msg string) {
	limit := L.reg.maxSize
	if limit < len(L.reg.array) {
		limit = len(L.reg.array)
	}
	if n > limit-L.reg.top {
		L.RaiseError("stack overflow (%s)", msg)
	}
}

// posRelatI55 translates a relative initial string position: negative
// means back from the end. The result is clipped to [1, inf).
func posRelatI55(pos int64, l int) int64 {
	switch {
	case pos > 0:
		return pos
	case pos == 0:
		return 1
	case pos < -int64(l):
		return 1
	}
	return int64(l) + pos + 1
}

// endPos55 reads an optional final string position (argument n) and
// clips it to [0, l].
func endPos55(L *LState, n int, def int64, l int) int64 {
	pos := L.OptInt64(n, def)
	switch {
	case pos > int64(l):
		return int64(l)
	case pos >= 0:
		return pos
	case pos < -int64(l):
		return 0
	}
	return int64(l) + pos + 1
}

// str55Len implements string.len(s).
func str55Len(L *LState) int {
	L.Push(L.newInt(int64(len(strArg55(L, 1)))))
	return 1
}

// str55Sub implements string.sub(s, i [, j]).
func str55Sub(L *LState) int {
	s := strArg55(L, 1)
	start := posRelatI55(L.CheckInt64(2), len(s))
	end := endPos55(L, 3, -1, len(s))
	if start <= end {
		L.Push(LString(s[start-1 : end]))
	} else {
		L.Push(emptyLString)
	}
	return 1
}

// str55Byte implements string.byte(s [, i [, j]]).
func str55Byte(L *LState) int {
	s := strArg55(L, 1)
	pi := L.OptInt64(2, 1)
	posi := posRelatI55(pi, len(s))
	pose := endPos55(L, 3, pi, len(s))
	if posi > pose {
		return 0 // empty interval; return no values
	}
	if pose-posi >= maxSlice55 {
		L.RaiseError("string slice too long")
	}
	n := int(pose-posi) + 1
	checkStack55(L, n, "string slice too long")
	for i := 0; i < n; i++ {
		L.Push(L.newInt(int64(s[int(posi)+i-1])))
	}
	return n
}

// str55Char implements string.char(...).
func str55Char(L *LState) int {
	n := L.GetTop()
	buf := make([]byte, n)
	for i := 1; i <= n; i++ {
		c := uint64(L.CheckInt64(i))
		if c > math.MaxUint8 {
			L.ArgError(i, "value out of range")
		}
		buf[i-1] = byte(c)
	}
	L.Push(LString(buf))
	return 1
}

// str55Dump implements string.dump. This runtime has no binary chunk
// format, so Lua functions cannot be dumped; other values are rejected
// like in the reference implementation.
func str55Dump(L *LState) int {
	if fn, ok := L.Get(1).(*LFunction); !ok || fn.IsG {
		L.ArgError(1, "Lua function expected")
	}
	L.RaiseError("unable to dump given function")
	return 0
}

// mapASCII55 returns s with every byte inside [lo, hi] shifted by delta.
// It implements the C-locale case conversions of the reference library.
func mapASCII55(s string, lo, hi byte, delta int) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; lo <= c && c <= hi {
			buf := []byte(s)
			for j := i; j < len(buf); j++ {
				if c := buf[j]; lo <= c && c <= hi {
					buf[j] = byte(int(c) + delta)
				}
			}
			return string(buf)
		}
	}
	return s
}

// str55Lower implements string.lower(s) for the C locale.
func str55Lower(L *LState) int {
	L.Push(LString(mapASCII55(strArg55(L, 1), 'A', 'Z', 'a'-'A')))
	return 1
}

// str55Upper implements string.upper(s) for the C locale.
func str55Upper(L *LState) int {
	L.Push(LString(mapASCII55(strArg55(L, 1), 'a', 'z', 'A'-'a')))
	return 1
}

// str55Reverse implements string.reverse(s) (byte-wise).
func str55Reverse(L *LState) int {
	s := strArg55(L, 1)
	out := make([]byte, len(s))
	for i, j := 0, len(s)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = s[j]
	}
	L.Push(LString(out))
	return 1
}

// str55Rep implements string.rep(s, n [, sep]).
func str55Rep(L *LState) int {
	s := strArg55(L, 1)
	n := L.CheckInt64(2)
	sep := optStrArg55(L, 3, "")
	unit := int64(len(s)) + int64(len(sep))
	if n <= 0 || unit == 0 {
		L.Push(emptyLString)
		return 1
	}
	if unit > maxStringSize55/n {
		L.RaiseError("resulting string too large")
	}
	if len(sep) == 0 {
		L.Push(LString(strings.Repeat(s, int(n))))
		return 1
	}
	buf := make([]byte, 0, int(n)*int(unit)-len(sep))
	for i := int64(0); i < n; i++ {
		if i > 0 {
			buf = append(buf, sep...)
		}
		buf = append(buf, s...)
	}
	L.Push(LString(buf))
	return 1
}

/* pattern matching {{{ */

// raisePatternError55 converts a pattern error into a Lua error.
func raisePatternError55(L *LState, err error) {
	if err != nil {
		L.RaiseError("%s", err.Error())
	}
}

// captureValue55 returns capture i of the current match [s, e) of m as a
// Lua value: a string, or an integer for a position capture.
func captureValue55(L *LState, m *pm.Matcher, src string, i, s, e int) LValue {
	start, length, err := m.Capture(i, s, e)
	raisePatternError55(L, err)
	if length == pm.CapPosition {
		return L.newInt(int64(start) + 1)
	}
	return LString(src[start : start+length])
}

// pushCaptures55 pushes the captures of the current match [s, e) of m. If
// the pattern has no captures and whole is set, the whole match is pushed.
// It returns the number of pushed values.
func pushCaptures55(L *LState, m *pm.Matcher, src string, s, e int, whole bool) int {
	nlevels := m.NumCaptures()
	if nlevels == 0 && whole {
		nlevels = 1
	}
	for i := 0; i < nlevels; i++ {
		L.Push(captureValue55(L, m, src, i, s, e))
	}
	return nlevels
}

// patternStart55 reports whether pattern p is anchored and returns the
// offset of the first pattern byte behind the anchor.
func patternStart55(p string) (anchor bool, start int) {
	if len(p) > 0 && p[0] == '^' {
		return true, 1
	}
	return false, 0
}

// str55FindAux implements string.find (find is true) and string.match.
func str55FindAux(L *LState, find bool) int {
	s := strArg55(L, 1)
	p := strArg55(L, 2)
	init := posRelatI55(L.OptInt64(3, 1), len(s)) - 1
	if init > int64(len(s)) { // start after string's end?
		L.Push(LNil) // cannot find anything
		return 1
	}
	if find && (LVAsBool(L.Get(4)) || !strings.ContainsAny(p, patSpecials55)) {
		// explicit request or no special characters: do a plain search
		if pos := strings.Index(s[init:], p); pos >= 0 {
			L.Push(L.newInt(init + int64(pos) + 1))
			L.Push(L.newInt(init + int64(pos) + int64(len(p))))
			return 2
		}
		L.Push(LNil)
		return 1
	}
	anchor, pstart := patternStart55(p)
	m := pm.NewMatcher(s, p)
	for s1 := int(init); ; s1++ {
		e, err := m.Match(s1, pstart)
		raisePatternError55(L, err)
		if e != -1 {
			if find {
				L.Push(L.newInt(int64(s1) + 1))
				L.Push(L.newInt(int64(e)))
				return pushCaptures55(L, m, s, s1, e, false) + 2
			}
			return pushCaptures55(L, m, s, s1, e, true)
		}
		if s1 >= len(s) || anchor {
			break
		}
	}
	L.Push(LNil) // not found
	return 1
}

// str55Find implements string.find(s, pattern [, init [, plain]]).
func str55Find(L *LState) int {
	return str55FindAux(L, true)
}

// str55Match implements string.match(s, pattern [, init]).
func str55Match(L *LState) int {
	return str55FindAux(L, false)
}

// str55Gmatch implements string.gmatch(s, pattern [, init]). The returned
// iterator keeps its own match state; a leading '^' is not an anchor.
func str55Gmatch(L *LState) int {
	s := strArg55(L, 1)
	p := strArg55(L, 2)
	init := posRelatI55(L.OptInt64(3, 1), len(s)) - 1
	if init > int64(len(s)) { // start after string's end?
		init = int64(len(s)) + 1
	}
	m := pm.NewMatcher(s, p)
	src, lastmatch := int(init), -1
	L.Push(L.NewFunction(func(L *LState) int {
		for ; src <= len(s); src++ {
			e, err := m.Match(src, 0)
			raisePatternError55(L, err)
			if e != -1 && e != lastmatch {
				start := src
				src, lastmatch = e, e
				return pushCaptures55(L, m, s, start, e, true)
			}
		}
		return 0 // not found
	}))
	return 1
}

// gsubAddString55 appends the replacement string repl for the match
// [s, e) to buf, expanding the %0-%9 and %% escapes.
func gsubAddString55(L *LState, m *pm.Matcher, buf []byte, src, repl string, s, e int) []byte {
	for {
		i := strings.IndexByte(repl, '%')
		if i < 0 {
			break
		}
		buf = append(buf, repl[:i]...)
		i++ // skip ESC
		var c byte
		if i < len(repl) {
			c = repl[i]
		}
		switch {
		case c == '%':
			buf = append(buf, c)
		case c == '0':
			buf = append(buf, src[s:e]...)
		case '1' <= c && c <= '9':
			buf = append(buf, L.valueToString(captureValue55(L, m, src, int(c-'1'), s, e))...)
		default:
			L.RaiseError("%s", "invalid use of '%' in replacement string")
		}
		repl = repl[i+1:]
	}
	return append(buf, repl...)
}

// gsubAddValue55 appends the replacement for the match [s, e) to buf and
// reports whether it differs from the original text.
func gsubAddValue55(L *LState, m *pm.Matcher, buf []byte, src string, s, e int, repl LValue) ([]byte, bool) {
	var value LValue
	switch r := repl.(type) {
	case *LFunction: // call the function
		L.Push(r)
		n := pushCaptures55(L, m, src, s, e, true) // all captures as arguments
		L.Call(n, 1)
		value = L.Get(-1)
		L.Pop(1)
	case *LTable: // index the table with the first capture
		value = L.GetTable(r, captureValue55(L, m, src, 0, s, e))
	default: // number or string
		return gsubAddString55(L, m, buf, src, L.valueToString(repl), s, e), true
	}
	if LVIsFalse(value) { // nil or false: keep original text
		return append(buf, src[s:e]...), false
	}
	if !LVCanConvToString(value) {
		L.RaiseError("invalid replacement value (a %s)", L.typeNameOf(value))
	}
	return append(buf, L.valueToString(value)...), true
}

// str55Gsub implements string.gsub(s, pattern, repl [, n]).
func str55Gsub(L *LState) int {
	src := strArg55(L, 1)
	p := strArg55(L, 2)
	repl := L.Get(3)
	maxS := L.OptInt64(4, int64(len(src))+1) // max replacements
	switch repl.(type) {
	case LString, LNumber, LInteger, *LTable, *LFunction:
	default:
		got := "no value"
		if L.GetTop() >= 3 {
			got = L.typeNameOf(repl)
		}
		L.ArgError(3, "string/function/table expected, got "+got)
	}
	anchor, pstart := patternStart55(p)
	m := pm.NewMatcher(src, p)
	var buf []byte
	pos, lastmatch := 0, -1
	changed := false
	n := int64(0) // replacement count
	for n < maxS {
		e, err := m.Match(pos, pstart)
		raisePatternError55(L, err)
		if e != -1 && e != lastmatch { // match?
			var ch bool
			n++
			buf, ch = gsubAddValue55(L, m, buf, src, pos, e, repl)
			changed = changed || ch
			pos, lastmatch = e, e
		} else if pos < len(src) { // otherwise, skip one character
			buf = append(buf, src[pos])
			pos++
		} else {
			break // end of subject
		}
		if anchor {
			break
		}
	}
	if !changed { // no changes: return the original string
		L.Push(LString(src))
	} else {
		L.Push(LString(append(buf, src[pos:]...)))
	}
	L.Push(L.newInt(n)) // number of substitutions
	return 2
}

/* }}} */

/* string.format {{{ */

const (
	// fmtSpanChars55 lists the characters spanned as flags, width and
	// precision of a conversion specification.
	fmtSpanChars55 = "-+ #0123456789."
	// fmtMaxSpan55 is the number of spanned characters from which a
	// specification is rejected as too long.
	fmtMaxSpan55 = 21

	fmtFlagsFloat55 = "-+ #0" // valid flags for a, e, f and g
	fmtFlagsHex55   = "-#0"   // valid flags for o, x and X
	fmtFlagsInt55   = "-+ 0"  // valid flags for d and i
	fmtFlagsUint55  = "-0"    // valid flags for u
	fmtFlagsChar55  = "-"     // valid flags for c, p and s
)

// fmtSpec55 is a parsed conversion specification of string.format
// (flags, width and precision of a C printf conversion).
type fmtSpec55 struct {
	minus, plus, space, alt, zero bool
	width                         int // -1 if absent
	prec                          int // -1 if absent
}

// fmtSkip2Digits55 skips at most two digits of form starting at i.
func fmtSkip2Digits55(form string, i int) int {
	for n := 0; n < 2 && i < len(form) && '0' <= form[i] && form[i] <= '9'; n++ {
		i++
	}
	return i
}

// checkFormat55 validates the conversion specification form ("%...c")
// against the flags allowed for its conversion; precision tells whether
// the conversion accepts a precision.
func checkFormat55(L *LState, form, flags string, precision bool) {
	i := 1 // skip '%'
	for i < len(form) && strings.IndexByte(flags, form[i]) >= 0 {
		i++ // skip flags
	}
	if i < len(form) && form[i] != '0' { // a width cannot start with '0'
		i = fmtSkip2Digits55(form, i) // skip width
		if i < len(form) && form[i] == '.' && precision {
			i = fmtSkip2Digits55(form, i+1) // skip precision
		}
	}
	if i >= len(form) || !(('a' <= form[i] && form[i] <= 'z') || ('A' <= form[i] && form[i] <= 'Z')) {
		L.RaiseError("invalid conversion specification: '%s'", form)
	}
}

// parseFmtSpec55 parses a conversion specification that passed
// checkFormat55.
func parseFmtSpec55(form string) fmtSpec55 {
	sp := fmtSpec55{width: -1, prec: -1}
	i := 1
flags:
	for ; i < len(form); i++ {
		switch form[i] {
		case '-':
			sp.minus = true
		case '+':
			sp.plus = true
		case ' ':
			sp.space = true
		case '#':
			sp.alt = true
		case '0':
			sp.zero = true
		default:
			break flags
		}
	}
	if j := fmtSkip2Digits55(form, i); j > i {
		sp.width, _ = strconv.Atoi(form[i:j])
		i = j
	}
	if i < len(form) && form[i] == '.' {
		j := fmtSkip2Digits55(form, i+1)
		sp.prec, _ = strconv.Atoi(form[i+1 : j])
	}
	return sp
}

// pad appends prefix+body to buf, padded to the field width. Zero padding
// (between prefix and body) is used when the '0' flag is set and zeroOK.
func (sp *fmtSpec55) pad(buf []byte, prefix, body string, zeroOK bool) []byte {
	fill := sp.width - len(prefix) - len(body)
	switch {
	case fill <= 0:
		buf = append(buf, prefix...)
		buf = append(buf, body...)
	case sp.minus:
		buf = append(buf, prefix...)
		buf = append(buf, body...)
		buf = append(buf, strings.Repeat(" ", fill)...)
	case sp.zero && zeroOK:
		buf = append(buf, prefix...)
		buf = append(buf, strings.Repeat("0", fill)...)
		buf = append(buf, body...)
	default:
		buf = append(buf, strings.Repeat(" ", fill)...)
		buf = append(buf, prefix...)
		buf = append(buf, body...)
	}
	return buf
}

// sign returns the sign prefix of a signed conversion.
func (sp *fmtSpec55) sign(neg bool) string {
	switch {
	case neg:
		return "-"
	case sp.plus:
		return "+"
	case sp.space:
		return " "
	}
	return ""
}

// formatInt appends the integer n converted by conv (d, i, u, o, x or X).
func (sp *fmtSpec55) formatInt(buf []byte, conv byte, n int64) []byte {
	u := uint64(n)
	prefix := ""
	base := 10
	switch conv {
	case 'd', 'i':
		if n < 0 {
			u = -u
		}
		prefix = sp.sign(n < 0)
	case 'o':
		base = 8
	case 'x', 'X':
		base = 16
	}
	digits := strconv.FormatUint(u, base)
	if sp.prec == 0 && u == 0 {
		digits = ""
	}
	if len(digits) < sp.prec {
		digits = strings.Repeat("0", sp.prec-len(digits)) + digits
	}
	if sp.alt {
		switch {
		case base == 8 && !strings.HasPrefix(digits, "0"):
			digits = "0" + digits
		case base == 16 && u != 0:
			prefix = "0x"
		}
	}
	if conv == 'X' {
		prefix, digits = strings.ToUpper(prefix), strings.ToUpper(digits)
	}
	return sp.pad(buf, prefix, digits, sp.prec < 0)
}

// fmtExponent55 returns the decimal exponent of a number formatted by
// strconv with the 'e' format.
func fmtExponent55(s string) int {
	x, _ := strconv.Atoi(s[strings.IndexByte(s, 'e')+1:])
	return x
}

// fmtTrimZeros55 removes trailing zeros (and a trailing radix point) from
// the fraction of the mantissa m.
func fmtTrimZeros55(m string) string {
	if strings.IndexByte(m, '.') < 0 {
		return m
	}
	return strings.TrimSuffix(strings.TrimRight(m, "0"), ".")
}

// fmtDecimal55 formats the finite non-negative float f like the C printf
// conversions e, f and g (conv is the lower-case conversion).
func (sp *fmtSpec55) fmtDecimal55(conv byte, f float64) string {
	prec := sp.prec
	if prec < 0 {
		prec = 6
	}
	switch conv {
	case 'e':
		s := strconv.FormatFloat(f, 'e', prec, 64)
		if sp.alt && prec == 0 {
			i := strings.IndexByte(s, 'e')
			s = s[:i] + "." + s[i:]
		}
		return s
	case 'f':
		s := strconv.FormatFloat(f, 'f', prec, 64)
		if sp.alt && prec == 0 {
			s += "."
		}
		return s
	}
	// 'g': use the style e if the exponent X of the e conversion is less
	// than -4 or not less than the precision P, else the style f with
	// precision P - 1 - X; trailing zeros are removed unless '#' is given.
	if prec == 0 {
		prec = 1
	}
	s := strconv.FormatFloat(f, 'e', prec-1, 64)
	x := fmtExponent55(s)
	if x < -4 || x >= prec {
		i := strings.IndexByte(s, 'e')
		mant, exp := s[:i], s[i:]
		if !sp.alt {
			mant = fmtTrimZeros55(mant)
		} else if strings.IndexByte(mant, '.') < 0 {
			mant += "."
		}
		return mant + exp
	}
	s = strconv.FormatFloat(f, 'f', prec-1-x, 64)
	if !sp.alt {
		return fmtTrimZeros55(s)
	}
	if strings.IndexByte(s, '.') < 0 {
		s += "."
	}
	return s
}

// fmtHexFloat55 formats the finite non-negative float f like the C printf
// conversion a without the "0x" prefix: a normalized mantissa digit, the
// hexadecimal fraction (prec digits, or the shortest exact form if prec is
// negative) and the binary exponent. Rounding is to nearest, ties to even.
func fmtHexFloat55(f float64, prec int, alt bool) string {
	const fracDigits = 13 // 52 mantissa bits
	bits := math.Float64bits(f)
	exp := int(bits>>52) & 0x7ff
	frac := bits & (1<<52 - 1)
	lead := uint64(1)
	switch {
	case exp == 0 && frac == 0:
		lead = 0
	case exp == 0: // subnormal: normalize
		exp = -1022
		for frac&(1<<52) == 0 {
			frac <<= 1
			exp--
		}
		frac &= 1<<52 - 1
	default:
		exp -= 1023
	}
	digits := fracDigits
	if prec >= 0 && prec < fracDigits {
		shift := uint(4 * (fracDigits - prec))
		rest := frac & (1<<shift - 1)
		half := uint64(1) << (shift - 1)
		frac >>= shift
		odd := frac&1 == 1
		if prec == 0 {
			odd = lead&1 == 1
		}
		if rest > half || (rest == half && odd) {
			frac++
			if frac>>(4*uint(prec)) != 0 { // carry into the leading digit
				frac = 0
				lead++
			}
		}
		digits = prec
	}
	s := ""
	if digits > 0 {
		s = fmt.Sprintf("%0*x", digits, frac)
	}
	if prec < 0 {
		s = strings.TrimRight(s, "0")
	} else if prec > fracDigits {
		s += strings.Repeat("0", prec-fracDigits)
	}
	if s != "" || alt {
		s = "." + s
	}
	sign := "+"
	if exp < 0 {
		sign, exp = "-", -exp
	}
	return strconv.FormatUint(lead, 10) + s + "p" + sign + strconv.Itoa(exp)
}

// formatFloat appends the float f converted by conv (a, A, e, E, f, g or
// G).
func (sp *fmtSpec55) formatFloat(buf []byte, conv byte, f float64) []byte {
	upper := 'A' <= conv && conv <= 'Z'
	lower := conv
	if upper {
		lower = conv + ('a' - 'A')
	}
	var prefix, body string
	zeroOK := true
	switch {
	case math.IsNaN(f): // the reference prints NaN without any sign
		body, zeroOK = "nan", false
	case math.IsInf(f, 0):
		prefix, body, zeroOK = sp.sign(f < 0), "inf", false
	default:
		prefix = sp.sign(math.Signbit(f))
		if lower == 'a' {
			prefix += "0x"
			body = fmtHexFloat55(math.Abs(f), sp.prec, sp.alt)
		} else {
			body = sp.fmtDecimal55(lower, math.Abs(f))
		}
	}
	if upper {
		prefix, body = strings.ToUpper(prefix), strings.ToUpper(body)
	}
	return sp.pad(buf, prefix, body, zeroOK)
}

// fmtPointer55 returns the %p representation of v: an address-like
// identity for collectable values and "(null)" for the others. Strings
// have no stable address in this runtime, so a content hash stands in:
// equal strings have equal identities.
func fmtPointer55(v LValue) string {
	switch o := v.(type) {
	case *LTable, *LFunction, *LUserData, *LState:
		return fmt.Sprintf("%p", o)
	case LChannel:
		return fmt.Sprintf("%p", o)
	case LString:
		h := fnv.New64a()
		h.Write([]byte(o))
		return fmt.Sprintf("0x%012x", h.Sum64()>>16)
	}
	return "(null)"
}

// fmtQuoteString55 appends s as a Lua string literal that reads back to
// the same string.
func fmtQuoteString55(buf []byte, s string) []byte {
	buf = append(buf, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\' || c == '\n':
			buf = append(buf, '\\', c)
		case c < 0x20 || c == 0x7f: // control character
			buf = append(buf, '\\')
			if i+1 < len(s) && '0' <= s[i+1] && s[i+1] <= '9' {
				buf = append(buf, fmt.Sprintf("%03d", c)...)
			} else {
				buf = strconv.AppendUint(buf, uint64(c), 10)
			}
		default:
			buf = append(buf, c)
		}
	}
	return append(buf, '"')
}

// fmtQuote55 appends the %q representation of argument arg: a literal the
// Lua reader converts back to the value.
func fmtQuote55(L *LState, buf []byte, arg int) []byte {
	switch v := L.Get(arg).(type) {
	case LString:
		return fmtQuoteString55(buf, string(v))
	case LInteger:
		if int64(v) == minInteger { // corner case: no decimal literal
			return append(buf, "0x8000000000000000"...)
		}
		return strconv.AppendInt(buf, int64(v), 10)
	case LNumber:
		f := float64(v)
		switch {
		case math.IsInf(f, 1):
			return append(buf, "1e9999"...)
		case math.IsInf(f, -1):
			return append(buf, "-1e9999"...)
		case math.IsNaN(f):
			return append(buf, "(0/0)"...)
		}
		if math.Signbit(f) {
			buf = append(buf, '-')
		}
		buf = append(buf, "0x"...)
		return append(buf, fmtHexFloat55(math.Abs(f), -1, false)...)
	case *LNilType, LBool:
		return append(buf, v.String()...)
	}
	L.ArgError(arg, "value has no literal form")
	return buf
}

// formatString appends the %s conversion of argument arg.
func (sp *fmtSpec55) formatString(L *LState, buf []byte, form string, arg int) []byte {
	s := L.ToStringMeta(L.Get(arg)).String()
	if len(form) == 2 { // no modifiers: keep the entire string
		return append(buf, s...)
	}
	if strings.IndexByte(s, 0) >= 0 {
		L.ArgError(arg, "string contains zeros")
	}
	checkFormat55(L, form, fmtFlagsChar55, true)
	*sp = parseFmtSpec55(form)
	if sp.prec < 0 && len(s) >= 100 {
		// no precision and string is too long to be formatted
		return append(buf, s...)
	}
	if sp.prec >= 0 && len(s) > sp.prec {
		s = s[:sp.prec]
	}
	return sp.pad(buf, "", s, false)
}

// fmtItem55 appends the conversion of argument arg described by the
// specification form (from '%' up to the conversion character conv).
func fmtItem55(L *LState, buf []byte, form string, conv byte, arg int) []byte {
	var sp fmtSpec55
	switch conv {
	case 'c':
		checkFormat55(L, form, fmtFlagsChar55, false)
		sp = parseFmtSpec55(form)
		return sp.pad(buf, "", string([]byte{byte(L.CheckInt64(arg))}), false)
	case 'd', 'i', 'u', 'o', 'x', 'X':
		flags := fmtFlagsHex55
		switch conv {
		case 'd', 'i':
			flags = fmtFlagsInt55
		case 'u':
			flags = fmtFlagsUint55
		}
		n := L.CheckInt64(arg)
		checkFormat55(L, form, flags, true)
		sp = parseFmtSpec55(form)
		return sp.formatInt(buf, conv, n)
	case 'a', 'A':
		checkFormat55(L, form, fmtFlagsFloat55, true)
		sp = parseFmtSpec55(form)
		return sp.formatFloat(buf, conv, float64(L.CheckNumber(arg)))
	case 'e', 'E', 'f', 'g', 'G':
		n := float64(L.CheckNumber(arg))
		checkFormat55(L, form, fmtFlagsFloat55, true)
		sp = parseFmtSpec55(form)
		return sp.formatFloat(buf, conv, n)
	case 'p':
		checkFormat55(L, form, fmtFlagsChar55, false)
		sp = parseFmtSpec55(form)
		return sp.pad(buf, "", fmtPointer55(L.Get(arg)), false)
	case 'q':
		if len(form) != 2 { // modifiers?
			L.RaiseError("%s", "specifier '%q' cannot have modifiers")
		}
		return fmtQuote55(L, buf, arg)
	case 's':
		return sp.formatString(L, buf, form, arg)
	}
	L.RaiseError("invalid conversion '%s' to 'format'", form)
	return buf
}

// str55Format implements string.format(formatstring, ...).
func str55Format(L *LState) int {
	format := strArg55(L, 1)
	top := L.GetTop()
	arg := 1
	buf := make([]byte, 0, len(format)+16)
	for i := 0; i < len(format); {
		c := format[i]
		i++
		if c != '%' {
			buf = append(buf, c)
			continue
		}
		if i < len(format) && format[i] == '%' { // %%
			buf = append(buf, '%')
			i++
			continue
		}
		arg++
		if arg > top {
			L.ArgError(arg, "no value") // too many format specifiers
		}
		span := 0
		for i+span < len(format) && strings.IndexByte(fmtSpanChars55, format[i+span]) >= 0 {
			span++
		}
		if span >= fmtMaxSpan55 {
			L.RaiseError("invalid format (too long)")
		}
		var conv byte // stays 0 if the format ends inside the specification
		end := i + span
		if end < len(format) {
			conv = format[end]
			end++
		}
		buf = fmtItem55(L, buf, format[i-1:end], conv, arg)
		i = end
	}
	L.Push(LString(buf))
	return 1
}

/* }}} */

/* }}} */
