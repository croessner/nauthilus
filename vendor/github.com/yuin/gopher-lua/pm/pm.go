// Lua pattern match functions for Go
package pm

import (
	"fmt"
)

const (
	EOS               = -1
	_UNKNOWN          = -2
	maxRecursionLevel = 1000000
)

/* Error {{{ */

type Error struct {
	Pos     int
	Message string
}

func newError(pos int, message string, args ...interface{}) *Error {
	if len(args) == 0 {
		return &Error{pos, message}
	}
	return &Error{pos, fmt.Sprintf(message, args...)}
}

func (e *Error) Error() string {
	switch e.Pos {
	case EOS:
		return fmt.Sprintf("%s at EOS", e.Message)
	case _UNKNOWN:
		return fmt.Sprintf("%s", e.Message)
	default:
		return fmt.Sprintf("%s at %d", e.Message, e.Pos)
	}
}

/* }}} */

/* MatchData {{{ */

type MatchData struct {
	// captured positions
	// layout
	// xxxx xxxx xxxx xxx0 : caputured positions
	// xxxx xxxx xxxx xxx1 : position captured positions
	captures []uint32
}

func newMatchState() *MatchData { return &MatchData{[]uint32{}} }

func (st *MatchData) addPosCapture(s, pos int) {
	for s+1 >= len(st.captures) {
		st.captures = append(st.captures, 0)
	}
	st.captures[s] = (uint32(pos) << 1) | 1
	st.captures[s+1] = (uint32(pos) << 1) | 1
}

func (st *MatchData) setCapture(s, pos int) uint32 {
	for s >= len(st.captures) {
		st.captures = append(st.captures, 0)
	}
	v := st.captures[s]
	st.captures[s] = (uint32(pos) << 1)
	return v
}

func (st *MatchData) restoreCapture(s int, pos uint32) { st.captures[s] = pos }

func (st *MatchData) CaptureLength() int { return len(st.captures) }

func (st *MatchData) IsPosCapture(idx int) bool { return (st.captures[idx] & 1) == 1 }

func (st *MatchData) Capture(idx int) int { return int(st.captures[idx] >> 1) }

/* }}} */

/* scanner {{{ */

type scannerState struct {
	Pos     int
	started bool
}

type scanner struct {
	src   []byte
	State scannerState
	saved scannerState
}

func newScanner(src []byte) *scanner {
	return &scanner{
		src: src,
		State: scannerState{
			Pos:     0,
			started: false,
		},
		saved: scannerState{},
	}
}

func (sc *scanner) Length() int { return len(sc.src) }

func (sc *scanner) Next() int {
	if !sc.State.started {
		sc.State.started = true
		if len(sc.src) == 0 {
			sc.State.Pos = EOS
		}
	} else {
		sc.State.Pos = sc.NextPos()
	}
	if sc.State.Pos == EOS {
		return EOS
	}
	return int(sc.src[sc.State.Pos])
}

func (sc *scanner) CurrentPos() int {
	return sc.State.Pos
}

func (sc *scanner) NextPos() int {
	if sc.State.Pos == EOS || sc.State.Pos >= len(sc.src)-1 {
		return EOS
	}
	if !sc.State.started {
		return 0
	} else {
		return sc.State.Pos + 1
	}
}

func (sc *scanner) Peek() int {
	cureof := sc.State.Pos == EOS
	ch := sc.Next()
	if !cureof {
		if sc.State.Pos == EOS {
			sc.State.Pos = len(sc.src) - 1
		} else {
			sc.State.Pos--
			if sc.State.Pos < 0 {
				sc.State.Pos = 0
				sc.State.started = false
			}
		}
	}
	return ch
}

func (sc *scanner) Save() { sc.saved = sc.State }

func (sc *scanner) Restore() { sc.State = sc.saved }

/* }}} */

/* bytecode {{{ */

type opCode int

const (
	opChar opCode = iota
	opMatch
	opTailMatch
	opJmp
	opSplit
	opSave
	opPSave
	opBrace
	opNumber
)

type inst struct {
	OpCode   opCode
	Class    class
	Operand1 int
	Operand2 int
}

/* }}} */

/* classes {{{ */

type class interface {
	Matches(ch int) bool
}

type dotClass struct{}

func (pn *dotClass) Matches(ch int) bool { return true }

type charClass struct {
	Ch int
}

func (pn *charClass) Matches(ch int) bool { return pn.Ch == ch }

type singleClass struct {
	Class int
}

func (pn *singleClass) Matches(ch int) bool {
	ret := false
	switch pn.Class {
	case 'a', 'A':
		ret = 'A' <= ch && ch <= 'Z' || 'a' <= ch && ch <= 'z'
	case 'c', 'C':
		ret = (0x00 <= ch && ch <= 0x1F) || ch == 0x7F
	case 'd', 'D':
		ret = '0' <= ch && ch <= '9'
	case 'l', 'L':
		ret = 'a' <= ch && ch <= 'z'
	case 'p', 'P':
		ret = (0x21 <= ch && ch <= 0x2f) || (0x3a <= ch && ch <= 0x40) || (0x5b <= ch && ch <= 0x60) || (0x7b <= ch && ch <= 0x7e)
	case 's', 'S':
		switch ch {
		case ' ', '\f', '\n', '\r', '\t', '\v':
			ret = true
		}
	case 'u', 'U':
		ret = 'A' <= ch && ch <= 'Z'
	case 'w', 'W':
		ret = '0' <= ch && ch <= '9' || 'A' <= ch && ch <= 'Z' || 'a' <= ch && ch <= 'z'
	case 'x', 'X':
		ret = '0' <= ch && ch <= '9' || 'a' <= ch && ch <= 'f' || 'A' <= ch && ch <= 'F'
	case 'z', 'Z':
		ret = ch == 0
	default:
		return ch == pn.Class
	}
	if 'A' <= pn.Class && pn.Class <= 'Z' {
		return !ret
	}
	return ret
}

type setClass struct {
	IsNot   bool
	Classes []class
}

func (pn *setClass) Matches(ch int) bool {
	for _, class := range pn.Classes {
		if class.Matches(ch) {
			return !pn.IsNot
		}
	}
	return pn.IsNot
}

type rangeClass struct {
	Begin class
	End   class
}

func (pn *rangeClass) Matches(ch int) bool {
	switch begin := pn.Begin.(type) {
	case *charClass:
		end, ok := pn.End.(*charClass)
		if !ok {
			return false
		}
		return begin.Ch <= ch && ch <= end.Ch
	}
	return false
}

// }}}

// patterns {{{

type pattern interface{}

type singlePattern struct {
	Class class
}

type seqPattern struct {
	MustHead bool
	MustTail bool
	Patterns []pattern
}

type repeatPattern struct {
	Type  int
	Class class
}

type posCapPattern struct{}

type capPattern struct {
	Pattern pattern
}

type numberPattern struct {
	N int
}

type bracePattern struct {
	Begin int
	End   int
}

// }}}

/* parse {{{ */

func parseClass(sc *scanner, allowset bool) class {
	ch := sc.Next()
	switch ch {
	case '%':
		return &singleClass{sc.Next()}
	case '.':
		if allowset {
			return &dotClass{}
		}
		return &charClass{ch}
	case '[':
		if allowset {
			return parseClassSet(sc)
		}
		return &charClass{ch}
	//case '^' '$', '(', ')', ']', '*', '+', '-', '?':
	//	panic(newError(sc.CurrentPos(), "invalid %c", ch))
	case EOS:
		panic(newError(sc.CurrentPos(), "unexpected EOS"))
	default:
		return &charClass{ch}
	}
}

func parseClassSet(sc *scanner) class {
	set := &setClass{false, []class{}}
	if sc.Peek() == '^' {
		set.IsNot = true
		sc.Next()
	}
	isrange := false
	for {
		ch := sc.Peek()
		switch ch {
		// case '[':
		// 	panic(newError(sc.CurrentPos(), "'[' can not be nested"))
		case EOS:
			panic(newError(sc.CurrentPos(), "unexpected EOS"))
		case ']':
			if len(set.Classes) > 0 {
				sc.Next()
				goto exit
			}
			fallthrough
		case '-':
			if len(set.Classes) > 0 {
				sc.Next()
				isrange = true
				continue
			}
			fallthrough
		default:
			set.Classes = append(set.Classes, parseClass(sc, false))
		}
		if isrange {
			begin := set.Classes[len(set.Classes)-2]
			end := set.Classes[len(set.Classes)-1]
			set.Classes = set.Classes[0 : len(set.Classes)-2]
			set.Classes = append(set.Classes, &rangeClass{begin, end})
			isrange = false
		}
	}
exit:
	if isrange {
		set.Classes = append(set.Classes, &charClass{'-'})
	}

	return set
}

func parsePattern(sc *scanner, toplevel bool) *seqPattern {
	pat := &seqPattern{}
	if toplevel {
		if sc.Peek() == '^' {
			sc.Next()
			pat.MustHead = true
		}
	}
	for {
		ch := sc.Peek()
		switch ch {
		case '%':
			sc.Save()
			sc.Next()
			switch sc.Peek() {
			case '0':
				panic(newError(sc.CurrentPos(), "invalid capture index"))
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				pat.Patterns = append(pat.Patterns, &numberPattern{sc.Next() - 48})
			case 'b':
				sc.Next()
				pat.Patterns = append(pat.Patterns, &bracePattern{sc.Next(), sc.Next()})
			default:
				sc.Restore()
				pat.Patterns = append(pat.Patterns, &singlePattern{parseClass(sc, true)})
			}
		case '.', '[', ']':
			pat.Patterns = append(pat.Patterns, &singlePattern{parseClass(sc, true)})
		//case ']':
		//	panic(newError(sc.CurrentPos(), "invalid ']'"))
		case ')':
			if toplevel {
				panic(newError(sc.CurrentPos(), "invalid ')'"))
			}
			return pat
		case '(':
			sc.Next()
			if sc.Peek() == ')' {
				sc.Next()
				pat.Patterns = append(pat.Patterns, &posCapPattern{})
			} else {
				ret := &capPattern{parsePattern(sc, false)}
				if sc.Peek() != ')' {
					panic(newError(sc.CurrentPos(), "unfinished capture"))
				}
				sc.Next()
				pat.Patterns = append(pat.Patterns, ret)
			}
		case '*', '+', '-', '?':
			sc.Next()
			if len(pat.Patterns) > 0 {
				spat, ok := pat.Patterns[len(pat.Patterns)-1].(*singlePattern)
				if ok {
					pat.Patterns = pat.Patterns[0 : len(pat.Patterns)-1]
					pat.Patterns = append(pat.Patterns, &repeatPattern{ch, spat.Class})
					continue
				}
			}
			pat.Patterns = append(pat.Patterns, &singlePattern{&charClass{ch}})
		case '$':
			if toplevel && (sc.NextPos() == sc.Length()-1 || sc.NextPos() == EOS) {
				pat.MustTail = true
			} else {
				pat.Patterns = append(pat.Patterns, &singlePattern{&charClass{ch}})
			}
			sc.Next()
		case EOS:
			sc.Next()
			goto exit
		default:
			sc.Next()
			pat.Patterns = append(pat.Patterns, &singlePattern{&charClass{ch}})
		}
	}
exit:
	return pat
}

type iptr struct {
	insts   []inst
	capture int
}

func compilePattern(p pattern, ps ...*iptr) []inst {
	var ptr *iptr
	toplevel := false
	if len(ps) == 0 {
		toplevel = true
		ptr = &iptr{[]inst{inst{opSave, nil, 0, -1}}, 2}
	} else {
		ptr = ps[0]
	}
	switch pat := p.(type) {
	case *singlePattern:
		ptr.insts = append(ptr.insts, inst{opChar, pat.Class, -1, -1})
	case *seqPattern:
		for _, cp := range pat.Patterns {
			compilePattern(cp, ptr)
		}
	case *repeatPattern:
		idx := len(ptr.insts)
		switch pat.Type {
		case '*':
			ptr.insts = append(ptr.insts,
				inst{opSplit, nil, idx + 1, idx + 3},
				inst{opChar, pat.Class, -1, -1},
				inst{opJmp, nil, idx, -1})
		case '+':
			ptr.insts = append(ptr.insts,
				inst{opChar, pat.Class, -1, -1},
				inst{opSplit, nil, idx, idx + 2})
		case '-':
			ptr.insts = append(ptr.insts,
				inst{opSplit, nil, idx + 3, idx + 1},
				inst{opChar, pat.Class, -1, -1},
				inst{opJmp, nil, idx, -1})
		case '?':
			ptr.insts = append(ptr.insts,
				inst{opSplit, nil, idx + 1, idx + 2},
				inst{opChar, pat.Class, -1, -1})
		}
	case *posCapPattern:
		ptr.insts = append(ptr.insts, inst{opPSave, nil, ptr.capture, -1})
		ptr.capture += 2
	case *capPattern:
		c0, c1 := ptr.capture, ptr.capture+1
		ptr.capture += 2
		ptr.insts = append(ptr.insts, inst{opSave, nil, c0, -1})
		compilePattern(pat.Pattern, ptr)
		ptr.insts = append(ptr.insts, inst{opSave, nil, c1, -1})
	case *bracePattern:
		ptr.insts = append(ptr.insts, inst{opBrace, nil, pat.Begin, pat.End})
	case *numberPattern:
		ptr.insts = append(ptr.insts, inst{opNumber, nil, pat.N, -1})
	}
	if toplevel {
		if p.(*seqPattern).MustTail {
			ptr.insts = append(ptr.insts, inst{opSave, nil, 1, -1}, inst{opTailMatch, nil, -1, -1})
		}
		ptr.insts = append(ptr.insts, inst{opSave, nil, 1, -1}, inst{opMatch, nil, -1, -1})
	}
	return ptr.insts
}

/* }}} parse */

/* VM {{{ */

// Simple recursive virtual machine based on the
// "Regular Expression Matching: the Virtual Machine Approach" (https://swtch.com/~rsc/regexp/regexp2.html)
func recursiveVM(src []byte, insts []inst, pc, sp, recLevel int, ms ...*MatchData) (bool, int, *MatchData) {
	recLevel++
	if recLevel > maxRecursionLevel {
		panic(newError(_UNKNOWN, "pattern/input too complex"))
	}
	var m *MatchData
	if len(ms) == 0 {
		m = newMatchState()
	} else {
		m = ms[0]
	}
redo:
	inst := insts[pc]
	switch inst.OpCode {
	case opChar:
		if sp >= len(src) || !inst.Class.Matches(int(src[sp])) {
			return false, sp, m
		}
		pc++
		sp++
		goto redo
	case opMatch:
		return true, sp, m
	case opTailMatch:
		return sp >= len(src), sp, m
	case opJmp:
		pc = inst.Operand1
		goto redo
	case opSplit:
		if ok, nsp, _ := recursiveVM(src, insts, inst.Operand1, sp, recLevel, m); ok {
			return true, nsp, m
		}
		pc = inst.Operand2
		goto redo
	case opSave:
		s := m.setCapture(inst.Operand1, sp)
		if ok, nsp, _ := recursiveVM(src, insts, pc+1, sp, recLevel, m); ok {
			return true, nsp, m
		}
		m.restoreCapture(inst.Operand1, s)
		return false, sp, m
	case opPSave:
		m.addPosCapture(inst.Operand1, sp+1)
		pc++
		goto redo
	case opBrace:
		if sp >= len(src) || int(src[sp]) != inst.Operand1 {
			return false, sp, m
		}
		count := 1
		for sp = sp + 1; sp < len(src); sp++ {
			if int(src[sp]) == inst.Operand2 {
				count--
			}
			if count == 0 {
				pc++
				sp++
				goto redo
			}
			if int(src[sp]) == inst.Operand1 {
				count++
			}
		}
		return false, sp, m
	case opNumber:
		idx := inst.Operand1 * 2
		if idx >= m.CaptureLength()-1 {
			panic(newError(_UNKNOWN, "invalid capture index"))
		}
		capture := src[m.Capture(idx):m.Capture(idx+1)]
		for i := 0; i < len(capture); i++ {
			if i+sp >= len(src) || capture[i] != src[i+sp] {
				return false, sp, m
			}
		}
		pc++
		sp += len(capture)
		goto redo
	}
	panic("should not reach here")
}

/* }}} */

/* API {{{ */

func Find(p string, src []byte, offset, limit int) (matches []*MatchData, err error) {
	defer func() {
		if v := recover(); v != nil {
			if perr, ok := v.(*Error); ok {
				err = perr
			} else {
				panic(v)
			}
		}
	}()
	pat := parsePattern(newScanner([]byte(p)), true)
	insts := compilePattern(pat)
	matches = []*MatchData{}
	for sp := offset; sp <= len(src); {
		ok, nsp, ms := recursiveVM(src, insts, 0, sp, 0)
		sp++
		if ok {
			if sp < nsp {
				sp = nsp
			}
			matches = append(matches, ms)
		}
		if len(matches) == limit || pat.MustHead {
			break
		}
	}
	return
}

/* }}} */

/* Lua 5.4/5.5 matcher {{{ */

const (
	// MaxCaptures is the maximum number of captures of a Matcher pattern.
	MaxCaptures = 32
	// CapPosition is the capture length reported for a position capture.
	CapPosition = -2

	capUnfinished = -1
	maxMatchDepth = 200
	patEscape     = '%'
)

// matchCapture is one capture slot of a Matcher: the start offset in the
// subject and the length (or capUnfinished / CapPosition).
type matchCapture struct {
	init int
	len  int
}

// Matcher matches a subject against a Lua 5.4/5.5 pattern. It is a port of
// the backtracking matcher of the reference implementation (lstrlib.c), so
// results, corner cases and error messages follow the reference
// interpreter. The leading '^' anchor is handled by the caller, which
// passes the offset of the first pattern byte to Match.
type Matcher struct {
	src     string
	pat     string
	depth   int
	level   int
	capture [MaxCaptures]matchCapture
}

// NewMatcher returns a matcher for the subject src and the pattern pat.
func NewMatcher(src, pat string) *Matcher {
	return &Matcher{src: src, pat: pat}
}

// Match tries to match the pattern, starting at pattern offset p, against
// the subject at offset s. It returns the offset just behind the match or
// -1 if there is no match. Malformed patterns and patterns that are too
// complex are reported as an *Error.
func (m *Matcher) Match(s, p int) (end int, err error) {
	defer func() {
		if v := recover(); v != nil {
			perr, ok := v.(*Error)
			if !ok {
				panic(v)
			}
			end, err = -1, perr
		}
	}()
	m.level = 0
	m.depth = maxMatchDepth
	return m.match(s, p), nil
}

// NumCaptures returns the number of captures of the last successful match.
func (m *Matcher) NumCaptures() int { return m.level }

// Capture returns capture i (zero based) of the last successful match that
// spans the subject offsets [s, e). If the pattern has no captures, capture
// 0 is the whole match. The returned length is CapPosition for a position
// capture, in which case start is the captured subject offset.
func (m *Matcher) Capture(i, s, e int) (start, length int, err error) {
	if i >= m.level {
		if i != 0 {
			return 0, 0, &Error{_UNKNOWN, fmt.Sprintf("invalid capture index %%%d", i+1)}
		}
		return s, e - s, nil
	}
	c := m.capture[i]
	if c.len == capUnfinished {
		return 0, 0, &Error{_UNKNOWN, "unfinished capture"}
	}
	return c.init, c.len, nil
}

// fail aborts the running match with a pattern error.
func (m *Matcher) fail(format string, args ...interface{}) {
	panic(&Error{_UNKNOWN, fmt.Sprintf(format, args...)})
}

// pc returns the pattern byte at offset i, or 0 behind the pattern end
// (mirroring the terminating NUL the reference implementation relies on).
func (m *Matcher) pc(i int) byte {
	if i < len(m.pat) {
		return m.pat[i]
	}
	return 0
}

// sc returns the subject byte at offset i, or 0 behind the subject end.
func (m *Matcher) sc(i int) byte {
	if i < len(m.src) {
		return m.src[i]
	}
	return 0
}

// checkCapture validates a back-reference digit and returns its capture
// index.
func (m *Matcher) checkCapture(l int) int {
	l -= '1'
	if l < 0 || l >= m.level || m.capture[l].len == capUnfinished {
		m.fail("invalid capture index %%%d", l+1)
	}
	return l
}

// captureToClose returns the index of the innermost unfinished capture.
func (m *Matcher) captureToClose() int {
	for level := m.level - 1; level >= 0; level-- {
		if m.capture[level].len == capUnfinished {
			return level
		}
	}
	m.fail("invalid pattern capture")
	return 0
}

// classEnd returns the pattern offset behind the single-character class
// that starts at p.
func (m *Matcher) classEnd(p int) int {
	c := m.pat[p]
	p++
	switch c {
	case patEscape:
		if p >= len(m.pat) {
			m.fail("malformed pattern (ends with '%%')")
		}
		return p + 1
	case '[':
		if m.pc(p) == '^' {
			p++
		}
		for { // look for a ']'
			if p >= len(m.pat) {
				m.fail("malformed pattern (missing ']')")
			}
			c = m.pat[p]
			p++
			if c == patEscape && p < len(m.pat) {
				p++ // skip escapes (e.g. '%]')
			}
			if m.pc(p) == ']' && p < len(m.pat) {
				break
			}
		}
		return p + 1
	}
	return p
}

// isASCIIClass reports whether c belongs to the C-locale character class
// selected by the lower-case class letter cl; known is false if cl is not
// a class letter.
func isASCIIClass(c byte, cl byte) (res, known bool) {
	switch cl {
	case 'a':
		return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z', true
	case 'c':
		return c < 0x20 || c == 0x7f, true
	case 'd':
		return '0' <= c && c <= '9', true
	case 'g':
		return 0x21 <= c && c <= 0x7e, true
	case 'l':
		return 'a' <= c && c <= 'z', true
	case 'p':
		return (0x21 <= c && c <= 0x2f) || (0x3a <= c && c <= 0x40) || (0x5b <= c && c <= 0x60) || (0x7b <= c && c <= 0x7e), true
	case 's':
		return c == ' ' || ('\t' <= c && c <= '\r'), true
	case 'u':
		return 'A' <= c && c <= 'Z', true
	case 'w':
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z', true
	case 'x':
		return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F', true
	case 'z': // deprecated, but still accepted by the reference
		return c == 0, true
	}
	return false, false
}

// matchClass reports whether c matches the escaped class letter cl
// ("%a", "%D", ...); other escaped characters match themselves.
func matchClass(c byte, cl byte) bool {
	lower := cl
	if 'A' <= cl && cl <= 'Z' {
		lower = cl + ('a' - 'A')
	}
	res, known := isASCIIClass(c, lower)
	if !known {
		return cl == c
	}
	if lower == cl {
		return res
	}
	return !res
}

// matchBracketClass reports whether c matches the set that starts at
// pattern offset p ('[') and ends at ec (the closing ']').
func (m *Matcher) matchBracketClass(c byte, p, ec int) bool {
	sig := true
	if m.pc(p+1) == '^' {
		sig = false
		p++ // skip the '^'
	}
	for p++; p < ec; p++ {
		if m.pat[p] == patEscape {
			p++
			if matchClass(c, m.pc(p)) {
				return sig
			}
		} else if m.pc(p+1) == '-' && p+2 < ec {
			p += 2
			if m.pat[p-2] <= c && c <= m.pat[p] {
				return sig
			}
		} else if m.pat[p] == c {
			return sig
		}
	}
	return !sig
}

// singleMatch reports whether the subject byte at s matches the single
// character class at pattern offsets [p, ep).
func (m *Matcher) singleMatch(s, p, ep int) bool {
	if s >= len(m.src) {
		return false
	}
	c := m.src[s]
	switch m.pat[p] {
	case '.':
		return true // matches any char
	case patEscape:
		return matchClass(c, m.pc(p+1))
	case '[':
		return m.matchBracketClass(c, p, ep-1)
	}
	return m.pat[p] == c
}

// matchBalance matches a "%bxy" item whose two delimiter bytes start at
// pattern offset p.
func (m *Matcher) matchBalance(s, p int) int {
	if p >= len(m.pat)-1 {
		m.fail("malformed pattern (missing arguments to '%%b')")
	}
	if s >= len(m.src) || m.src[s] != m.pat[p] {
		return -1
	}
	b, e := m.pat[p], m.pat[p+1]
	cont := 1
	for s++; s < len(m.src); s++ {
		if m.src[s] == e {
			cont--
			if cont == 0 {
				return s + 1
			}
		} else if m.src[s] == b {
			cont++
		}
	}
	return -1 // string ends out of balance
}

// maxExpand matches the greedy repetition of the class at [p, ep).
func (m *Matcher) maxExpand(s, p, ep int) int {
	i := 0 // counts maximum expand for item
	for m.singleMatch(s+i, p, ep) {
		i++
	}
	// keeps trying to match with the maximum repetitions
	for ; i >= 0; i-- {
		if res := m.match(s+i, ep+1); res != -1 {
			return res
		}
	}
	return -1
}

// minExpand matches the lazy repetition of the class at [p, ep).
func (m *Matcher) minExpand(s, p, ep int) int {
	for {
		if res := m.match(s, ep+1); res != -1 {
			return res
		}
		if !m.singleMatch(s, p, ep) {
			return -1
		}
		s++ // try with one more repetition
	}
}

// startCapture opens a capture (what is capUnfinished or CapPosition) and
// continues matching at pattern offset p.
func (m *Matcher) startCapture(s, p, what int) int {
	level := m.level
	if level >= MaxCaptures {
		m.fail("too many captures")
	}
	m.capture[level] = matchCapture{init: s, len: what}
	m.level = level + 1
	res := m.match(s, p)
	if res == -1 { // match failed?
		m.level-- // undo capture
	}
	return res
}

// endCapture closes the innermost open capture and continues matching at
// pattern offset p.
func (m *Matcher) endCapture(s, p int) int {
	l := m.captureToClose()
	m.capture[l].len = s - m.capture[l].init // close capture
	res := m.match(s, p)
	if res == -1 { // match failed?
		m.capture[l].len = capUnfinished // undo capture
	}
	return res
}

// matchBackReference matches the text of the capture selected by the
// back-reference digit l at subject offset s.
func (m *Matcher) matchBackReference(s int, l int) int {
	l = m.checkCapture(l)
	c := m.capture[l]
	// a position capture never matches (its length is not a text length)
	if c.len >= 0 && len(m.src)-s >= c.len && m.src[c.init:c.init+c.len] == m.src[s:s+c.len] {
		return s + c.len
	}
	return -1
}

// match guards the recursion depth of doMatch.
func (m *Matcher) match(s, p int) int {
	if m.depth == 0 {
		m.fail("pattern too complex")
	}
	m.depth--
	res := m.doMatch(s, p)
	m.depth++
	return res
}

// doMatch matches the pattern from offset p against the subject from
// offset s and returns the end of the match or -1.
func (m *Matcher) doMatch(s, p int) int {
	for p != len(m.pat) {
		switch m.pat[p] {
		case '(': // start capture
			if m.pc(p+1) == ')' { // position capture?
				return m.startCapture(s, p+2, CapPosition)
			}
			return m.startCapture(s, p+1, capUnfinished)
		case ')': // end capture
			return m.endCapture(s, p+1)
		case '$':
			if p+1 == len(m.pat) { // is the '$' the last char in pattern?
				if s == len(m.src) {
					return s
				}
				return -1
			}
		case patEscape: // escaped sequences not in the format class[*+?-]?
			switch m.pc(p + 1) {
			case 'b': // balanced string?
				s = m.matchBalance(s, p+2)
				if s == -1 {
					return -1
				}
				p += 4
				continue
			case 'f': // frontier?
				p += 2
				if m.pc(p) != '[' {
					m.fail("missing '[' after '%%f' in pattern")
				}
				ep := m.classEnd(p) // points to what is next
				var previous byte
				if s > 0 {
					previous = m.src[s-1]
				}
				if !m.matchBracketClass(previous, p, ep-1) && m.matchBracketClass(m.sc(s), p, ep-1) {
					p = ep
					continue
				}
				return -1
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9': // capture results (%0-%9)?
				s = m.matchBackReference(s, int(m.pat[p+1]))
				if s == -1 {
					return -1
				}
				p += 2
				continue
			}
		}
		// pattern class plus optional suffix
		ep := m.classEnd(p) // points to optional suffix
		suffix := m.pc(ep)
		if !m.singleMatch(s, p, ep) { // does not match at least once?
			if suffix == '*' || suffix == '?' || suffix == '-' { // accept empty?
				p = ep + 1
				continue
			}
			return -1 // '+' or no suffix
		}
		switch suffix { // matched once: handle optional suffix
		case '?': // optional
			if res := m.match(s+1, ep+1); res != -1 {
				return res
			}
			p = ep + 1
		case '+': // 1 or more repetitions
			return m.maxExpand(s+1, p, ep)
		case '*': // 0 or more repetitions
			return m.maxExpand(s, p, ep)
		case '-': // 0 or more repetitions (minimum)
			return m.minExpand(s, p, ep)
		default: // no suffix
			s++
			p = ep
		}
	}
	return s
}

/* }}} */
