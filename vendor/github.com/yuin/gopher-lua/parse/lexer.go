package parse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yuin/gopher-lua/ast"
)

const EOF = -1
const whitespace1 = 1<<'\t' | 1<<' ' | 1<<'\v' | 1<<'\f'
const whitespace2 = 1<<'\t' | 1<<'\n' | 1<<'\r' | 1<<' ' | 1<<'\v' | 1<<'\f'

// Version selects the language profile accepted by the parser.
type Version int

const (
	// Lua51 is the GopherLua compatible Lua 5.1 grammar (plus goto).
	Lua51 Version = iota
	// Lua55 is the Lua 5.5 grammar.
	Lua55
)

// Options configures the parser.
type Options struct {
	Version Version
}

// Token types. The numeric values are those of the former yacc generated
// parser so that existing users of ast.Token.Type keep working.
const (
	TAnd = 57346 + iota
	TBreak
	TDo
	TElse
	TElseIf
	TEnd
	TFalse
	TFor
	TFunction
	TIf
	TIn
	TLocal
	TNil
	TNot
	TOr
	TReturn
	TRepeat
	TThen
	TTrue
	TUntil
	TWhile
	TGoto
	TEqeq
	TNeq
	TLte
	TGte
	T2Comma
	T3Comma
	T2Colon
	TIdent
	TNumber
	TString
	TIdiv
	TShl
	TShr
)

var tokenNames = [...]string{
	"TAnd", "TBreak", "TDo", "TElse", "TElseIf", "TEnd", "TFalse", "TFor",
	"TFunction", "TIf", "TIn", "TLocal", "TNil", "TNot", "TOr", "TReturn",
	"TRepeat", "TThen", "TTrue", "TUntil", "TWhile", "TGoto", "TEqeq",
	"TNeq", "TLte", "TGte", "T2Comma", "T3Comma", "T2Colon", "TIdent",
	"TNumber", "TString", "TIdiv", "TShl", "TShr",
}

// TokenName returns a printable name of a token type.
func TokenName(c int) string {
	if c >= TAnd && c-TAnd < len(tokenNames) {
		return tokenNames[c-TAnd]
	}
	if c == EOF {
		return "EOF"
	}
	return string([]byte{byte(c)})
}

type Error struct {
	Pos     ast.Position
	Message string
	Token   string
}

func (e *Error) Error() string {
	pos := e.Pos
	if pos.Line == EOF {
		return fmt.Sprintf("%v at EOF:   %s\n", pos.Source, e.Message)
	} else {
		return fmt.Sprintf("%v line:%d(column:%d) near '%v':   %s\n", pos.Source, pos.Line, pos.Column, e.Token, e.Message)
	}
}

func writeChar(buf *bytes.Buffer, c int) { buf.WriteByte(byte(c)) }

func isDecimal(ch int) bool { return '0' <= ch && ch <= '9' }

func isIdent(ch int, pos int) bool {
	return ch == '_' || 'A' <= ch && ch <= 'Z' || 'a' <= ch && ch <= 'z' || isDecimal(ch) && pos > 0
}

func isDigit(ch int) bool {
	return '0' <= ch && ch <= '9' || 'a' <= ch && ch <= 'f' || 'A' <= ch && ch <= 'F'
}

type Scanner struct {
	Pos    ast.Position
	reader *bufio.Reader
	lua55  bool
	// lastLine is the line of the most recently consumed character. It
	// stays valid at the end of the input, where Pos.Line becomes EOF.
	lastLine int
}

func NewScanner(reader io.Reader, source string) *Scanner {
	return &Scanner{
		Pos: ast.Position{
			Source: source,
			Line:   1,
			Column: 0,
		},
		reader:   bufio.NewReaderSize(reader, 4096),
		lastLine: 1,
	}
}

func (sc *Scanner) Error(tok string, msg string) *Error { return &Error{sc.Pos, msg, tok} }

func (sc *Scanner) TokenError(tok ast.Token, msg string) *Error { return &Error{tok.Pos, msg, tok.Str} }

func (sc *Scanner) readNext() int {
	ch, err := sc.reader.ReadByte()
	if err != nil {
		return EOF
	}
	return int(ch)
}

func (sc *Scanner) Newline(ch int) {
	if ch < 0 {
		return
	}
	sc.Pos.Line += 1
	sc.lastLine = sc.Pos.Line
	sc.Pos.Column = 0
	next := sc.Peek()
	if ch == '\n' && next == '\r' || ch == '\r' && next == '\n' {
		sc.reader.ReadByte()
	}
}

func (sc *Scanner) Next() int {
	ch := sc.readNext()
	switch ch {
	case '\n', '\r':
		sc.Newline(ch)
		ch = int('\n')
	case EOF:
		sc.Pos.Line = EOF
		sc.Pos.Column = 0
	default:
		sc.Pos.Column++
	}
	return ch
}

func (sc *Scanner) Peek() int {
	ch := sc.readNext()
	if ch != EOF {
		sc.reader.UnreadByte()
	}
	return ch
}

func (sc *Scanner) skipWhiteSpace(whitespace int64) int {
	ch := sc.Next()
	for ; ch >= 0 && ch < 64 && whitespace&(1<<uint(ch)) != 0; ch = sc.Next() {
	}
	return ch
}

func (sc *Scanner) skipComments(ch int) error {
	// multiline comment
	if sc.Peek() == '[' && sc.longBracketAhead() {
		ch = sc.Next()
		if sc.Peek() == '[' || sc.Peek() == '=' {
			var buf bytes.Buffer
			if err := sc.scanMultilineString(sc.Next(), &buf); err != nil {
				return sc.Error(buf.String(), "invalid multiline comment")
			}
			return nil
		}
	}
	for {
		if ch == '\n' || ch == '\r' || ch < 0 {
			break
		}
		ch = sc.Next()
	}
	return nil
}

// longBracketAhead reports whether the input continues with an opening
// long bracket ("[", any number of "=", "["). Anything else after "--["
// is an ordinary line comment.
func (sc *Scanner) longBracketAhead() bool {
	for n := 2; ; n *= 2 {
		buf, _ := sc.reader.Peek(n)
		for i := 1; i < len(buf); i++ {
			switch buf[i] {
			case '=':
			case '[':
				return true
			default:
				return false
			}
		}
		if len(buf) < n || n >= 2048 {
			return false
		}
	}
}

func (sc *Scanner) scanIdent(ch int, buf *bytes.Buffer) error {
	writeChar(buf, ch)
	for isIdent(sc.Peek(), 1) {
		writeChar(buf, sc.Next())
	}
	return nil
}

func (sc *Scanner) scanDecimal(ch int, buf *bytes.Buffer) error {
	writeChar(buf, ch)
	for isDecimal(sc.Peek()) {
		writeChar(buf, sc.Next())
	}
	return nil
}

func (sc *Scanner) scanNumber(ch int, buf *bytes.Buffer) error {
	if sc.lua55 {
		return sc.scanNumber55(ch, buf)
	}
	if ch == '0' { // octal
		if sc.Peek() == 'x' || sc.Peek() == 'X' {
			writeChar(buf, ch)
			writeChar(buf, sc.Next())
			hasvalue := false
			for isDigit(sc.Peek()) {
				writeChar(buf, sc.Next())
				hasvalue = true
			}
			if !hasvalue {
				return sc.Error(buf.String(), "illegal hexadecimal number")
			}
			return nil
		} else if sc.Peek() != '.' && isDecimal(sc.Peek()) {
			ch = sc.Next()
		}
	}
	sc.scanDecimal(ch, buf)
	if sc.Peek() == '.' {
		sc.scanDecimal(sc.Next(), buf)
	}
	if ch = sc.Peek(); ch == 'e' || ch == 'E' {
		writeChar(buf, sc.Next())
		if ch = sc.Peek(); ch == '-' || ch == '+' {
			writeChar(buf, sc.Next())
		}
		sc.scanDecimal(sc.Next(), buf)
	}
	return nil
}

// scanNumber55 reads a numeral the way the reference Lua 5.5 lexer does:
// it consumes everything that can be part of a numeral and validates the
// collected text afterwards.
func (sc *Scanner) scanNumber55(ch int, buf *bytes.Buffer) error {
	expo1, expo2 := 'e', 'E'
	writeChar(buf, ch)
	if ch == '0' && (sc.Peek() == 'x' || sc.Peek() == 'X') {
		writeChar(buf, sc.Next())
		expo1, expo2 = 'p', 'P'
	}
	for {
		c := sc.Peek()
		if c == int(expo1) || c == int(expo2) {
			writeChar(buf, sc.Next())
			if c = sc.Peek(); c == '-' || c == '+' {
				writeChar(buf, sc.Next())
			}
		} else if isDigit(c) || c == '.' {
			writeChar(buf, sc.Next())
		} else {
			break
		}
	}
	if isIdent(sc.Peek(), 0) {
		writeChar(buf, sc.Next())
	}
	if !validNumeral(buf.String()) {
		return sc.Error(buf.String(), "malformed number")
	}
	return nil
}

// validNumeral checks a Lua 5.3+ numeral (decimal or hexadecimal, integer
// or float).
func validNumeral(s string) bool {
	isDigitAt := func(i int, hex bool) bool {
		if i >= len(s) {
			return false
		}
		if hex {
			return isDigit(int(s[i]))
		}
		return isDecimal(int(s[i]))
	}
	i := 0
	hex := false
	if len(s) > 1 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		hex = true
		i = 2
	}
	digits := 0
	for isDigitAt(i, hex) {
		i++
		digits++
	}
	if i < len(s) && s[i] == '.' {
		i++
		for isDigitAt(i, hex) {
			i++
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < len(s) && ((!hex && (s[i] == 'e' || s[i] == 'E')) || (hex && (s[i] == 'p' || s[i] == 'P'))) {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		if !isDigitAt(i, false) {
			return false
		}
		for isDigitAt(i, false) {
			i++
		}
	}
	return i == len(s)
}

func (sc *Scanner) scanString(quote int, buf *bytes.Buffer) error {
	ch := sc.Next()
	for ch != quote {
		if ch == '\n' || ch == '\r' || ch < 0 {
			return sc.Error(buf.String(), "unterminated string")
		}
		if ch == '\\' {
			if err := sc.scanEscape(ch, buf); err != nil {
				return err
			}
		} else {
			writeChar(buf, ch)
		}
		ch = sc.Next()
	}
	return nil
}

func (sc *Scanner) scanEscape(ch int, buf *bytes.Buffer) error {
	ch = sc.Next()
	switch ch {
	case 'a':
		buf.WriteByte('\a')
	case 'b':
		buf.WriteByte('\b')
	case 'f':
		buf.WriteByte('\f')
	case 'n':
		buf.WriteByte('\n')
	case 'r':
		buf.WriteByte('\r')
	case 't':
		buf.WriteByte('\t')
	case 'v':
		buf.WriteByte('\v')
	case '\\':
		buf.WriteByte('\\')
	case '"':
		buf.WriteByte('"')
	case '\'':
		buf.WriteByte('\'')
	case '\n':
		buf.WriteByte('\n')
	case '\r':
		buf.WriteByte('\n')
		sc.Newline('\r')
	default:
		if '0' <= ch && ch <= '9' {
			bytes := []byte{byte(ch)}
			for i := 0; i < 2 && isDecimal(sc.Peek()); i++ {
				bytes = append(bytes, byte(sc.Next()))
			}
			val, _ := strconv.ParseInt(string(bytes), 10, 32)
			if sc.lua55 && val > 255 {
				return sc.Error("\\"+string(bytes), "decimal escape too large")
			}
			writeChar(buf, int(val))
		} else if sc.lua55 {
			return sc.scanEscape55(ch, buf)
		} else {
			writeChar(buf, ch)
		}
	}
	return nil
}

// scanEscape55 handles the escape sequences added after Lua 5.1.
func (sc *Scanner) scanEscape55(ch int, buf *bytes.Buffer) error {
	switch ch {
	case 'x':
		val := 0
		for i := 0; i < 2; i++ {
			c := sc.Peek()
			if !isDigit(c) {
				return sc.Error("\\x", "hexadecimal digit expected")
			}
			sc.Next()
			val = val*16 + hexValue(c)
		}
		writeChar(buf, val)
	case 'z':
		for {
			c := sc.Peek()
			if c == ' ' || (c >= '\t' && c <= '\r') {
				sc.Next()
				continue
			}
			break
		}
	case 'u':
		if sc.Peek() != '{' {
			return sc.Error("\\u", "missing '{' in \\u{xxxx}")
		}
		sc.Next()
		var val uint64
		n := 0
		for isDigit(sc.Peek()) {
			val = val*16 + uint64(hexValue(sc.Next()))
			n++
			if val > 0x7FFFFFFF {
				return sc.Error("\\u", "UTF-8 value too large")
			}
		}
		if n == 0 {
			return sc.Error("\\u", "hexadecimal digit expected")
		}
		if sc.Peek() != '}' {
			return sc.Error("\\u", "missing '}' in \\u{xxxx}")
		}
		sc.Next()
		buf.Write(utf8Encode(uint32(val)))
	default:
		tok := "\\"
		if ch >= 0 {
			tok += string(rune(ch))
		}
		return sc.Error(tok, "invalid escape sequence")
	}
	return nil
}

func hexValue(c int) int {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// utf8Encode encodes x (up to 2^31) using the original UTF-8 scheme of up
// to six bytes, like the reference implementation.
func utf8Encode(x uint32) []byte {
	if x < 0x80 {
		return []byte{byte(x)}
	}
	if x <= utf8.MaxRune && (x < 0xD800 || x > 0xDFFF) {
		var b [4]byte
		n := utf8.EncodeRune(b[:], rune(x))
		return b[:n]
	}
	var buf [8]byte
	n := 1
	mfb := uint32(0x3f)
	for {
		buf[8-n] = byte(0x80 | (x & 0x3f))
		n++
		x >>= 6
		mfb >>= 1
		if x <= mfb {
			break
		}
	}
	buf[8-n] = byte((^mfb << 1) | x)
	return buf[8-n:]
}

func (sc *Scanner) countSep(ch int) (int, int) {
	count := 0
	for ; ch == '='; count = count + 1 {
		ch = sc.Next()
	}
	return count, ch
}

func (sc *Scanner) scanMultilineString(ch int, buf *bytes.Buffer) error {
	var count1, count2 int
	count1, ch = sc.countSep(ch)
	if ch != '[' {
		return sc.Error(string(rune(ch)), "invalid multiline string")
	}
	ch = sc.Next()
	if ch == '\n' || ch == '\r' {
		ch = sc.Next()
	}
	for {
		if ch < 0 {
			return sc.Error(buf.String(), "unterminated multiline string")
		} else if ch == ']' {
			count2, ch = sc.countSep(sc.Next())
			if count1 == count2 && ch == ']' {
				goto finally
			}
			buf.WriteByte(']')
			buf.WriteString(strings.Repeat("=", count2))
			continue
		}
		writeChar(buf, ch)
		ch = sc.Next()
	}

finally:
	return nil
}

var reservedWords = map[string]int{
	"and": TAnd, "break": TBreak, "do": TDo, "else": TElse, "elseif": TElseIf,
	"end": TEnd, "false": TFalse, "for": TFor, "function": TFunction,
	"if": TIf, "in": TIn, "local": TLocal, "nil": TNil, "not": TNot, "or": TOr,
	"return": TReturn, "repeat": TRepeat, "then": TThen, "true": TTrue,
	"until": TUntil, "while": TWhile, "goto": TGoto}

// Scan returns the next token. The boolean result reports whether a line
// break precedes the token.
func (sc *Scanner) Scan(lexer *Lexer) (ast.Token, error) {
redo:
	var err error
	tok := ast.Token{}
	newline := false

	ch := sc.skipWhiteSpace(whitespace1)
	if ch == '\n' || ch == '\r' {
		newline = true
		ch = sc.skipWhiteSpace(whitespace2)
	}

	if ch == '(' && lexer.PrevTokenType == ')' {
		lexer.PNewLine = newline
	} else {
		lexer.PNewLine = false
	}

	var _buf bytes.Buffer
	buf := &_buf
	tok.Pos = sc.Pos

	switch {
	case isIdent(ch, 0):
		tok.Type = TIdent
		err = sc.scanIdent(ch, buf)
		tok.Str = buf.String()
		if err != nil {
			goto finally
		}
		if typ, ok := reservedWords[tok.Str]; ok {
			tok.Type = typ
		}
	case isDecimal(ch):
		tok.Type = TNumber
		err = sc.scanNumber(ch, buf)
		tok.Str = buf.String()
	default:
		switch ch {
		case EOF:
			tok.Type = EOF
		case '-':
			if sc.Peek() == '-' {
				err = sc.skipComments(sc.Next())
				if err != nil {
					goto finally
				}
				goto redo
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '"', '\'':
			tok.Type = TString
			err = sc.scanString(ch, buf)
			tok.Str = buf.String()
		case '[':
			if c := sc.Peek(); c == '[' || c == '=' {
				tok.Type = TString
				err = sc.scanMultilineString(sc.Next(), buf)
				tok.Str = buf.String()
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '=':
			if sc.Peek() == '=' {
				tok.Type = TEqeq
				tok.Str = "=="
				sc.Next()
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '~':
			if sc.Peek() == '=' {
				tok.Type = TNeq
				tok.Str = "~="
				sc.Next()
			} else if sc.lua55 {
				tok.Type = ch
				tok.Str = "~"
			} else {
				err = sc.Error("~", "Invalid '~' token")
			}
		case '<':
			if sc.Peek() == '=' {
				tok.Type = TLte
				tok.Str = "<="
				sc.Next()
			} else if sc.lua55 && sc.Peek() == '<' {
				tok.Type = TShl
				tok.Str = "<<"
				sc.Next()
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '>':
			if sc.Peek() == '=' {
				tok.Type = TGte
				tok.Str = ">="
				sc.Next()
			} else if sc.lua55 && sc.Peek() == '>' {
				tok.Type = TShr
				tok.Str = ">>"
				sc.Next()
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '.':
			ch2 := sc.Peek()
			switch {
			case isDecimal(ch2):
				tok.Type = TNumber
				err = sc.scanNumber(ch, buf)
				tok.Str = buf.String()
			case ch2 == '.':
				writeChar(buf, ch)
				writeChar(buf, sc.Next())
				if sc.Peek() == '.' {
					writeChar(buf, sc.Next())
					tok.Type = T3Comma
				} else {
					tok.Type = T2Comma
				}
			default:
				tok.Type = '.'
			}
			tok.Str = buf.String()
		case ':':
			if sc.Peek() == ':' {
				tok.Type = T2Colon
				tok.Str = "::"
				sc.Next()
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '/':
			if sc.lua55 && sc.Peek() == '/' {
				tok.Type = TIdiv
				tok.Str = "//"
				sc.Next()
			} else {
				tok.Type = ch
				tok.Str = string(rune(ch))
			}
		case '+', '*', '%', '^', '#', '(', ')', '{', '}', ']', ';', ',':
			tok.Type = ch
			tok.Str = string(rune(ch))
		case '&', '|':
			if sc.lua55 {
				tok.Type = ch
				tok.Str = string(rune(ch))
			} else {
				writeChar(buf, ch)
				err = sc.Error(buf.String(), "Invalid token")
				goto finally
			}
		default:
			writeChar(buf, ch)
			err = sc.Error(buf.String(), "Invalid token")
			goto finally
		}
	}

finally:
	tok.Name = TokenName(int(tok.Type))
	return tok, err
}

// Lexer is the token source of the parser.
type Lexer struct {
	scanner       *Scanner
	Stmts         []ast.Stmt
	PNewLine      bool
	Token         ast.Token
	PrevTokenType int
}

func (lx *Lexer) Error(message string) {
	panic(lx.scanner.Error(lx.Token.Str, message))
}

func (lx *Lexer) TokenError(tok ast.Token, message string) {
	panic(lx.scanner.TokenError(tok, message))
}

// Parse parses a Lua 5.1 chunk (the GopherLua compatible grammar).
func Parse(reader io.Reader, name string) (chunk []ast.Stmt, err error) {
	return ParseWithOptions(reader, name, Options{})
}

// ParseWithOptions parses a chunk using the given language profile.
func ParseWithOptions(reader io.Reader, name string, opts Options) (chunk []ast.Stmt, err error) {
	scanner := NewScanner(reader, name)
	scanner.lua55 = opts.Version == Lua55
	p := &parser{
		lx:    &Lexer{scanner, nil, false, ast.Token{Str: ""}, TNil},
		lua55: scanner.lua55,
	}
	defer func() {
		if e := recover(); e != nil {
			if perr, ok := e.(*Error); ok {
				chunk = nil
				err = perr
				return
			}
			panic(e)
		}
	}()
	p.next()
	chunk = p.parseChunk()
	return
}

// Dump {{{

func isInlineDumpNode(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Struct, reflect.Slice, reflect.Interface, reflect.Ptr:
		return false
	default:
		return true
	}
}

func dump(node interface{}, level int, s string) string {
	rt := reflect.TypeOf(node)
	if fmt.Sprint(rt) == "<nil>" {
		return strings.Repeat(s, level) + "<nil>"
	}

	rv := reflect.ValueOf(node)
	buf := []string{}
	switch rt.Kind() {
	case reflect.Slice:
		if rv.Len() == 0 {
			return strings.Repeat(s, level) + "<empty>"
		}
		for i := 0; i < rv.Len(); i++ {
			buf = append(buf, dump(rv.Index(i).Interface(), level, s))
		}
	case reflect.Ptr:
		vt := rv.Elem()
		tt := rt.Elem()
		indicies := []int{}
		for i := 0; i < tt.NumField(); i++ {
			if strings.Index(tt.Field(i).Name, "Base") > -1 {
				continue
			}
			indicies = append(indicies, i)
		}
		switch {
		case len(indicies) == 0:
			return strings.Repeat(s, level) + "<empty>"
		case len(indicies) == 1 && isInlineDumpNode(vt.Field(indicies[0])):
			for _, i := range indicies {
				buf = append(buf, strings.Repeat(s, level)+"- Node$"+tt.Name()+": "+dump(vt.Field(i).Interface(), 0, s))
			}
		default:
			buf = append(buf, strings.Repeat(s, level)+"- Node$"+tt.Name())
			for _, i := range indicies {
				if isInlineDumpNode(vt.Field(i)) {
					inf := dump(vt.Field(i).Interface(), 0, s)
					buf = append(buf, strings.Repeat(s, level+1)+tt.Field(i).Name+": "+inf)
				} else {
					buf = append(buf, strings.Repeat(s, level+1)+tt.Field(i).Name+": ")
					buf = append(buf, dump(vt.Field(i).Interface(), level+2, s))
				}
			}
		}
	default:
		buf = append(buf, strings.Repeat(s, level)+fmt.Sprint(node))
	}
	return strings.Join(buf, "\n")
}

func Dump(chunk []ast.Stmt) string {
	return dump(chunk, 0, "   ")
}

// }}
