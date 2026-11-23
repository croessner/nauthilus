package parse

import (
	"fmt"

	"github.com/yuin/gopher-lua/ast"
)

// parser is a hand-written recursive descent parser for the Lua 5.1 and
// Lua 5.5 grammars. It replaces the former yacc generated parser and
// produces the same AST.
type parser struct {
	lx    *Lexer
	lua55 bool

	tok ast.Token // current token
	// one token of extra lookahead
	hasAhead bool
	ahead    ast.Token

	prevLine int // line of the most recently consumed token
	depth    int // nesting depth guard
	// paren records expressions that were written in parentheses; they
	// are not valid assignment targets.
	paren map[ast.Expr]bool
}

const maxParseDepth = 200

func (p *parser) scan() ast.Token {
	lx := p.lx
	lx.PrevTokenType = lx.Token.Type
	tok, err := lx.scanner.Scan(lx)
	if err != nil {
		panic(err)
	}
	lx.Token = tok
	return tok
}

// next advances to the next token.
func (p *parser) next() {
	if p.tok.Pos.Line > 0 {
		p.prevLine = p.tok.Pos.Line
	}
	if p.hasAhead {
		p.tok = p.ahead
		p.hasAhead = false
		return
	}
	p.tok = p.scan()
}

// peek returns the token after the current one without consuming it.
func (p *parser) peek() ast.Token {
	if !p.hasAhead {
		p.ahead = p.scan()
		p.hasAhead = true
	}
	return p.ahead
}

func (p *parser) errorAt(tok ast.Token, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if tok.Type == EOF {
		pos := tok.Pos
		pos.Line = EOF
		panic(&Error{Pos: pos, Message: msg, Token: "<eof>"})
	}
	panic(&Error{Pos: tok.Pos, Message: msg, Token: tok.Str})
}

func (p *parser) syntaxError() {
	if p.lua55 {
		p.errorAt(p.tok, "unexpected symbol")
	}
	p.errorAt(p.tok, "syntax error")
}

func tokenText(typ int) string {
	switch typ {
	case TAnd:
		return "and"
	case TBreak:
		return "break"
	case TDo:
		return "do"
	case TElse:
		return "else"
	case TElseIf:
		return "elseif"
	case TEnd:
		return "end"
	case TFalse:
		return "false"
	case TFor:
		return "for"
	case TFunction:
		return "function"
	case TIf:
		return "if"
	case TIn:
		return "in"
	case TLocal:
		return "local"
	case TNil:
		return "nil"
	case TNot:
		return "not"
	case TOr:
		return "or"
	case TReturn:
		return "return"
	case TRepeat:
		return "repeat"
	case TThen:
		return "then"
	case TTrue:
		return "true"
	case TUntil:
		return "until"
	case TWhile:
		return "while"
	case TGoto:
		return "goto"
	case TEqeq:
		return "=="
	case TNeq:
		return "~="
	case TLte:
		return "<="
	case TGte:
		return ">="
	case T2Comma:
		return ".."
	case T3Comma:
		return "..."
	case T2Colon:
		return "::"
	case TIdent:
		return "<name>"
	case TNumber:
		return "<number>"
	case TString:
		return "<string>"
	case TIdiv:
		return "//"
	case TShl:
		return "<<"
	case TShr:
		return ">>"
	case EOF:
		return "<eof>"
	}
	return string(rune(typ))
}

func (p *parser) check(typ int) bool { return p.tok.Type == typ }

func (p *parser) accept(typ int) bool {
	if p.tok.Type == typ {
		p.next()
		return true
	}
	return false
}

func (p *parser) expect(typ int) ast.Token {
	tok := p.tok
	if tok.Type != typ {
		p.errorAt(tok, "'%s' expected", tokenText(typ))
	}
	p.next()
	return tok
}

// expectMatch expects the closing token of a construct opened at line.
func (p *parser) expectMatch(what, who int, line int) ast.Token {
	tok := p.tok
	if tok.Type != what {
		if line == tok.Pos.Line {
			p.errorAt(tok, "'%s' expected", tokenText(what))
		}
		p.errorAt(tok, "'%s' expected (to close '%s' at line %d)", tokenText(what), tokenText(who), line)
	}
	p.next()
	return tok
}

func (p *parser) expectName() ast.Token {
	tok := p.tok
	if tok.Type != TIdent {
		p.errorAt(tok, "<name> expected")
	}
	p.next()
	return tok
}

func (p *parser) enter() {
	p.depth++
	if p.depth > maxParseDepth {
		p.errorAt(p.tok, "chunk has too many syntax levels")
	}
}

func (p *parser) leave() { p.depth-- }

/* statements {{{ */

func (p *parser) parseChunk() []ast.Stmt {
	stmts := p.parseBlock()
	if !p.check(EOF) {
		if p.lua55 {
			p.errorAt(p.tok, "'<eof>' expected")
		}
		p.syntaxError()
	}
	return stmts
}

func (p *parser) blockFollow(withUntil bool) bool {
	switch p.tok.Type {
	case TElse, TElseIf, TEnd, EOF:
		return true
	case TUntil:
		return withUntil
	}
	return false
}

func (p *parser) parseBlock() []ast.Stmt {
	stmts := []ast.Stmt{}
	for !p.blockFollow(true) {
		if p.check(TReturn) {
			stmts = append(stmts, p.parseReturn())
			break
		}
		if p.check(TBreak) && !p.lua55 {
			// Lua 5.1: break must be the last statement of a block.
			tok := p.tok
			p.next()
			st := &ast.BreakStmt{}
			st.SetLine(tok.Pos.Line)
			stmts = append(stmts, st)
			p.accept(';')
			break
		}
		if st := p.parseStatement(); st != nil {
			stmts = append(stmts, st)
		}
	}
	return stmts
}

func (p *parser) parseReturn() ast.Stmt {
	tok := p.expect(TReturn)
	st := &ast.ReturnStmt{}
	st.SetLine(tok.Pos.Line)
	if !p.blockFollow(true) && !p.check(';') {
		st.Exprs = p.parseExprList()
	}
	p.accept(';')
	return st
}

func (p *parser) parseStatement() ast.Stmt {
	p.enter()
	defer p.leave()
	tok := p.tok
	switch tok.Type {
	case ';':
		p.next()
		return nil
	case TIf:
		return p.parseIf()
	case TWhile:
		p.next()
		cond := p.parseExpr()
		p.expect(TDo)
		body := p.parseBlock()
		end := p.expectMatch(TEnd, TWhile, tok.Pos.Line)
		st := &ast.WhileStmt{Condition: cond, Stmts: body}
		st.SetLine(tok.Pos.Line)
		st.SetLastLine(end.Pos.Line)
		return st
	case TDo:
		p.next()
		body := p.parseBlock()
		end := p.expectMatch(TEnd, TDo, tok.Pos.Line)
		st := &ast.DoBlockStmt{Stmts: body}
		st.SetLine(tok.Pos.Line)
		st.SetLastLine(end.Pos.Line)
		return st
	case TFor:
		return p.parseFor()
	case TRepeat:
		p.next()
		body := p.parseBlock()
		p.expectMatch(TUntil, TRepeat, tok.Pos.Line)
		cond := p.parseExpr()
		st := &ast.RepeatStmt{Condition: cond, Stmts: body}
		st.SetLine(tok.Pos.Line)
		st.SetLastLine(cond.Line())
		return st
	case TFunction:
		p.next()
		name := p.parseFuncName()
		fn := p.parseFuncBody(tok.Pos.Line)
		st := &ast.FuncDefStmt{Name: name, Func: fn}
		st.SetLine(tok.Pos.Line)
		st.SetLastLine(fn.LastLine())
		return st
	case TLocal:
		p.next()
		if p.check(TFunction) {
			p.next()
			name := p.expectName()
			fn := p.parseFuncBody(tok.Pos.Line)
			st := &ast.LocalAssignStmt{Names: []string{name.Str}, Exprs: []ast.Expr{fn}, IsFunction: true}
			st.SetLine(tok.Pos.Line)
			st.SetLastLine(fn.LastLine())
			return st
		}
		return p.parseLocal(tok)
	case T2Colon:
		p.next()
		name := p.expectName()
		p.expect(T2Colon)
		st := &ast.LabelStmt{Name: name.Str}
		st.SetLine(tok.Pos.Line)
		return st
	case TBreak:
		p.next()
		st := &ast.BreakStmt{}
		st.SetLine(tok.Pos.Line)
		return st
	case TGoto:
		p.next()
		name := p.expectName()
		st := &ast.GotoStmt{Label: name.Str}
		st.SetLine(tok.Pos.Line)
		return st
	case TIdent:
		if p.lua55 && tok.Str == "global" {
			switch nt := p.peek(); nt.Type {
			case TIdent, '<', '*', TFunction:
				p.next()
				return p.parseGlobal(tok)
			}
		}
	}
	return p.parseExprStatement()
}

func (p *parser) parseIf() ast.Stmt {
	tok := p.expect(TIf)
	root := &ast.IfStmt{}
	root.SetLine(tok.Pos.Line)
	cur := root
	cur.Condition = p.parseExpr()
	p.expect(TThen)
	cur.Then = p.parseBlock()
	for {
		switch p.tok.Type {
		case TElseIf:
			etok := p.tok
			p.next()
			elif := &ast.IfStmt{}
			elif.SetLine(etok.Pos.Line)
			elif.Condition = p.parseExpr()
			p.expect(TThen)
			elif.Then = p.parseBlock()
			cur.Else = []ast.Stmt{elif}
			cur = elif
			continue
		case TElse:
			p.next()
			cur.Else = p.parseBlock()
		}
		break
	}
	end := p.expectMatch(TEnd, TIf, tok.Pos.Line)
	root.SetLastLine(end.Pos.Line)
	return root
}

func (p *parser) parseFor() ast.Stmt {
	tok := p.expect(TFor)
	name1 := p.expectName()
	if p.check('=') {
		p.next()
		st := &ast.NumberForStmt{Name: name1.Str}
		st.SetLine(tok.Pos.Line)
		st.Init = p.parseExpr()
		p.expect(',')
		st.Limit = p.parseExpr()
		if p.accept(',') {
			st.Step = p.parseExpr()
		}
		p.expect(TDo)
		st.Stmts = p.parseBlock()
		end := p.expectMatch(TEnd, TFor, tok.Pos.Line)
		st.SetLastLine(end.Pos.Line)
		return st
	}
	st := &ast.GenericForStmt{Names: []string{name1.Str}}
	st.SetLine(tok.Pos.Line)
	for p.accept(',') {
		st.Names = append(st.Names, p.expectName().Str)
	}
	if !p.check(TIn) {
		p.errorAt(p.tok, "'=' or 'in' expected")
	}
	p.next()
	st.Exprs = p.parseExprList()
	p.expect(TDo)
	st.Stmts = p.parseBlock()
	end := p.expectMatch(TEnd, TFor, tok.Pos.Line)
	st.SetLastLine(end.Pos.Line)
	return st
}

func (p *parser) parseFuncName() *ast.FuncName {
	tok := p.expectName()
	ident := &ast.IdentExpr{Value: tok.Str}
	ident.SetLine(tok.Pos.Line)
	name := &ast.FuncName{Func: ident}
	for p.check('.') {
		p.next()
		ktok := p.expectName()
		key := &ast.StringExpr{Value: ktok.Str}
		key.SetLine(ktok.Pos.Line)
		fn := &ast.AttrGetExpr{Object: name.Func, Key: key}
		fn.SetLine(ktok.Pos.Line)
		name = &ast.FuncName{Func: fn}
	}
	if p.accept(':') {
		mtok := p.expectName()
		name = &ast.FuncName{Func: nil, Receiver: name.Func, Method: mtok.Str}
	}
	return name
}

// parseAttrib parses an optional "<name>" attribute (Lua 5.4+).
func (p *parser) parseAttrib() string {
	if !p.lua55 || !p.check('<') {
		return ""
	}
	p.next()
	tok := p.expectName()
	if tok.Str != "const" && tok.Str != "close" {
		p.errorAt(tok, "unknown attribute '%s'", tok.Str)
	}
	p.expect('>')
	return tok.Str
}

func (p *parser) parseLocal(tok ast.Token) ast.Stmt {
	st := &ast.LocalAssignStmt{Exprs: []ast.Expr{}}
	st.SetLine(tok.Pos.Line)
	attribs := []string{}
	hasAttrib := false
	prefix := p.parseAttrib() // Lua 5.5 collective attribute
	for {
		name := p.expectName()
		attr := p.parseAttrib()
		if attr == "" {
			attr = prefix
		}
		if attr != "" {
			hasAttrib = true
		}
		st.Names = append(st.Names, name.Str)
		attribs = append(attribs, attr)
		if !p.accept(',') {
			break
		}
	}
	if hasAttrib {
		st.Attribs = attribs
	}
	if p.accept('=') {
		st.Exprs = p.parseExprList()
	}
	return st
}

func (p *parser) parseGlobal(tok ast.Token) ast.Stmt {
	st := &ast.GlobalDeclStmt{}
	st.SetLine(tok.Pos.Line)
	if p.check(TFunction) {
		p.next()
		name := p.expectName()
		fn := p.parseFuncBody(tok.Pos.Line)
		st.Names = []string{name.Str}
		st.Attribs = []string{""}
		st.Exprs = []ast.Expr{fn}
		st.IsFunc = true
		st.SetLastLine(fn.LastLine())
		return st
	}
	prefix := p.parseAttrib()
	if prefix == "close" {
		p.errorAt(tok, "global variables cannot be to-be-closed")
	}
	if p.accept('*') {
		st.Wildcard = true
		st.WildcardAttrib = prefix
		return st
	}
	for {
		name := p.expectName()
		attr := p.parseAttrib()
		if attr == "close" {
			p.errorAt(name, "global variables cannot be to-be-closed")
		}
		if attr == "" {
			attr = prefix
		}
		st.Names = append(st.Names, name.Str)
		st.Attribs = append(st.Attribs, attr)
		if !p.accept(',') {
			break
		}
	}
	if p.accept('=') {
		st.Exprs = p.parseExprList()
	}
	return st
}

func (p *parser) parseExprStatement() ast.Stmt {
	first := p.parseSuffixedExpr()
	if p.check('=') || p.check(',') {
		lhs := []ast.Expr{first}
		for p.accept(',') {
			lhs = append(lhs, p.parseSuffixedExpr())
		}
		for _, e := range lhs {
			switch e.(type) {
			case *ast.IdentExpr, *ast.AttrGetExpr:
				if p.paren[e] {
					p.syntaxError()
				}
			default:
				p.syntaxError()
			}
		}
		p.expect('=')
		rhs := p.parseExprList()
		st := &ast.AssignStmt{Lhs: lhs, Rhs: rhs}
		st.SetLine(lhs[0].Line())
		return st
	}
	call, ok := first.(*ast.FuncCallExpr)
	if !ok || (call.AdjustRet && p.lua55) {
		if p.lua55 {
			p.syntaxError()
		}
		p.errorAt(p.tok, "parse error")
	}
	st := &ast.FuncCallStmt{Expr: first}
	st.SetLine(first.Line())
	return st
}

/* }}} */

/* expressions {{{ */

func (p *parser) parseExprList() []ast.Expr {
	exprs := []ast.Expr{p.parseExpr()}
	for p.accept(',') {
		exprs = append(exprs, p.parseExpr())
	}
	return exprs
}

func (p *parser) parseExpr() ast.Expr {
	return p.parseSubExpr(0)
}

type binPriority struct{ left, right int }

const unaryPriority = 12

// binaryPriority returns the operator priorities of the current token.
func (p *parser) binaryPriority() (binPriority, bool) {
	switch p.tok.Type {
	case TOr:
		return binPriority{1, 1}, true
	case TAnd:
		return binPriority{2, 2}, true
	case '<', '>', TLte, TGte, TNeq, TEqeq:
		return binPriority{3, 3}, true
	case '|':
		return binPriority{4, 4}, p.lua55
	case '~':
		return binPriority{5, 5}, p.lua55
	case '&':
		return binPriority{6, 6}, p.lua55
	case TShl, TShr:
		return binPriority{7, 7}, p.lua55
	case T2Comma:
		return binPriority{9, 8}, true
	case '+', '-':
		return binPriority{10, 10}, true
	case '*', '/', '%', TIdiv:
		return binPriority{11, 11}, true
	case '^':
		return binPriority{14, 13}, true
	}
	return binPriority{}, false
}

func (p *parser) parseSubExpr(limit int) ast.Expr {
	p.enter()
	defer p.leave()
	var lhs ast.Expr
	switch p.tok.Type {
	case TNot:
		p.next()
		operand := p.parseSubExpr(unaryPriority)
		e := &ast.UnaryNotOpExpr{Expr: operand}
		e.SetLine(operand.Line())
		lhs = e
	case '-':
		p.next()
		operand := p.parseSubExpr(unaryPriority)
		e := &ast.UnaryMinusOpExpr{Expr: operand}
		e.SetLine(operand.Line())
		lhs = e
	case '#':
		p.next()
		operand := p.parseSubExpr(unaryPriority)
		e := &ast.UnaryLenOpExpr{Expr: operand}
		e.SetLine(operand.Line())
		lhs = e
	case '~':
		if !p.lua55 {
			p.syntaxError()
		}
		p.next()
		operand := p.parseSubExpr(unaryPriority)
		e := &ast.UnaryBNotOpExpr{Expr: operand}
		e.SetLine(operand.Line())
		lhs = e
	default:
		lhs = p.parseSimpleExpr()
	}
	for {
		pri, ok := p.binaryPriority()
		if !ok || pri.left <= limit {
			break
		}
		op := p.tok
		p.next()
		rhs := p.parseSubExpr(pri.right)
		var e ast.Expr
		switch op.Type {
		case TOr:
			e = &ast.LogicalOpExpr{Lhs: lhs, Operator: "or", Rhs: rhs}
		case TAnd:
			e = &ast.LogicalOpExpr{Lhs: lhs, Operator: "and", Rhs: rhs}
		case '<', '>', TLte, TGte, TNeq, TEqeq:
			e = &ast.RelationalOpExpr{Lhs: lhs, Operator: op.Str, Rhs: rhs}
		case T2Comma:
			e = &ast.StringConcatOpExpr{Lhs: lhs, Rhs: rhs}
		default:
			e = &ast.ArithmeticOpExpr{Lhs: lhs, Operator: op.Str, Rhs: rhs}
		}
		e.SetLine(lhs.Line())
		lhs = e
	}
	return lhs
}

func (p *parser) parseSimpleExpr() ast.Expr {
	tok := p.tok
	switch tok.Type {
	case TNumber:
		p.next()
		e := &ast.NumberExpr{Value: tok.Str}
		e.SetLine(tok.Pos.Line)
		return e
	case TString:
		p.next()
		e := &ast.StringExpr{Value: tok.Str}
		e.SetLine(tok.Pos.Line)
		return e
	case TNil:
		p.next()
		e := &ast.NilExpr{}
		e.SetLine(tok.Pos.Line)
		return e
	case TTrue:
		p.next()
		e := &ast.TrueExpr{}
		e.SetLine(tok.Pos.Line)
		return e
	case TFalse:
		p.next()
		e := &ast.FalseExpr{}
		e.SetLine(tok.Pos.Line)
		return e
	case T3Comma:
		p.next()
		e := &ast.Comma3Expr{}
		e.SetLine(tok.Pos.Line)
		return e
	case '{':
		return p.parseTable()
	case TFunction:
		p.next()
		body := p.parseFuncBody(tok.Pos.Line)
		e := &ast.FunctionExpr{ParList: body.ParList, Stmts: body.Stmts}
		e.SetLine(tok.Pos.Line)
		e.SetLastLine(body.LastLine())
		return e
	}
	return p.parseSuffixedExpr()
}

func (p *parser) parsePrimaryExpr() ast.Expr {
	tok := p.tok
	switch tok.Type {
	case TIdent:
		p.next()
		e := &ast.IdentExpr{Value: tok.Str}
		e.SetLine(tok.Pos.Line)
		return e
	case '(':
		p.next()
		inner := p.parseExpr()
		p.expectMatch(')', '(', tok.Pos.Line)
		switch ex := inner.(type) {
		case *ast.Comma3Expr:
			ex.AdjustRet = true
		case *ast.FuncCallExpr:
			ex.AdjustRet = true
			return inner
		}
		if p.paren == nil {
			p.paren = make(map[ast.Expr]bool)
		}
		p.paren[inner] = true
		inner.SetLine(tok.Pos.Line)
		return inner
	}
	p.syntaxError()
	return nil
}

func (p *parser) parseSuffixedExpr() ast.Expr {
	e := p.parsePrimaryExpr()
	for {
		tok := p.tok
		switch tok.Type {
		case '.':
			p.next()
			ktok := p.expectName()
			key := &ast.StringExpr{Value: ktok.Str}
			key.SetLine(ktok.Pos.Line)
			ne := &ast.AttrGetExpr{Object: e, Key: key}
			ne.SetLine(e.Line())
			e = ne
		case '[':
			p.next()
			key := p.parseExpr()
			p.expect(']')
			ne := &ast.AttrGetExpr{Object: e, Key: key}
			ne.SetLine(e.Line())
			e = ne
		case ':':
			p.next()
			mtok := p.expectName()
			args := p.parseCallArgs()
			ne := &ast.FuncCallExpr{Method: mtok.Str, Receiver: e, Args: args}
			ne.SetLine(e.Line())
			e = ne
		case '(', TString, '{':
			args := p.parseCallArgs()
			ne := &ast.FuncCallExpr{Func: e, Args: args}
			ne.SetLine(e.Line())
			e = ne
		default:
			return e
		}
	}
}

func (p *parser) parseCallArgs() []ast.Expr {
	tok := p.tok
	switch tok.Type {
	case TString:
		p.next()
		e := &ast.StringExpr{Value: tok.Str}
		e.SetLine(tok.Pos.Line)
		return []ast.Expr{e}
	case '{':
		return []ast.Expr{p.parseTable()}
	case '(':
		// (A call continued on a new line is one statement, like in
		// GopherLua and Lua 5.2+; reference Lua 5.1 calls it ambiguous.)
		p.next()
		if p.accept(')') {
			return []ast.Expr{}
		}
		args := p.parseExprList()
		p.expectMatch(')', '(', tok.Pos.Line)
		return args
	}
	p.errorAt(tok, "function arguments expected")
	return nil
}

func (p *parser) parseTable() ast.Expr {
	tok := p.expect('{')
	e := &ast.TableExpr{Fields: []*ast.Field{}}
	e.SetLine(tok.Pos.Line)
	for !p.check('}') {
		var field *ast.Field
		switch {
		case p.check(TIdent) && p.peek().Type == '=':
			ktok := p.tok
			p.next()
			p.next()
			key := &ast.StringExpr{Value: ktok.Str}
			key.SetLine(ktok.Pos.Line)
			field = &ast.Field{Key: key, Value: p.parseExpr()}
		case p.check('['):
			p.next()
			key := p.parseExpr()
			p.expect(']')
			p.expect('=')
			field = &ast.Field{Key: key, Value: p.parseExpr()}
		default:
			field = &ast.Field{Value: p.parseExpr()}
		}
		e.Fields = append(e.Fields, field)
		if !p.accept(',') && !p.accept(';') {
			break
		}
		for !p.lua55 && (p.check(',') || p.check(';')) {
			// GopherLua's grammar tolerates repeated field separators
			p.next()
		}
	}
	p.expectMatch('}', '{', tok.Pos.Line)
	return e
}

// parseFuncBody parses "(parlist) block end". line is the line of the
// "function" keyword.
func (p *parser) parseFuncBody(line int) *ast.FunctionExpr {
	open := p.expect('(')
	par := &ast.ParList{HasVargs: false, Names: []string{}}
	if !p.check(')') {
		for {
			if p.check(T3Comma) {
				p.next()
				par.HasVargs = true
				if p.lua55 && p.check(TIdent) {
					par.VarargName = p.tok.Str
					p.next()
				}
				break
			}
			par.Names = append(par.Names, p.expectName().Str)
			if !p.accept(',') {
				break
			}
		}
	}
	p.expect(')')
	body := p.parseBlock()
	end := p.expectMatch(TEnd, TFunction, line)
	fn := &ast.FunctionExpr{ParList: par, Stmts: body}
	fn.SetLine(open.Pos.Line)
	fn.SetLastLine(end.Pos.Line)
	return fn
}

/* }}} */
