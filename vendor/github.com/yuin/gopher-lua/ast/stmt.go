package ast

type Stmt interface {
	PositionHolder
	stmtMarker()
}

type StmtBase struct {
	Node
}

func (stmt *StmtBase) stmtMarker() {}

type AssignStmt struct {
	StmtBase

	Lhs []Expr
	Rhs []Expr
}

type LocalAssignStmt struct {
	StmtBase

	Names []string
	Exprs []Expr
	// Attribs holds the attribute ("", "const" or "close") of each name.
	// It is nil when no name has an attribute (Lua 5.4+).
	Attribs []string
	// IsFunction is true for the "local function name" form, where the
	// name is in scope inside the function body.
	IsFunction bool
}

// GlobalDeclStmt is a Lua 5.5 global declaration:
//
//	global [attrib] name {, name} [= explist]
//	global [attrib] *
//	global function name funcbody
type GlobalDeclStmt struct {
	StmtBase

	Names []string
	// Attribs holds the attribute ("" or "const") of each name.
	Attribs []string
	Exprs   []Expr
	// Wildcard is true for the "global *" form; WildcardAttrib is its
	// attribute.
	Wildcard       bool
	WildcardAttrib string
	// IsFunc is true for the "global function" form.
	IsFunc bool
}

type FuncCallStmt struct {
	StmtBase

	Expr Expr
}

type DoBlockStmt struct {
	StmtBase

	Stmts []Stmt
}

type WhileStmt struct {
	StmtBase

	Condition Expr
	Stmts     []Stmt
}

type RepeatStmt struct {
	StmtBase

	Condition Expr
	Stmts     []Stmt
}

type IfStmt struct {
	StmtBase

	Condition Expr
	Then      []Stmt
	Else      []Stmt
}

type NumberForStmt struct {
	StmtBase

	Name  string
	Init  Expr
	Limit Expr
	Step  Expr
	Stmts []Stmt
}

type GenericForStmt struct {
	StmtBase

	Names []string
	Exprs []Expr
	Stmts []Stmt
}

type FuncDefStmt struct {
	StmtBase

	Name *FuncName
	Func *FunctionExpr
}

type ReturnStmt struct {
	StmtBase

	Exprs []Expr
}

type BreakStmt struct {
	StmtBase
}

type LabelStmt struct {
	StmtBase

	Name string
}

type GotoStmt struct {
	StmtBase

	Label string
}
