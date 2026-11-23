package ast

type Field struct {
	Key   Expr
	Value Expr
}

type ParList struct {
	HasVargs bool
	Names    []string
	// VarargName is the name of the vararg table of a Lua 5.5 named
	// vararg parameter ("...name"), or "".
	VarargName string
}

type FuncName struct {
	Func     Expr
	Receiver Expr
	Method   string
}
