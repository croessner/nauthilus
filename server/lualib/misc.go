package lualib

import (
	"unicode"

	"github.com/croessner/nauthilus/server/global"
	lua "github.com/yuin/gopher-lua"
)

func toInt(lv lua.LValue) int {
	if num, ok := lv.(lua.LNumber); ok {
		return int(num)
	}

	return 0
}

// validatePassword validates the given password against a set of policy requirements.
// It takes a Lua state pointer and returns an integer indicating the result of the validation.
//
// The function expects two arguments:
//  1. A Lua table containing the password policy requirements.
//     The keys of the table are strings representing the policy name, and the values are integers representing the minimum count for that policy.
//     The supported policy names are "min_length", "min_upper", "min_lower", "min_number", and "min_special".
//
// 2. A string representing the password to be validated.
//
// The function first checks if the length of the password is less than the minimum required length specified in the policy table.
// If it is, it pushes false onto the Lua stack and returns 1.
//
// Then, it iterates over each character in the password and counts how many uppercase letters, lowercase letters, numbers,
// and special characters are in the password. The function uses the unicode package to perform the character checks.
//
// Finally, it compares the counted values against the minimum requirements specified in the policy table.
// If any count is lower than the corresponding requirement, it pushes false onto the Lua stack and returns 1.
// Otherwise, it pushes true onto the Lua stack and returns 1.
func validatePassword(L *lua.LState) int {
	var (
		upperCount   int
		lowerCount   int
		numberCount  int
		specialCount int
	)

	policyTbl := L.ToTable(1)
	password := L.CheckString(2)

	minLength := toInt(policyTbl.RawGetString("min_length"))
	minUpper := toInt(policyTbl.RawGetString("min_upper"))
	minLower := toInt(policyTbl.RawGetString("min_lower"))
	minNumber := toInt(policyTbl.RawGetString("min_number"))
	minSpecial := toInt(policyTbl.RawGetString("min_special"))

	if len(password) < minLength {
		L.Push(lua.LBool(false))

		return 1
	}

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			upperCount++
		case unicode.IsLower(char):
			lowerCount++
		case unicode.IsDigit(char):
			numberCount++
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			specialCount++
		}
	}

	if upperCount < minUpper || lowerCount < minLower || numberCount < minNumber || specialCount < minSpecial {
		L.Push(lua.LBool(false))

		return 1
	}

	L.Push(lua.LBool(true))

	return 1
}

// SetUPMiscFunctions sets up miscellaneous functions in the given Lua table. It adds the function "check_password_policy"
// to the table, which is implemented by the validatePassword function.
//
// The function expects two arguments:
// 1. A Lua table to store the function.
// 2. A Lua state pointer.
//
// The function retrieves the constant value of "check_password_policy" from the global package and adds it as a string key
// in the provided table, with the value being a new function created by calling validatePassword with the Lua state pointer.
//
// Returns: None.
func SetUPMiscFunctions(table *lua.LTable, L *lua.LState) {
	table.RawSetString(global.LuaFnCheckPasswordPolicy, L.NewFunction(validatePassword))
}
