package lualib

import (
	"math/rand"
	"time"
	"unicode"

	"github.com/biter777/countries"
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

// getCountryName retrieves the country name based on the given ISO code.
//
// It takes a Lua state pointer as input and returns an integer indicating the number of values pushed onto the stack.
// The function expects one argument:
//  1. A string representing the ISO code of the country.
//
// The function first checks if the ISO code exists in the countries database.
// If the code is unknown, it pushes the string "Unknown" onto the Lua stack.
// Otherwise, it retrieves the country name and pushes it onto the Lua stack.
//
// The function does not throw any errors.
//
// It returns 1 to indicate that one value has been pushed onto the stack.
func getCountryName(L *lua.LState) int {
	isoCode := L.CheckString(1)
	country := countries.ByName(isoCode)

	if country == countries.Unknown {
		L.Push(lua.LString("Unknown"))
	} else {
		countryName := country.String()
		L.Push(lua.LString(countryName))
	}

	return 1
}

// waitRandom waits for a random amount of time between `minWait` and `maxWait`.
func waitRandom(L *lua.LState) int {
	minWait := L.CheckNumber(1)
	maxWait := L.CheckNumber(2)

	if minWait < 0 || maxWait < 0 || minWait >= maxWait {
		L.Push(lua.LNil)

		return 1
	}

	minMillis := int(minWait)
	maxMillis := int(maxWait)

	rand.Seed(time.Now().UnixNano())
	randomMillis := rand.Intn(maxMillis-minMillis) + minMillis

	time.Sleep(time.Duration(randomMillis) * time.Millisecond)

	L.Push(lua.LNumber(randomMillis))

	return 1
}

// SetUPMiscFunctions sets up miscellaneous Lua functions in the given Lua table.
// It adds the Lua functions "check_password_policy", "get_country_name", and "wait_random"
// to the table, using the respective function implementations as callbacks.
// The table is expected to be a Lua table object, and the Lua state parameter is used
// to create new Lua function objects and add them to the table.
func SetUPMiscFunctions(table *lua.LTable, L *lua.LState) {
	table.RawSetString(global.LuaFnCheckPasswordPolicy, L.NewFunction(validatePassword))
	table.RawSetString(global.LuaFnGetCountryName, L.NewFunction(getCountryName))
	table.RawSetString(global.LuaFnWaitRandom, L.NewFunction(waitRandom))
}
