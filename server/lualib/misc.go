package lualib

import (
	"bufio"
	"crypto/rand"
	"math/big"
	"os"
	"time"
	"unicode"

	"github.com/biter777/countries"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/util"
	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
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

	minMillis := int64(minWait)
	maxMillis := int64(maxWait)

	randomMillis, err := getCryptoRandomInt(minMillis, maxMillis)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	time.Sleep(time.Duration(randomMillis) * time.Millisecond)

	L.Push(lua.LNumber(randomMillis))

	return 1
}

// getCryptoRandomInt returns a cryptographically secure random integer between min and max.
func getCryptoRandomInt(min, max int64) (int64, error) {
	diff := max - min
	if diff <= 0 {
		return 0, errors.ErrInvalidRange
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return 0, err
	}

	return nBig.Int64() + min, nil
}

// SetupMiscFunctions sets up miscellaneous Lua functions in the given Lua table.
// It adds the Lua functions "check_password_policy", "get_country_name", and "wait_random"
// to the table, using the respective function implementations as callbacks.
// The table is expected to be a Lua table object, and the Lua state parameter is used
// to create new Lua function objects and add them to the table.
func SetupMiscFunctions(table *lua.LTable, L *lua.LState) {
	table.RawSetString(global.LuaFnCheckPasswordPolicy, L.NewFunction(validatePassword))
	table.RawSetString(global.LuaFnGetCountryName, L.NewFunction(getCountryName))
	table.RawSetString(global.LuaFnWaitRandom, L.NewFunction(waitRandom))
}

// CompileLua reads the passed lua file from disk and compiles it.
func CompileLua(filePath string) (*lua.FunctionProto, error) {
	file, err := os.Open(filePath)

	defer file.Close()

	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)

	chunk, err := parse.Parse(reader, filePath)
	if err != nil {
		return nil, err
	}

	proto, err := lua.Compile(chunk, filePath)
	if err != nil {
		return nil, err
	}

	return proto, nil
}

// DoCompiledFile takes a FunctionProto, as returned by CompileLua, and runs it in the LState. It is equivalent
// to calling DoFile on the LState with the original source file.
func DoCompiledFile(L *lua.LState, proto *lua.FunctionProto) error {
	lfunc := L.NewFunctionFromProto(proto)

	L.Push(lfunc)

	return L.PCall(0, lua.MultRet, nil)
}

// CleanupLTable cleans up the given Lua table by setting all its values to nil.
// It iterates through the key-value pairs of the table and sets each value to nil using the RawSet method.
// This function is typically used to release resources associated with a Lua table and prevent memory leaks.
// Parameters:
// - table: A pointer to the Lua table that needs to be cleaned up.
// Returns: None.
func CleanupLTable(table *lua.LTable) {
	table.ForEach(func(key lua.LValue, value lua.LValue) {
		table.RawSet(key, lua.LNil)
	})
}

// Loader takes a *lua.LState as input and initializes a new module by setting the functions from `exports`
// into a new lua.LTable. The module table is then pushed onto the top of the stack.
// Finally, it returns 1 to indicate that one value has been returned to Lua.
func Loader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exports)

	L.Push(mod)

	return 1
}

var exports = map[string]lua.LGFunction{
	"compare_passwords": comparePasswords,
}

// comparePasswords takes two strings, `hashPassword` and `plainPassword`, as input parameters.
// It checks if the number of arguments passed is equal to 2. If not, it returns false and an error message.
// It then uses the `util.ComparePasswords` function to compare the hashed and plain passwords.
// The result of the comparison is pushed onto the Lua stack as a boolean value.
// If there is an error during the comparison, the error message is pushed onto the Lua stack.
// The function returns 2 to indicate that it has pushed 2 values onto the Lua stack.
func comparePasswords(L *lua.LState) int {
	if L.GetTop() != 2 {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("wrong number of arguments"))

		return 2
	}

	hashPassword := L.CheckString(1)
	plainPassword := L.CheckString(2)

	passwordsMatched, err := util.ComparePasswords(hashPassword, plainPassword)

	L.Push(lua.LBool(passwordsMatched))

	if err != nil {
		L.Push(lua.LString(err.Error()))
	} else {
		L.Push(lua.LNil)
	}

	return 2
}
