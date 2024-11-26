// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package lualib

import (
	"bufio"
	"crypto/rand"
	"math/big"
	"os"
	"time"
	"unicode"

	"github.com/biter777/countries"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/util"
	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// exportsModMisc is a variable of type map[string]lua.LGFunction that holds the mappings
// between Lua function names and their corresponding Go implementations.
// It contains two key-value pairs:
// 1. Key: definitions.LuaFnGetCountryName, Value: getCountryName
// 2. Key: definitions.LuaFnWaitRandom, Value: waitRandom
var exportsModMisc = map[string]lua.LGFunction{
	definitions.LuaFnGetCountryName: getCountryName,
	definitions.LuaFnWaitRandom:     waitRandom,
}

// `exportsModPassword` is a variable of type map[string]lua.LGFunction that contains the exported Lua functions for the module.
// It maps the names of the Lua functions to their corresponding Go functions.
// The module provides two functions: `comparePasswords` and `validatePassword`.
// `comparePasswords` compares two passwords and returns a boolean value indicating whether they match.
// `validatePassword` validates a password against a set of policy requirements and returns a boolean value indicating whether the password is valid.
// Both functions are used as Lua function callbacks and interact with the Lua stack to push the results.
// The module is typically used by the `LoaderModPassword` function to initialize a new Lua module.
// The `exportsModPassword` variable itself is not mentioned in the surrounding code example.
var exportsModPassword = map[string]lua.LGFunction{
	definitions.LuaFnComparePasswords:    comparePasswords,
	definitions.LuaFnCheckPasswordPolicy: validatePassword,
}

// LoaderModMisc initializes a new module for the "nauthilus_misc" module in Lua.
// It sets the functions from the "exportsModMisc" map into a new lua.LTable.
// The module table is then pushed onto the top of the stack.
// Finally, it returns 1 to indicate that one value has been returned to Lua.
func LoaderModMisc(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModMisc)

	L.Push(mod)

	return 1
}

// LoaderModPassword takes a *lua.LState as input and initializes a new module by setting the functions from `exportsModPassword`
// into a new lua.LTable. The module table is then pushed onto the top of the stack.
// Finally, it returns 1 to indicate that one value has been returned to Lua.
func LoaderModPassword(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModPassword)

	L.Push(mod)

	return 1
}

// toInt converts the given Lua value to an integer.
// If the value is a Lua number, it is converted to an integer and returned.
// If the value is not a Lua number, 0 is returned.
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
