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
	"fmt"
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

// exportsModMisc is a map that registers miscellaneous Lua functions with their respective names and implementations.
var exportsModMisc = map[string]lua.LGFunction{
	definitions.LuaFnGetCountryName: getCountryName,
	definitions.LuaFnWaitRandom:     waitRandom,
}

// exportsModPassword is a map of Lua function names to their respective implementations for password-related operations.
var exportsModPassword = map[string]lua.LGFunction{
	definitions.LuaFnComparePasswords:     comparePasswords,
	definitions.LuaFnCheckPasswordPolicy:  validatePassword,
	definitions.LuaFnGeneratePasswordHash: generatePasswordHash,
}

// LoaderModMisc registers the miscellaneous module in the Lua state and returns the module table.
func LoaderModMisc(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModMisc)

	L.Push(mod)

	return 1
}

// LoaderModPassword registers the password-related functions in the Lua runtime and returns the module.
func LoaderModPassword(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModPassword)

	L.Push(mod)

	return 1
}

// toInt converts a Lua LValue to an integer if it is of type LNumber. If conversion is not possible, it returns 0.
func toInt(lv lua.LValue) int {
	if num, ok := lv.(lua.LNumber); ok {
		return int(num)
	}

	return 0
}

// validatePassword checks if a given password complies with policy constraints provided in a Lua table.
// It validates length, uppercase, lowercase, numeric, and special character requirements.
// Returns true if all conditions are met, false otherwise.
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

// getCountryName retrieves the country name based on an ISO code string provided as the first argument in the Lua state.
// If the ISO code is invalid or unknown, it pushes "Unknown" onto the Lua stack. Returns 1 as the result count.
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
	if err != nil {
		return nil, err
	}

	if file == nil {
		return nil, fmt.Errorf("file %s not found", filePath)
	}

	defer file.Close()

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

// comparePasswords verifies whether a plain-text password matches a hashed password using the underlying utility logic.
// Accepts two arguments: hashed password and plain-text password.
// Returns a boolean indicating match success and an error message if applicable.
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

// generatePasswordHash creates the Redis-compatible password hash matching the Go backend behavior.
// It takes one argument (password string) and returns a lowercase 8-hex-character string.
func generatePasswordHash(L *lua.LState) int {
	password := L.CheckString(1)

	hash := util.GetHash(util.PreparePassword(password))
	L.Push(lua.LString(hash))

	return 1
}
