// Copyright (C) 2026 Christian Rößner
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

package policyprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

const (
	maximumLuaPolicyScriptBytes = 1024 * 1024
	maximumLuaScriptNameBytes   = 1024
)

var (
	// ErrScriptPreparation identifies a bounded generic Lua script that could not be compiled.
	ErrScriptPreparation = errors.New("lua policy script preparation failed")

	// ErrCallbackRegistration identifies a missing or unusable exact generic callback.
	ErrCallbackRegistration = errors.New("lua policy callback registration failed")

	// ErrCallbackInput identifies a rejected target, caller, fact, effect, or parameter request.
	ErrCallbackInput = errors.New("invalid Lua policy callback input")

	// ErrCallbackExecution identifies a contained Lua error, panic, cancellation, or timeout.
	ErrCallbackExecution = errors.New("lua policy callback execution failed")
)

var (
	errLuaOperation = errors.New("lua policy operation rejected")
	errLuaCallback  = errors.New("lua policy callback is unavailable")
	errLuaResult    = errors.New("lua policy callback result rejected")
)

// Script is one immutable precompiled generic Lua policy-provider program.
type Script struct {
	prototype *lua.FunctionProto
}

// CompileScript compiles one bounded source without retaining the caller's bytes.
func CompileScript(name string, source []byte) (*Script, error) {
	if !validScriptName(name) || len(source) == 0 || len(source) > maximumLuaPolicyScriptBytes {
		return nil, ErrScriptPreparation
	}

	chunk, err := parse.Parse(bytes.NewReader(append([]byte(nil), source...)), name)
	if err != nil {
		return nil, ErrScriptPreparation
	}

	prototype, err := lua.Compile(chunk, name)
	if err != nil {
		return nil, ErrScriptPreparation
	}

	return &Script{prototype: prototype}, nil
}

// CompileScriptFile reads and compiles one bounded configured Lua file.
func CompileScriptFile(path string) (*Script, error) {
	if !validScriptName(path) {
		return nil, ErrScriptPreparation
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, ErrScriptPreparation
	}
	defer func() { _ = file.Close() }()

	source, err := readBoundedScript(file)
	if err != nil {
		return nil, ErrScriptPreparation
	}

	return CompileScript(path, source)
}

// validateCallback checks one exact callback in an isolated restricted state.
func (s *Script) validateCallback(ctx context.Context, callback string) error {
	if !s.constructed() || !registeredCallbackName(callback) || ctx == nil {
		return ErrCallbackRegistration
	}

	err := s.withState(ctx, func(state *lua.LState) error {
		if executeErr := executeLuaPrototype(state, s.prototype); executeErr != nil {
			return errLuaOperation
		}

		if state.GetGlobal(callback).Type() != lua.LTFunction {
			return errLuaCallback
		}

		return nil
	})
	if err != nil {
		return classifiedCallbackError(ctx, ErrCallbackRegistration)
	}

	return nil
}

// invoke executes one exact callback and consumes its result before closing the fresh state.
func (s *Script) invoke(
	ctx context.Context,
	callback string,
	buildRequest func(*lua.LState) lua.LValue,
	consumeResult func(lua.LValue) error,
) error {
	if invalidInvocation(ctx, s, callback, buildRequest, consumeResult) {
		return ErrCallbackInput
	}

	err := s.withState(ctx, func(state *lua.LState) error {
		return s.invokeState(state, callback, buildRequest, consumeResult)
	})

	return classifyInvocationError(ctx, err)
}

// invokeState performs one protected callback call while the request-owned state is alive.
func (s *Script) invokeState(
	state *lua.LState,
	callback string,
	buildRequest func(*lua.LState) lua.LValue,
	consumeResult func(lua.LValue) error,
) error {
	if err := executeLuaPrototype(state, s.prototype); err != nil {
		return errLuaOperation
	}

	callbackValue := state.GetGlobal(callback)
	if callbackValue.Type() != lua.LTFunction {
		return errLuaCallback
	}

	request := buildRequest(state)
	if err := state.CallByParam(lua.P{Fn: callbackValue, NRet: 1, Protect: true}, request); err != nil {
		return errLuaOperation
	}

	result := state.Get(-1)
	defer state.Pop(1)

	if err := consumeResult(result); err != nil {
		return errLuaResult
	}

	return nil
}

// invalidInvocation rejects incomplete dependencies before allocating a Lua state.
func invalidInvocation(
	ctx context.Context,
	script *Script,
	callback string,
	buildRequest func(*lua.LState) lua.LValue,
	consumeResult func(lua.LValue) error,
) bool {
	return !script.constructed() || ctx == nil || !registeredCallbackName(callback) ||
		buildRequest == nil || consumeResult == nil
}

// classifyInvocationError maps internal sentinels to the stable secret-safe public taxonomy.
func classifyInvocationError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, errLuaResult):
		return fmt.Errorf("%w: %w", ErrCallbackExecution, ErrInvalidResult)
	case errors.Is(err, errLuaCallback):
		return ErrCallbackRegistration
	case err != nil:
		return classifiedCallbackError(ctx, ErrCallbackExecution)
	default:
		return nil
	}
}

// withState owns fresh-state setup, context binding, cleanup, and panic containment.
func (s *Script) withState(ctx context.Context, operation func(*lua.LState) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errLuaOperation
		}
	}()

	state := newRestrictedLuaState()
	defer state.Close()

	state.SetContext(ctx)

	return operation(state)
}

// constructed reports whether a script came through the bounded compiler.
func (s *Script) constructed() bool {
	return s != nil && s.prototype != nil
}

// newRestrictedLuaState opens only deterministic computation libraries and removes effectful base functions.
func newRestrictedLuaState() *lua.LState {
	state := lua.NewState(lua.Options{SkipOpenLibs: true})

	for _, library := range []struct {
		open lua.LGFunction
		name string
	}{
		{open: lua.OpenBase, name: lua.BaseLibName},
		{open: lua.OpenTable, name: lua.TabLibName},
		{open: lua.OpenString, name: lua.StringLibName},
		{open: lua.OpenMath, name: lua.MathLibName},
	} {
		state.Push(state.NewFunction(library.open))
		state.Push(lua.LString(library.name))
		state.Call(1, 0)
	}

	for _, name := range []string{
		"collectgarbage",
		"dofile",
		"load",
		"loadfile",
		"loadstring",
		"module",
		"print",
		"require",
		"_printregs",
	} {
		state.SetGlobal(name, lua.LNil)
	}

	return state
}

// executeLuaPrototype loads one immutable prototype into the request-owned state.
func executeLuaPrototype(state *lua.LState, prototype *lua.FunctionProto) error {
	function := state.NewFunctionFromProto(prototype)

	return state.CallByParam(lua.P{Fn: function, NRet: 0, Protect: true})
}

// readBoundedScript reads at most one byte beyond the source limit for deterministic rejection.
func readBoundedScript(reader io.Reader) ([]byte, error) {
	source, err := io.ReadAll(io.LimitReader(reader, maximumLuaPolicyScriptBytes+1))
	if err != nil || len(source) == 0 || len(source) > maximumLuaPolicyScriptBytes {
		return nil, ErrScriptPreparation
	}

	return source, nil
}

// validScriptName checks the non-secret compiler source label bound.
func validScriptName(name string) bool {
	return name != "" && len(name) <= maximumLuaScriptNameBytes && utf8.ValidString(name)
}

// registeredCallbackName recognizes only the two generic extension callback points.
func registeredCallbackName(callback string) bool {
	return callback == PolicyFactsCollectCallback || callback == PolicyEffectsExecuteCallback
}

// classifiedCallbackError preserves context identity while discarding Lua text.
func classifiedCallbackError(ctx context.Context, class error) error {
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("%w: %w", class, ctx.Err())
	}

	return class
}
