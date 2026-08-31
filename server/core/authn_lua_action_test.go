// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"

	lua "github.com/yuin/gopher-lua"
)

const authnLuaActionTestEffectID = "authn/lua_action_exact"

type authnLuaActionTestProgram struct {
	prototype *lua.FunctionProto
	pools     *vmpool.Manager
}

// ID returns the exact configured test effect identity.
func (authnLuaActionTestProgram) ID() string {
	return authnLuaActionTestEffectID
}

// OpenCompiledLuaAction returns the exact test-owned action prototype.
func (p authnLuaActionTestProgram) OpenCompiledLuaAction() (string, *lua.FunctionProto, error) {
	return "exact", p.prototype, nil
}

// LuaPoolKey returns the exact generation-specific test pool key.
func (authnLuaActionTestProgram) LuaPoolKey() string {
	return "policy-authn:901:lua_action:" + authnLuaActionTestEffectID
}

// LuaPoolManager returns the test generation's explicit isolated pool owner.
func (p authnLuaActionTestProgram) LuaPoolManager() *vmpool.Manager {
	return p.pools
}

// SealedLuaModules returns the empty external module snapshot used by this test.
func (authnLuaActionTestProgram) SealedLuaModules() *luaseal.Modules {
	return nil
}

func TestAuthnLuaActionHostExecutesExactCapturedProgramOnce(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	auth, ginCtx, _ := newCurrentBehaviorAuthState(t, cfg)
	program := authnLuaActionTestProgram{
		prototype: compileAuthnLuaActionTestProgram(t), pools: vmpool.NewManager(),
	}
	execution := newAuthnLuaActionTestExecution(t)
	host := &authnCandidateExecution{auth: auth, ginCtx: ginCtx}

	result := host.ExecuteAuthnLuaAction(t.Context(), program, execution)
	if result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("ExecuteAuthnLuaAction() = %s/%q, want succeeded", result.State(), result.ErrorClass())
	}

	values := ginCtx.Writer.Header().Values("X-Nauthilus-Policy-Action")
	if len(values) != 1 || values[0] != "exact" {
		t.Fatalf("exact action response values = %#v, want one execution", values)
	}
}

func TestAuthnLuaActionHostUsesProgramOwnedPoolManager(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	auth, ginCtx, _ := newCurrentBehaviorAuthState(t, cfg)
	program := authnLuaActionTestProgram{
		prototype: compileAuthnLuaActionTestProgram(t), pools: vmpool.NewManager(),
	}
	poolKey := vmpool.PoolKey(program.LuaPoolKey())
	pool := program.pools.GetOrCreate(poolKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg})

	lease, err := pool.AcquireLease(t.Context())
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	defer func() {
		lease.Release()

		if deleteErr := program.pools.Delete(poolKey); deleteErr != nil {
			t.Errorf("Delete() error = %v", deleteErr)
		}
	}()

	execution := newAuthnLuaActionTestExecution(t)
	host := &authnCandidateExecution{auth: auth, ginCtx: ginCtx}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	result := host.ExecuteAuthnLuaAction(ctx, program, execution)
	if result.State() != effectsupervisor.StateFailed {
		t.Fatalf("ExecuteAuthnLuaAction() state = %s, want captured-pool timeout failure", result.State())
	}

	if values := ginCtx.Writer.Header().Values("X-Nauthilus-Policy-Action"); len(values) != 0 {
		t.Fatalf("blocked captured pool unexpectedly executed action: %#v", values)
	}
}

func TestAuthnRequestStageFlagsUseObservedRequestState(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment string
		rejected    bool
		want        AuthnRequestStageFlags
	}{
		{
			name: "active request",
			want: AuthnRequestStageFlags{
				EnvironmentStageExpected: true,
				SubjectStageExpected:     true,
			},
		},
		{
			name:        "policy environment rejection",
			environment: definitions.ControlLua,
			rejected:    true,
			want: AuthnRequestStageFlags{
				EnvironmentRejected:      true,
				EnvironmentStageExpected: true,
			},
		},
		{
			name:        "brute force rejection before environment",
			environment: definitions.ControlBruteForce,
			rejected:    true,
			want: AuthnRequestStageFlags{
				EnvironmentRejected: true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, ginCtx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))

			auth.Runtime.EnvironmentName = test.environment
			if test.rejected {
				ginCtx.Set(definitions.CtxEnvironmentRejectedKey, true)
			}

			if got := auth.AuthnRequestStageFlags(); got != test.want {
				t.Fatalf("AuthnRequestStageFlags() = %#v, want %#v", got, test.want)
			}
		})
	}
}

// compileAuthnLuaActionTestProgram compiles the exact request-owned response marker.
func compileAuthnLuaActionTestProgram(t *testing.T) *lua.FunctionProto {
	t.Helper()

	path := filepath.Join(t.TempDir(), "authn-action.lua")

	source := []byte(`
local response = require("nauthilus_http_response")

function nauthilus_call_action(request)
    if request.session == "guid-current-behavior" then
        response.add_http_response_header("X-Nauthilus-Policy-Action", "exact")
    end

    return 0
end
`)
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatalf("write exact authn action: %v", err)
	}

	prototype, err := compileLuaTestFile(path)
	if err != nil {
		t.Fatalf("compile exact authn action: %v", err)
	}

	return prototype
}

// newAuthnLuaActionTestExecution builds one strict selected-effect invocation.
func newAuthnLuaActionTestExecution(t *testing.T) policyruntime.EffectExecution {
	t.Helper()

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("decision.NewFactSet() error = %v", err)
	}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "authn-action-test", AuthenticationKind: "internal", TransportKind: "internal", Internal: true,
	})
	if err != nil {
		t.Fatalf("decision.NewCallerContext() error = %v", err)
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	parameters, err := decision.NewValueMap(nil)
	if err != nil {
		t.Fatalf("decision.NewValueMap() error = %v", err)
	}

	execution, err := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
		Facts: facts, Caller: caller, Parameters: parameters, Target: target,
		EffectID: authnLuaActionTestEffectID, DecisionID: "decision-authn-lua-action-test",
		Provider: "authn/lua_action", Generation: 901, Ordinal: 1,
	})
	if err != nil {
		t.Fatalf("policyruntime.NewEffectExecution() error = %v", err)
	}

	return execution
}

var _ policyruntime.AuthnLuaActionProgram = authnLuaActionTestProgram{}
var _ interface {
	OpenCompiledLuaAction() (string, *lua.FunctionProto, error)
	LuaPoolKey() string
	LuaPoolManager() *vmpool.Manager
	SealedLuaModules() *luaseal.Modules
} = authnLuaActionTestProgram{}
