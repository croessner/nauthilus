// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"

	lua "github.com/yuin/gopher-lua"
)

func TestConfiguredAuthnLuaActionInputHasNoLegacyFallbackAuthority(t *testing.T) {
	inputType := reflect.TypeOf(ConfiguredAuthnLuaActionInput{})
	for _, fieldName := range []string{"SyncFallback", "PostFallback"} {
		if _, exists := inputType.FieldByName(fieldName); exists {
			t.Errorf("ConfiguredAuthnLuaActionInput retains legacy fallback field %s", fieldName)
		}
	}
}

func TestPreparedAuthnLuaActionKeepsCapturedModuleBytes(t *testing.T) {
	directory := t.TempDir()

	modulePath := filepath.Join(directory, "shared.lua")
	if err := os.WriteFile(modulePath, []byte(`return { value = "captured" }`), 0o600); err != nil {
		t.Fatalf("write captured module: %v", err)
	}

	script := writeAuthnLuaActionScript(t, `
local shared = require("shared")
captured_module_value = shared.value
function nauthilus_call_action(_request) return 0 end
	`)
	configured := decodePolicy(t, fmt.Sprintf(configuredAuthnLuaActionFixture, script)).Policy
	pattern := filepath.Join(directory, "?.lua")

	artifacts := capturePolicyLuaTestArtifacts(t, configured, pattern)
	if err := os.WriteFile(modulePath, []byte(`return { value = "mutated" }`), 0o600); err != nil {
		t.Fatalf("mutate captured module: %v", err)
	}

	if err := os.WriteFile(script, []byte("function broken("), 0o600); err != nil {
		t.Fatalf("mutate captured action: %v", err)
	}

	modules, err := luaseal.CaptureSnapshot([]string{pattern}, artifacts)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	preparation, err := PrepareConfiguredAuthnLuaActions(t.Context(), ConfiguredAuthnLuaActionInput{
		PostActionAcceptance: &nativeGenerationAcceptor{},
		Artifacts:            artifacts,
		Modules:              modules,
		Pools:                vmpool.NewManager(),
		Policy:               configured,
		Generation:           75,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaActions() error = %v", err)
	}

	dispatcher, ok := preparation.Bindings.SyncEffects()[authnLuaActionSyncProvider].(configuredAuthnLuaSyncDispatcher)
	if !ok {
		t.Fatal("configured action dispatcher has no exact prepared implementation")
	}

	action := dispatcher.actions["authn/lua_action_notify"]
	if action == nil {
		t.Fatal("configured action is unavailable")
	}

	assertPreparedAuthnLuaActionCapturedModules(t, action)
}

// assertPreparedAuthnLuaActionCapturedModules checks repeatable execution against sealed module bytes.
func assertPreparedAuthnLuaActionCapturedModules(t *testing.T, action *preparedAuthnLuaAction) {
	t.Helper()

	for index := 0; index < 2; index++ {
		_, prototype, openErr := action.OpenCompiledLuaAction()
		if openErr != nil {
			t.Fatalf("open action state %d: %v", index, openErr)
		}

		state, stateErr := newAuthnLuaSourceValidationState(
			action.SealedLuaModules(),
			luaseal.PolicyProfileResponseAction,
		)
		if stateErr != nil {
			t.Fatalf("validation state %d: %v", index, stateErr)
		}

		if stateErr = lualib.DoCompiledFile(state, prototype); stateErr != nil {
			state.Close()
			t.Fatalf("execute action state %d: %v", index, stateErr)
		}

		if got := state.GetGlobal("captured_module_value").String(); got != "captured" {
			state.Close()
			t.Fatalf("action state %d module = %q, want captured", index, got)
		}

		state.Close()
	}
}

var _ interface {
	OpenCompiledLuaAction() (string, *lua.FunctionProto, error)
	LuaPoolManager() *vmpool.Manager
	SealedLuaModules() *luaseal.Modules
} = (*preparedAuthnLuaAction)(nil)

const configuredAuthnLuaActionFixture = `policy:
  namespaces:
    authn:
      effects:
        lua_action_notify:
          kind: lua_action
          action_type: lua
          script_path: %q
          targets: [{action: authenticate}]
          execution: host_sync
      domain_plans:
        configured:
          checkpoints:
            pre_auth: {providers: []}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          rules:
            - name: configured_action
              checkpoint: auth_decision
              if: {always: true}
              then:
                decision: deny
                obligations: [{id: authn/lua_action_notify}]
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        auth_decision: {policy_sets: [authn/configured]}
`

type recordingAuthnLuaActionHost struct {
	id    string
	calls int
}

// ExecuteAuthnLuaAction records one exact configured program dispatch.
func (h *recordingAuthnLuaActionHost) ExecuteAuthnLuaAction(
	_ context.Context,
	program policyruntime.AuthnLuaActionProgram,
	_ policyruntime.EffectExecution,
) effectsupervisor.Result {
	h.calls++
	h.id = program.ID()

	return effectsupervisor.Succeeded()
}

// PrepareAuthnLuaPostAction rejects the unused post-action branch in this synchronous fixture.
func (*recordingAuthnLuaActionHost) PrepareAuthnLuaPostAction(
	context.Context,
	policyruntime.AuthnLuaActionProgram,
	policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	return nil, fmt.Errorf("unexpected post-action preparation")
}

// TestPrepareConfiguredAuthnLuaActionsBindsExactEffectOnce proves generation-owned dispatch.
func TestPrepareConfiguredAuthnLuaActionsBindsExactEffectOnce(t *testing.T) {
	script := writeAuthnLuaActionScript(t, `
function nauthilus_call_action(request)
    return 1
end
`)
	configured := decodePolicy(t, fmt.Sprintf(configuredAuthnLuaActionFixture, script)).Policy

	preparation, err := PrepareConfiguredAuthnLuaActions(t.Context(), ConfiguredAuthnLuaActionInput{
		PostActionAcceptance: &nativeGenerationAcceptor{},
		Artifacts:            capturePolicyLuaTestArtifacts(t, configured),
		Pools:                vmpool.NewManager(),
		Policy:               configured,
		Generation:           71,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaActions() error = %v", err)
	}

	provider := preparation.Bindings.SyncEffects()[authnLuaActionSyncProvider]
	if provider == nil {
		t.Fatal("configured authn Lua action dispatcher is missing")
	}

	execution := newConfiguredAuthnLuaActionExecution(t, 71)
	host := &recordingAuthnLuaActionHost{}
	ctx := policyruntime.ContextWithAuthnLuaActionHost(t.Context(), host)

	result := provider.Execute(ctx, execution)
	if result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("Execute() state = %q, want succeeded", result.State())
	}

	if host.calls != 1 || host.id != "authn/lua_action_notify" {
		t.Fatalf("configured action calls = %d/%q, want 1/authn/lua_action_notify", host.calls, host.id)
	}
}

// TestPrepareConfiguredAuthnLuaActionsValidatesKnownRequestModuleCalls proves safe precommit callback execution.
func TestPrepareConfiguredAuthnLuaActionsValidatesKnownRequestModuleCalls(t *testing.T) {
	script := writeAuthnLuaActionScript(t, `
local response = require("nauthilus_http_response")

function nauthilus_call_action(request)
    response.add_http_response_header("X-Policy-Test", "accepted")

    return 0
end
`)
	configured := decodePolicy(t, fmt.Sprintf(configuredAuthnLuaActionFixture, script)).Policy

	_, err := PrepareConfiguredAuthnLuaActions(t.Context(), ConfiguredAuthnLuaActionInput{
		PostActionAcceptance: &nativeGenerationAcceptor{},
		Artifacts:            capturePolicyLuaTestArtifacts(t, configured),
		Pools:                vmpool.NewManager(),
		Policy:               configured,
		Generation:           74,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaActions() error = %v", err)
	}
}

func TestPrepareConfiguredAuthnLuaPostActionRejectsHTTPResponseCapability(t *testing.T) {
	script := writeAuthnLuaActionScript(t, `
function nauthilus_call_action(_request)
    local response = require("nauthilus_http_response")
    response.add_http_response_header("X-Policy-Test", "forbidden")

    return 0
end
`)
	fixture := strings.Replace(configuredAuthnLuaActionFixture, "action_type: lua", "action_type: post", 1)
	fixture = strings.Replace(fixture, "execution: host_sync", "execution: host_post_action", 1)
	configured := decodePolicy(t, fmt.Sprintf(fixture, script)).Policy

	_, err := PrepareConfiguredAuthnLuaActions(t.Context(), ConfiguredAuthnLuaActionInput{
		PostActionAcceptance: &nativeGenerationAcceptor{},
		Artifacts:            capturePolicyLuaTestArtifacts(t, configured),
		Pools:                vmpool.NewManager(),
		Policy:               configured,
		Generation:           76,
	})
	if err == nil {
		t.Fatal("PrepareConfiguredAuthnLuaActions() accepted HTTP response mutation in a post action")
	}
}

// TestPrepareConfiguredAuthnLuaActionsRejectsInvalidCandidateScripts protects precommit validation.
func TestPrepareConfiguredAuthnLuaActionsRejectsInvalidCandidateScripts(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "syntax", source: "function nauthilus_call_action("},
		{name: "missing callback", source: "return true"},
		{name: "unsupported return", source: "function nauthilus_call_action(request) return 2 end"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			script := writeAuthnLuaActionScript(t, test.source)
			configured := decodePolicy(t, fmt.Sprintf(configuredAuthnLuaActionFixture, script)).Policy

			_, err := PrepareConfiguredAuthnLuaActions(t.Context(), ConfiguredAuthnLuaActionInput{
				PostActionAcceptance: &nativeGenerationAcceptor{},
				Artifacts:            capturePolicyLuaTestArtifacts(t, configured),
				Pools:                vmpool.NewManager(),
				Policy:               configured,
				Generation:           72,
			})
			if err == nil {
				t.Fatal("PrepareConfiguredAuthnLuaActions() accepted an invalid candidate script")
			}
		})
	}

	missing := filepath.Join(t.TempDir(), "missing.lua")
	configured := decodePolicy(t, fmt.Sprintf(configuredAuthnLuaActionFixture, missing)).Policy

	_, err := PrepareConfiguredAuthnLuaActions(t.Context(), ConfiguredAuthnLuaActionInput{
		PostActionAcceptance: &nativeGenerationAcceptor{},
		Artifacts:            captureEmptyLuaTestArtifacts(t),
		Pools:                vmpool.NewManager(),
		Policy:               configured,
		Generation:           73,
	})
	if err == nil || strings.Contains(err.Error(), "%!w") {
		t.Fatalf("missing action error = %v, want a concrete candidate rejection", err)
	}
}

// writeAuthnLuaActionScript writes one candidate-scoped action source.
func writeAuthnLuaActionScript(t *testing.T, source string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "action.lua")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

// newConfiguredAuthnLuaActionExecution constructs one exact selected configured effect.
func newConfiguredAuthnLuaActionExecution(t *testing.T, generation uint64) policyruntime.EffectExecution {
	t.Helper()

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "configured-action-test", AuthenticationKind: "internal", TransportKind: "internal", Internal: true,
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	parameters, err := decision.NewValueMap(nil)
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	execution, err := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
		Facts: facts, Caller: caller, Parameters: parameters, Target: target,
		EffectID: "authn/lua_action_notify", DecisionID: "configured-action-decision",
		Provider: authnLuaActionSyncProvider, Generation: generation, Ordinal: 1,
	})
	if err != nil {
		t.Fatalf("NewEffectExecution() error = %v", err)
	}

	return execution
}

var _ policyruntime.AuthnLuaActionHost = (*recordingAuthnLuaActionHost)(nil)
