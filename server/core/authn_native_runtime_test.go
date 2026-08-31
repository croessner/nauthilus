// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"sync/atomic"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	authnNativeObligationTestID = "authn/plugin.example.enforce"
	authnNativePostActionTestID = "authn/plugin.example.archive"
)

func TestAuthnNativeObligationExecutesExactSelectedProgramOnce(t *testing.T) {
	auth, ginCtx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
	runtime := &authnNativeTestRuntime{}
	auth.deps.NativeRuntime = runtime
	program := &authnNativeObligationTestProgram{id: authnNativeObligationTestID}
	host := &authnCandidateExecution{
		auth: auth, ginCtx: ginCtx, operation: policy.OperationAuthenticate,
	}

	result := host.ExecuteAuthnNativeObligation(
		t.Context(),
		program,
		newAuthnNativeTestExecution(t, authnNativeObligationTestID),
	)
	if result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("ExecuteAuthnNativeObligation() = %s/%q, want succeeded", result.State(), result.ErrorClass())
	}

	if program.calls.Load() != 1 || runtime.captures.Load() != 1 {
		t.Fatalf("native obligation calls/captures = %d/%d, want 1/1", program.calls.Load(), runtime.captures.Load())
	}
}

func TestAuthnNativePostActionCapturesCapabilitiesAndExecutesAtMostOnce(t *testing.T) {
	auth, ginCtx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
	runtime := &authnNativeTestRuntime{}
	auth.deps.NativeRuntime = runtime
	program := &authnNativePostActionTestProgram{
		id:           authnNativePostActionTestID,
		capabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials},
	}
	host := &authnCandidateExecution{
		auth: auth, ginCtx: ginCtx, operation: policy.OperationAuthenticate,
	}

	work, err := host.PrepareAuthnNativePostAction(
		t.Context(),
		program,
		newAuthnNativeTestExecution(t, authnNativePostActionTestID),
	)
	if err != nil {
		t.Fatalf("PrepareAuthnNativePostAction() error = %v", err)
	}

	executable, ok := work.(effectsupervisor.ExecutableWork)
	if !ok {
		t.Fatalf("native post-action work type = %T, want ExecutableWork", work)
	}
	defer executable.Cleanup()

	first := executable.Execute(t.Context())

	second := executable.Execute(t.Context())
	if first.State() != effectsupervisor.StateSucceeded || second.State() != effectsupervisor.StateFailed {
		t.Fatalf("native post-action states = %s/%s, want succeeded/failed", first.State(), second.State())
	}

	if program.calls.Load() != 1 || runtime.captures.Load() != 1 || !runtime.detached.Load() {
		t.Fatalf(
			"native post-action calls/captures/detached = %d/%d/%t, want 1/1/true",
			program.calls.Load(), runtime.captures.Load(), runtime.detached.Load(),
		)
	}

	if runtime.capability != pluginapi.CapabilityCredentials {
		t.Fatalf("native post-action capability = %q, want credentials", runtime.capability)
	}
}

type authnNativeTestRuntime struct {
	capability pluginapi.Capability
	captures   atomic.Int32
	detached   atomic.Bool
}

// Capture records projection options and returns immutable public test values.
func (r *authnNativeTestRuntime) Capture(
	_ context.Context,
	input AuthnNativeCaptureInput,
) (AuthnNativeCapture, error) {
	r.captures.Add(1)
	r.detached.Store(input.Detached)

	if len(input.Capabilities) > 0 {
		r.capability = input.Capabilities[0]
	}

	return AuthnNativeCapture{
		Runtime:      authnNativeTestRuntimeContext{},
		Snapshot:     pluginapi.RequestSnapshot{Username: input.Auth.GetUsername()},
		PasswordHash: "captured-password-hash",
	}, nil
}

// ApplyRuntimeDelta accepts the empty result used by exact execution tests.
func (*authnNativeTestRuntime) ApplyRuntimeDelta(*AuthState, pluginapi.RuntimeDelta) error {
	return nil
}

type authnNativeTestRuntimeContext map[string]any

// Get returns one detached test runtime value.
func (c authnNativeTestRuntimeContext) Get(key string) (any, bool) {
	value, ok := c[key]

	return value, ok
}

// Snapshot returns a detached test runtime value map.
func (c authnNativeTestRuntimeContext) Snapshot() map[string]any {
	result := make(map[string]any, len(c))
	for key, value := range c {
		result[key] = value
	}

	return result
}

type authnNativeObligationTestProgram struct {
	id    string
	calls atomic.Int32
}

// ID returns the exact selected obligation identity.
func (p *authnNativeObligationTestProgram) ID() string { return p.id }

// ExecuteObligation records the exact public request invocation.
func (p *authnNativeObligationTestProgram) ExecuteObligation(
	context.Context,
	pluginapi.ObligationRequest,
) (pluginapi.ObligationResult, error) {
	p.calls.Add(1)

	return pluginapi.ObligationResult{Applied: true}, nil
}

type authnNativePostActionTestProgram struct {
	id           string
	capabilities []pluginapi.Capability
	calls        atomic.Int32
}

// ID returns the exact selected post-action identity.
func (p *authnNativePostActionTestProgram) ID() string { return p.id }

// Capabilities returns the detached generation-captured module grant.
func (p *authnNativePostActionTestProgram) Capabilities() []pluginapi.Capability {
	return append([]pluginapi.Capability(nil), p.capabilities...)
}

// EnqueuePostAction records one detached supervisor-owned invocation.
func (p *authnNativePostActionTestProgram) EnqueuePostAction(
	context.Context,
	pluginapi.PostActionRequest,
) (pluginapi.PostActionEnqueueResult, error) {
	p.calls.Add(1)

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}

// newAuthnNativeTestExecution builds one canonical exact native effect selection.
func newAuthnNativeTestExecution(t *testing.T, effectID string) policyruntime.EffectExecution {
	t.Helper()

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("decision.NewFactSet() error = %v", err)
	}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "authn-native-test", AuthenticationKind: "internal", TransportKind: "internal", Internal: true,
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
		EffectID: effectID, DecisionID: "decision-authn-native-test", Provider: effectID,
		Generation: 902, Ordinal: 1,
	})
	if err != nil {
		t.Fatalf("policyruntime.NewEffectExecution() error = %v", err)
	}

	return execution
}

var _ decisionservice.AuthnNativeEffectHost = (*authnCandidateExecution)(nil)
