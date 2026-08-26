// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

// TestPrepareAuthenticationBindingsCapturesExactAuthSources proves auth-shaped native sources become generation owners.
func TestPrepareAuthenticationBindingsCapturesExactAuthSources(t *testing.T) {
	bindings, environment, subject := authenticationSourceBindingsFixture()

	prepared, err := bindings.PrepareAuthenticationBindings(t.Context(), AuthenticationBindingInput{
		Sources: authenticationSourceFixtureInputs(),
	})
	if err != nil {
		t.Fatalf("PrepareAuthenticationBindings() error = %v", err)
	}

	assertCapturedAuthenticationSources(t, prepared, environment, subject)
	assertCapturedAuthenticationAttributes(t, prepared)
}

// authenticationSourceBindingsFixture builds two public source captures and one registered extension fact.
func authenticationSourceBindingsFixture() (
	*GenerationBindings,
	*recordingAuthnEnvironmentSource,
	*recordingAuthnSubjectSource,
) {
	environment := &recordingAuthnEnvironmentSource{}
	subject := &recordingAuthnSubjectSource{}
	bindings := &GenerationBindings{modules: []GenerationModuleBinding{{
		moduleName: "example",
		policyAttributes: []policyregistry.AttributeDefinition{{
			ID: "plugin.environment.example.score", Stage: policy.StagePreAuth,
			Operations:    []policy.Operation{policy.OperationAuthenticate},
			ProducerTypes: []string{policy.CheckTypePluginEnvironment},
			ProducerCheck: policy.PluginEnvironmentCheckName("example"),
			Category:      policyregistry.AttributeCategoryEnvironment,
			Type:          policyregistry.AttributeTypeNumber, Source: policyregistry.SourcePlugin,
		}},
		components: []pluginregistry.Component{
			{
				Value: environment, SourceDescriptor: environment.Descriptor(),
				QualifiedName: "example.environment", ModuleName: "example", LocalName: "environment",
				Kind: pluginregistry.ComponentKindEnvironmentSource, Origin: pluginregistry.ComponentOriginNative,
			},
			{
				Value: subject, SourceDescriptor: subject.Descriptor(),
				QualifiedName: "example.risk", ModuleName: "example", LocalName: "risk",
				Kind: pluginregistry.ComponentKindSubjectSource, Origin: pluginregistry.ComponentOriginNative,
			},
		},
	}}}

	return bindings, environment, subject
}

// authenticationSourceFixtureInputs selects the exact captured environment and subject sources.
func authenticationSourceFixtureInputs() []AuthenticationSourceBindingInput {
	return []AuthenticationSourceBindingInput{
		{
			InstanceNames: []string{"plugin_environment_example"},
			ProviderID:    "authn/plugin.example.environment", ModuleName: "example",
			ComponentName: "environment", Kind: AuthenticationSourceEnvironment,
			Operations: []policy.Operation{policy.OperationAuthenticate}, Order: 1,
		},
		{
			InstanceNames: []string{"plugin_subject_example_risk"},
			ProviderID:    "authn/plugin.example.subject.risk", ModuleName: "example",
			ComponentName: "risk", Kind: AuthenticationSourceSubject,
			Operations: []policy.Operation{policy.OperationAuthenticate}, Order: 2,
		},
	}
}

// assertCapturedAuthenticationSources verifies typed invocation ownership and exact call isolation.
func assertCapturedAuthenticationSources(
	t *testing.T,
	prepared *AuthenticationBindings,
	environment *recordingAuthnEnvironmentSource,
	subject *recordingAuthnSubjectSource,
) {
	t.Helper()

	hosts := prepared.AuthnHostProviders()
	if len(hosts) != 2 {
		t.Fatalf("prepared host providers = %#v", hosts)
	}

	environmentProgram, ok := hosts["authn/plugin.example.environment"].(interface {
		EvaluateEnvironment(context.Context, pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error)
	})
	if !ok {
		t.Fatalf("environment owner = %T, want captured evaluator", hosts["authn/plugin.example.environment"])
	}

	if _, err := environmentProgram.EvaluateEnvironment(t.Context(), pluginapi.EnvironmentRequest{}); err != nil {
		t.Fatalf("EvaluateEnvironment() error = %v", err)
	}

	subjectProgram, ok := hosts["authn/plugin.example.subject.risk"].(interface {
		EvaluateSubject(context.Context, pluginapi.SubjectRequest) (pluginapi.SubjectResult, error)
	})
	if !ok {
		t.Fatalf("subject owner = %T, want captured evaluator", hosts["authn/plugin.example.subject.risk"])
	}

	if _, err := subjectProgram.EvaluateSubject(t.Context(), pluginapi.SubjectRequest{}); err != nil {
		t.Fatalf("EvaluateSubject() error = %v", err)
	}

	if environment.calls != 1 || subject.calls != 1 {
		t.Fatalf("source calls = environment:%d subject:%d, want one each", environment.calls, subject.calls)
	}
}

// assertCapturedAuthenticationAttributes verifies registered and generated source evidence.
func assertCapturedAuthenticationAttributes(t *testing.T, prepared *AuthenticationBindings) {
	t.Helper()

	attributes := prepared.PolicyAttributes()
	if _, exists := attributes["plugin.environment.example.score"]; !exists {
		t.Fatalf("prepared Policy attributes = %#v, want captured selected source metadata", attributes)
	}

	if _, exists := attributes[policy.PluginEnvironmentAttributeID("example", "environment", "triggered")]; !exists {
		t.Fatalf("prepared Policy attributes = %#v, want generated environment evidence", attributes)
	}

	if _, exists := attributes[policy.PluginSubjectAttributeID("example", "risk", "rejected")]; !exists {
		t.Fatalf("prepared Policy attributes = %#v, want generated subject evidence", attributes)
	}
}

// TestPrepareAuthenticationBindingsActivatesPublicAttributeProducerTypes proves ProducerCheck stays optional.
func TestPrepareAuthenticationBindingsActivatesPublicAttributeProducerTypes(t *testing.T) {
	environment := &recordingAuthnEnvironmentSource{}
	obligation := &recordingAuthnObligationTarget{name: "enforce"}
	bindings := publicAttributeProducerBindings(environment, obligation)

	prepared, err := bindings.PrepareAuthenticationBindings(t.Context(), AuthenticationBindingInput{
		Sources: []AuthenticationSourceBindingInput{{
			InstanceNames: []string{"plugin_environment_example"},
			ProviderID:    "authn/plugin.example.environment", ModuleName: "example",
			ComponentName: "environment", Kind: AuthenticationSourceEnvironment,
			Operations: []policy.Operation{policy.OperationAuthenticate}, Order: 1,
		}},
	})
	if err != nil {
		t.Fatalf("PrepareAuthenticationBindings() error = %v", err)
	}

	assertPublicAttributeProducerActivation(t, prepared)
}

// publicAttributeProducerBindings builds active source, backend, effect, and inactive metadata owners.
func publicAttributeProducerBindings(
	environment *recordingAuthnEnvironmentSource,
	obligation *recordingAuthnObligationTarget,
) *GenerationBindings {
	return &GenerationBindings{modules: []GenerationModuleBinding{
		publicAttributeProducerModule(environment, obligation),
		{
			moduleName: "inactive",
			policyAttributes: []policyregistry.AttributeDefinition{{
				ID: "plugin.environment.inactive.score", Stage: policy.StagePreAuth,
				Operations:    []policy.Operation{policy.OperationAuthenticate},
				ProducerTypes: []string{policy.CheckTypePluginEnvironment},
				Category:      policyregistry.AttributeCategoryEnvironment,
				Type:          policyregistry.AttributeTypeNumber, Source: policyregistry.SourcePlugin,
			}},
		},
	}}
}

// publicAttributeProducerModule builds one module spanning every public auth attribute producer family.
func publicAttributeProducerModule(
	environment *recordingAuthnEnvironmentSource,
	obligation *recordingAuthnObligationTarget,
) GenerationModuleBinding {
	return GenerationModuleBinding{
		moduleName: "example",
		policyAttributes: []policyregistry.AttributeDefinition{
			{
				ID: "plugin.environment.example.score", Stage: policy.StagePreAuth,
				Operations:    []policy.Operation{policy.OperationAuthenticate},
				ProducerTypes: []string{policy.CheckTypePluginEnvironment}, Category: policyregistry.AttributeCategoryEnvironment,
				Type: policyregistry.AttributeTypeNumber, Source: policyregistry.SourcePlugin,
			},
			{
				ID: "plugin.backend.example.allowed", Stage: policy.StageAuthBackend,
				Operations:    []policy.Operation{policy.OperationAuthenticate},
				ProducerTypes: []string{policy.CheckTypePluginBackend}, Category: policyregistry.AttributeCategorySubject,
				Type: policyregistry.AttributeTypeBool, Source: policyregistry.SourcePlugin,
			},
			{
				ID: "plugin.resource.example.enforced", Stage: policy.StageAuthDecision,
				Operations: []policy.Operation{policy.OperationAuthenticate}, Category: policyregistry.AttributeCategoryResource,
				Type: policyregistry.AttributeTypeBool, Source: policyregistry.SourcePlugin,
			},
		},
		components: []pluginregistry.Component{
			{
				Value: environment, SourceDescriptor: environment.Descriptor(),
				QualifiedName: "example.environment", ModuleName: "example", LocalName: "environment",
				Kind: pluginregistry.ComponentKindEnvironmentSource, Origin: pluginregistry.ComponentOriginNative,
			},
			{
				Value: &struct{}{}, QualifiedName: "example.backend", ModuleName: "example", LocalName: "backend",
				Kind: pluginregistry.ComponentKindBackend, Origin: pluginregistry.ComponentOriginNative,
			},
			{
				Value: obligation, QualifiedName: "example.enforce", ModuleName: "example", LocalName: "enforce",
				Kind: pluginregistry.ComponentKindObligationTarget, Origin: pluginregistry.ComponentOriginNative,
			},
		},
	}
}

// assertPublicAttributeProducerActivation verifies active public metadata without inactive leakage.
func assertPublicAttributeProducerActivation(t *testing.T, prepared *AuthenticationBindings) {
	t.Helper()

	attributes := prepared.PolicyAttributes()
	for _, id := range []string{
		"plugin.environment.example.score",
		"plugin.backend.example.allowed",
		"plugin.resource.example.enforced",
	} {
		if _, exists := attributes[id]; !exists {
			t.Errorf("prepared Policy attributes lost public producer contract %s", id)
		}
	}

	if _, leaked := attributes["plugin.environment.inactive.score"]; leaked {
		t.Fatal("prepared Policy attributes leaked an inactive module source")
	}
}

// TestPrepareAuthenticationBindingsRegistersPolicySelectedAuthEffects proves unchanged public targets get canonical owners.
func TestPrepareAuthenticationBindingsRegistersPolicySelectedAuthEffects(t *testing.T) {
	bindings, obligation, postAction := selectedAuthenticationEffectBindings()

	prepared, err := bindings.PrepareAuthenticationBindings(t.Context(), AuthenticationBindingInput{
		PostActionAcceptance: acceptingAuthnEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("PrepareAuthenticationBindings() error = %v", err)
	}

	const (
		obligationID = "authn/plugin.clickhouse.enforce"
		postActionID = "authn/plugin.clickhouse.post_action"
	)

	assertSelectedSyncAuthenticationEffect(t, prepared, obligationID)
	assertSelectedPostAuthenticationEffect(t, prepared, postActionID)

	if obligation.calls != 1 || postAction.calls != 1 {
		t.Fatalf("effect calls = obligation:%d post:%d, want one each", obligation.calls, postAction.calls)
	}

	assertSelectedAuthenticationEffectDefinitions(t, prepared, obligationID, postActionID)
}

// selectedAuthenticationEffectBindings builds one obligation and post-action capture.
func selectedAuthenticationEffectBindings() (
	*GenerationBindings,
	*recordingAuthnObligationTarget,
	*recordingAuthnPostActionTarget,
) {
	obligation := &recordingAuthnObligationTarget{name: "enforce"}
	postAction := &recordingAuthnPostActionTarget{name: "post_action"}
	bindings := &GenerationBindings{modules: []GenerationModuleBinding{{
		moduleName:   "clickhouse",
		capabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials},
		components: []pluginregistry.Component{
			{
				Value: obligation, QualifiedName: "clickhouse.enforce", ModuleName: "clickhouse",
				LocalName: "enforce", Kind: pluginregistry.ComponentKindObligationTarget,
				Origin: pluginregistry.ComponentOriginNative,
			},
			{
				Value: postAction, QualifiedName: "clickhouse.post_action", ModuleName: "clickhouse",
				LocalName: "post_action", Kind: pluginregistry.ComponentKindPostActionTarget,
				Origin: pluginregistry.ComponentOriginNative,
			},
		},
	}}}

	return bindings, obligation, postAction
}

// assertSelectedSyncAuthenticationEffect verifies the canonical obligation owner and invocation path.
func assertSelectedSyncAuthenticationEffect(t *testing.T, prepared *AuthenticationBindings, obligationID string) {
	t.Helper()

	syncOwner, exists := prepared.SyncEffects()[obligationID]
	if !exists {
		t.Fatalf("sync effects = %#v, want %s", prepared.SyncEffects(), obligationID)
	}

	if _, legacy := prepared.SyncEffects()["authn/clickhouse.enforce"]; legacy {
		t.Fatal("bare authn native obligation alias was accepted")
	}

	program, ok := syncOwner.(interface {
		ExecuteObligation(context.Context, pluginapi.ObligationRequest) (pluginapi.ObligationResult, error)
	})
	if !ok {
		t.Fatalf("sync owner = %T, want public obligation program", syncOwner)
	}

	if _, err := program.ExecuteObligation(t.Context(), pluginapi.ObligationRequest{}); err != nil {
		t.Fatalf("ExecuteObligation() error = %v", err)
	}
}

// assertSelectedPostAuthenticationEffect verifies the canonical post-action owner and detached grants.
func assertSelectedPostAuthenticationEffect(t *testing.T, prepared *AuthenticationBindings, postActionID string) {
	t.Helper()

	postOwner, exists := prepared.PostActions()[postActionID]
	if !exists {
		t.Fatalf("post actions = %#v, want %s", prepared.PostActions(), postActionID)
	}

	postProgram, ok := postOwner.(interface {
		EnqueuePostAction(context.Context, pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error)
		Capabilities() []pluginapi.Capability
	})
	if !ok {
		t.Fatalf("post owner = %T, want public post-action program", postOwner)
	}

	if _, err := postProgram.EnqueuePostAction(t.Context(), pluginapi.PostActionRequest{}); err != nil {
		t.Fatalf("EnqueuePostAction() error = %v", err)
	}

	capabilities := postProgram.Capabilities()
	if len(capabilities) != 1 || capabilities[0] != pluginapi.CapabilityCredentials {
		t.Fatalf("post-action capabilities = %v, want detached credentials grant", capabilities)
	}

	capabilities[0] = pluginapi.CapabilityMail

	if got := postProgram.Capabilities(); len(got) != 1 || got[0] != pluginapi.CapabilityCredentials {
		t.Fatalf("post-action capabilities after caller mutation = %v", got)
	}
}

// assertSelectedAuthenticationEffectDefinitions verifies exact same-ID provider/effect ownership.
func assertSelectedAuthenticationEffectDefinitions(
	t *testing.T,
	prepared *AuthenticationBindings,
	obligationID string,
	postActionID string,
) {
	t.Helper()

	definitions := prepared.Definitions()
	if len(definitions) != 1 || len(definitions[0].Providers()) != 2 || len(definitions[0].Effects()) != 2 {
		t.Fatalf("implicit definitions = %#v, want two exact provider/effect pairs", definitions)
	}

	for _, effect := range definitions[0].Effects() {
		if effect.ID() != effect.Provider() || effect.ID() != obligationID && effect.ID() != postActionID {
			t.Fatalf("implicit effect = %s/%s, want canonical same-ID ownership", effect.ID(), effect.Provider())
		}
	}
}

type recordingAuthnEnvironmentSource struct {
	calls int
}

// Descriptor returns the exact captured environment source identity.
func (*recordingAuthnEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "environment"}
}

// Evaluate records one generation-owned environment call.
func (s *recordingAuthnEnvironmentSource) Evaluate(
	context.Context,
	pluginapi.EnvironmentRequest,
) (pluginapi.EnvironmentResult, error) {
	s.calls++

	return pluginapi.EnvironmentResult{}, nil
}

type recordingAuthnSubjectSource struct {
	calls int
}

type recordingAuthnObligationTarget struct {
	name  string
	calls int
}

// Name returns the unchanged public component-local identity.
func (t *recordingAuthnObligationTarget) Name() string { return t.name }

// Execute records one policy-selected generation-owned obligation call.
func (t *recordingAuthnObligationTarget) Execute(
	context.Context,
	pluginapi.ObligationRequest,
) (pluginapi.ObligationResult, error) {
	t.calls++

	return pluginapi.ObligationResult{Applied: true}, nil
}

type recordingAuthnPostActionTarget struct {
	name  string
	calls int
}

// Name returns the unchanged public component-local identity.
func (t *recordingAuthnPostActionTarget) Name() string { return t.name }

// Enqueue records one policy-selected generation-owned post-action call.
func (t *recordingAuthnPostActionTarget) Enqueue(
	context.Context,
	pluginapi.PostActionRequest,
) (pluginapi.PostActionEnqueueResult, error) {
	t.calls++

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}

type acceptingAuthnEffectAcceptor struct{}

// Accept acknowledges one valid test plan without retaining it.
func (acceptingAuthnEffectAcceptor) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

// Descriptor returns the exact captured subject source identity.
func (*recordingAuthnSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "risk"}
}

// Evaluate records one generation-owned subject call.
func (s *recordingAuthnSubjectSource) Evaluate(
	context.Context,
	pluginapi.SubjectRequest,
) (pluginapi.SubjectResult, error) {
	s.calls++

	return pluginapi.SubjectResult{}, nil
}
