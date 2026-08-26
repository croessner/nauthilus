// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// TestInternalSessionCapturesPresentationAndConfigTogether proves internal authority is generation-owned.
func TestInternalSessionCapturesPresentationAndConfigTogether(t *testing.T) {
	configured := testPolicyAPIConfig(true, true, true)
	invocation := mustAuthorityInvocation(t, true)

	profileID, err := NewInternalProfileID("backchannel", "authenticate")
	if err != nil {
		t.Fatalf("NewInternalProfileID() error = %v", err)
	}

	authenticator := &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)}

	generation, err := newRuntimeGeneration(7, runtimeGenerationDependencies{
		material:      mustRuntimeGenerationMaterial(t, configured, map[string]decision.AuthenticationInput{profileID.String(): invocation.Authentication}),
		authenticator: authenticator,
		admission:     &recordingAdmissionAuthority{},
		evaluator:     &recordingCheckpointEvaluator{},
		supervisor:    &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("newRuntimeGeneration() error = %v", err)
	}

	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	err = service.WithInternalSession(context.Background(), InternalSessionInput{
		ProfileID:    profileID,
		Request:      invocation.Request,
		Finalization: invocation.Finalization,
	}, func(session DecisionSession) error {
		requestCtx := session.RequestContext(context.Background())

		captured, ok := CapturedConfigFromContext(requestCtx)
		if !ok || captured != configured {
			t.Fatalf("captured config = %T/%v, want exact candidate", captured, ok)
		}

		if resolver, found := CapturedMessageResolverFromContext(requestCtx); !found || resolver == nil {
			t.Fatal("captured generation localization resolver is unavailable")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WithInternalSession() error = %v", err)
	}

	if authenticator.callCount() != 1 {
		t.Fatalf("authenticator calls = %d, want 1", authenticator.callCount())
	}
}

// TestDecisionSessionOwnsDetachedAuthnPolicyAttributes proves native fact metadata follows the same generation lease.
func TestDecisionSessionOwnsDetachedAuthnPolicyAttributes(t *testing.T) {
	const attributeID = "plugin.environment.example.score"

	generation, err := newRuntimeGeneration(8, runtimeGenerationDependencies{
		material:      mustRuntimeGenerationMaterial(t, testPolicyAPIConfig(true, true, true), nil),
		authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		admission:     &recordingAdmissionAuthority{},
		evaluator:     &recordingCheckpointEvaluator{},
		supervisor:    &recordingEffectAcceptor{},
		authnPolicyAttributes: map[string]policyregistry.AttributeDefinition{
			attributeID: {ID: attributeID},
		},
	})
	if err != nil {
		t.Fatalf("newRuntimeGeneration() error = %v", err)
	}

	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	err = service.WithSession(t.Context(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		attributes, ok := session.(AuthnPolicyAttributeSession)
		if !ok {
			t.Fatal("captured session has no native authn Policy attribute view")
		}

		first := attributes.AuthnPolicyAttributes()
		if first[attributeID].ID != attributeID {
			t.Fatalf("captured attributes = %#v, want %s", first, attributeID)
		}

		delete(first, attributeID)

		if second := attributes.AuthnPolicyAttributes(); second[attributeID].ID != attributeID {
			t.Fatalf("captured attributes after caller mutation = %#v", second)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WithSession() error = %v", err)
	}
}

// TestDisabledPolicyTransportRejectsBeforeAuthentication proves route availability is same-generation authority.
func TestDisabledPolicyTransportRejectsBeforeAuthentication(t *testing.T) {
	invocation := mustAuthorityInvocation(t, false)

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind: "basic", Credential: []byte("opaque-test-evidence"), TransportKind: "http", Protected: true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	invocation.Authentication = authentication
	authenticator := &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)}

	generation, err := newRuntimeGeneration(9, runtimeGenerationDependencies{
		material:      mustRuntimeGenerationMaterial(t, testPolicyAPIConfig(true, false, true), nil),
		authenticator: authenticator,
		admission:     &recordingAdmissionAuthority{},
		evaluator:     &recordingCheckpointEvaluator{},
		supervisor:    &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("newRuntimeGeneration() error = %v", err)
	}

	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	_, err = service.Evaluate(context.Background(), invocation)
	if !errors.Is(err, ErrDecisionRouteUnavailable) {
		t.Fatalf("Evaluate() error = %v, want ErrDecisionRouteUnavailable", err)
	}

	if authenticator.callCount() != 0 {
		t.Fatalf("authenticator calls = %d, want 0", authenticator.callCount())
	}
}

// TestEvaluatePreparedUsesOneCapturedGeneration proves trusted transport evidence is derived under one lease.
func TestEvaluatePreparedUsesOneCapturedGeneration(t *testing.T) {
	configured := testPolicyAPIConfig(true, true, false)
	evaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 11, "prepared")}

	generation, err := newRuntimeGeneration(11, runtimeGenerationDependencies{
		material:      mustRuntimeGenerationMaterial(t, configured, nil),
		authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
		admission:     &recordingAdmissionAuthority{},
		evaluator:     evaluator,
		supervisor:    &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("newRuntimeGeneration() error = %v", err)
	}

	source := &replaceableGenerationSource{generation: generation}
	service := mustDecisionService(t, source)

	response, err := service.EvaluatePrepared(context.Background(), "http", func(captured config.File) (decision.Invocation, error) {
		if captured != configured {
			t.Fatalf("prepared config = %T, want captured candidate", captured)
		}

		invocation := mustAuthorityInvocation(t, false)
		authentication, authenticationErr := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
			Kind: "basic", Credential: []byte("opaque-test-evidence"), TransportKind: "http", Protected: true,
		})
		invocation.Authentication = authentication

		return invocation, authenticationErr
	})
	if err != nil {
		t.Fatalf("EvaluatePrepared() error = %v", err)
	}

	if response.DecisionID().String() != "prepared" || source.captureCount() != 1 {
		t.Fatalf("decision/captures = %q/%d, want prepared/1", response.DecisionID().String(), source.captureCount())
	}
}

// TestEvaluatePreparedGatesTransportBeforePreparation proves disabled routes preempt parsing and credentials.
func TestEvaluatePreparedGatesTransportBeforePreparation(t *testing.T) {
	generation, err := newRuntimeGeneration(12, runtimeGenerationDependencies{
		material:      mustRuntimeGenerationMaterial(t, testPolicyAPIConfig(true, false, true), nil),
		authenticator: &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
		admission:     &recordingAdmissionAuthority{},
		evaluator:     &recordingCheckpointEvaluator{},
		supervisor:    &recordingEffectAcceptor{},
	})
	if err != nil {
		t.Fatalf("newRuntimeGeneration() error = %v", err)
	}

	prepared := false
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	_, err = service.EvaluatePrepared(context.Background(), "http", func(config.File) (decision.Invocation, error) {
		prepared = true

		return decision.Invocation{}, errors.New("malformed request")
	})
	if !errors.Is(err, ErrDecisionRouteUnavailable) {
		t.Fatalf("EvaluatePrepared() error = %v, want ErrDecisionRouteUnavailable", err)
	}

	if prepared {
		t.Fatal("preparation callback ran for a disabled route")
	}
}

// mustRuntimeGenerationMaterial constructs explicit config/API authority for direct generation tests.
func mustRuntimeGenerationMaterial(
	t *testing.T,
	configured policyruntime.GenerationConfig,
	presentations map[string]decision.AuthenticationInput,
) policyruntime.DecisionServiceMaterial {
	t.Helper()

	material, err := policyruntime.NewDecisionServiceMaterial(
		configured,
		presentations,
		localization.NewResolver(localization.NewMapCatalog(nil), "en"),
	)
	if err != nil {
		t.Fatalf("NewDecisionServiceMaterial() error = %v", err)
	}

	return material
}

// testPolicyAPIConfig constructs one explicit top-level Policy API activation.
func testPolicyAPIConfig(enabled bool, httpEnabled bool, grpcEnabled bool) *config.FileSettings {
	configured := &config.FileSettings{}
	configured.Policy.API.Enabled = enabled
	configured.Policy.API.HTTP.Enabled = httpEnabled
	configured.Policy.API.GRPC.Enabled = grpcEnabled

	return configured
}
