// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const productionNonAuthDecisionFixture = `policy:
  api:
    enabled: true
    http: {enabled: true}
    grpc: {enabled: true}
    clients:
      - principal: policy-production-client
        authentication_kinds: [basic]
        authentication:
          basic:
            username: policy-user
            password: policy-password
        targets:
          - namespace: mail
            actions: [submit]
        allowed_schemas: [mail/submit/v1]
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1: {facts: []}
      policy_sets:
        default:
          rules:
            - name: production_permit
              checkpoint: final_decision
              if: {always: true}
              then: {decision: permit}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

type productionBasicThrottler struct{}

// BeforeAttempt admits one deterministic production-assembly test attempt.
func (*productionBasicThrottler) BeforeAttempt(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordFailure records no shared state in this production-assembly test.
func (*productionBasicThrottler) RecordFailure(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordSuccess records no shared state in this production-assembly test.
func (*productionBasicThrottler) RecordSuccess(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// TestProductionCoordinatorEvaluatesEnabledNonAuthTargetThroughBothTransports proves the real assembly path.
func TestProductionCoordinatorEvaluatesEnabledNonAuthTargetThroughBothTransports(t *testing.T) {
	configured := productionNonAuthDecisionCandidate(t)
	store := policyruntime.NewGenerationStore()

	coordinator := newProductionPolicyCoordinator(t, configured, store, unusedTokenFactory)

	if err := coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	service := productionDecisionService(t, store)
	for _, transport := range []string{"http", "grpc"} {
		t.Run(transport, func(t *testing.T) {
			response, evaluationErr := service.EvaluatePrepared(
				t.Context(),
				transport,
				func(captured config.File) (decision.Invocation, error) {
					if captured != configured {
						return decision.Invocation{}, fmt.Errorf("prepared callback received another config generation")
					}

					return productionNonAuthInvocation(t, transport), nil
				},
			)
			if evaluationErr != nil {
				t.Fatalf("EvaluatePrepared(%s) error = %v", transport, evaluationErr)
			}

			if response.Effect() != decision.EffectPermit || response.Policy().Rule() != "production_permit" {
				t.Fatalf(
					"EvaluatePrepared(%s) = %q/%q, want permit/production_permit",
					transport,
					response.Effect(),
					response.Policy().Rule(),
				)
			}
		})
	}
}

// newProductionPolicyCoordinator constructs the shared complete coordinator used by transport tests.
func newProductionPolicyCoordinator(
	t *testing.T,
	configured config.File,
	store *policyruntime.GenerationStore,
	tokens AccessTokenValidatorFactory,
) *Coordinator {
	t.Helper()

	coordinator, err := NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		tokens,
		func(context.Context, config.File) (callerauth.BasicThrottler, error) {
			return &productionBasicThrottler{}, nil
		},
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{HTTPProtected: true, GRPCProtected: true}, nil
		},
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// productionNonAuthDecisionCandidate decodes the exact top-level production Policy config.
func productionNonAuthDecisionCandidate(t *testing.T) *config.FileSettings {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(productionNonAuthDecisionFixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	return &config.FileSettings{Policy: document.Policy}
}

// productionBearerNonAuthDecisionCandidate replaces the external Basic profile with Bearer authority.
func productionBearerNonAuthDecisionCandidate(t *testing.T) *config.FileSettings {
	t.Helper()

	configured := productionNonAuthDecisionCandidate(t)
	configured.Policy.API.Clients[0].AuthenticationKinds = []string{policy.CallerAuthenticationKindBearer}
	configured.Policy.API.Clients[0].Authentication.Basic = nil

	return configured
}

// productionNonAuthInvocation constructs one protected exact external transport invocation.
func productionNonAuthInvocation(t *testing.T, transport string) decision.Invocation {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          "basic",
		Credential:    []byte("policy-user:policy-password"),
		TransportKind: transport,
		Peer:          "127.0.0.1:42123",
		Protected:     true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	boundary := effectsupervisor.BoundaryHTTPCommit
	if transport == "grpc" {
		boundary = effectsupervisor.BoundaryGRPCUnaryReturn
	}

	return decision.Invocation{
		Request: decision.DecisionRequestInput{
			Version: decision.ContractVersion, RequestID: "production-" + transport, Target: target,
		},
		Authentication: authentication,
		Finalization:   decision.NewEvaluationFinalization(boundary),
	}
}

var _ decisionservice.PreparedService = (*decisionservice.DecisionService)(nil)
var _ callerauth.BasicThrottler = (*productionBasicThrottler)(nil)
