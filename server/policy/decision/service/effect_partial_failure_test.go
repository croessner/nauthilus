package service

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

type completedThenCancelledEffect struct {
	recordingSyncEffectProvider
	cancel context.CancelFunc
}

// IdempotencyKey cancels only after the runtime receives the known successful outcome.
func (p *completedThenCancelledEffect) IdempotencyKey(string) string {
	p.cancel()
	return ""
}

// TestUnsafeCompletedEffectBeforeKnownFailureIsNotRetryable protects partial failures and cancellation while retaining safe retries.
func TestUnsafeCompletedEffectBeforeKnownFailureIsNotRetryable(t *testing.T) {
	for _, test := range []struct {
		name               string
		replayKey          string
		firstFails         bool
		cancelAfterSuccess bool
		wantRetry          bool
	}{
		{name: "unsafe success then failure"},
		{name: "idempotent success then failure", replayKey: "resource.event_id", wantRetry: true},
		{name: "failure before success", firstFails: true, wantRetry: true},
		{name: "cancel after known unsafe success", cancelAfterSuccess: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			target, _ := decision.NewTarget("mail", "submit")
			first := decisionRuntimeEffect(t, target, "mail/first", "mail/first_provider", registry.EffectKindObligation, registry.ExecutionHostSync)
			second := decisionRuntimeEffect(t, target, "mail/second", "mail/second_provider", registry.EffectKindObligation, registry.ExecutionHostSync)
			providers := []registry.ProviderDefinition{
				decisionRuntimeHostProvider(t, target, "mail/first_provider", registry.ExecutionHostSync, nil),
				decisionRuntimeHostProvider(t, target, "mail/second_provider", registry.ExecutionHostSync, nil),
			}
			catalog, target := decisionRuntimeCatalogWithSelections(t, decision.EffectPermit, registry.NoMatchDeny, nil, providers,
				[]registry.EffectDefinition{first, second}, []registry.EffectUse{decisionRuntimeEffectUse(t, "mail/first"), decisionRuntimeEffectUse(t, "mail/second")}, nil)
			firstProvider := &recordingSyncEffectProvider{result: effectsupervisor.Succeeded(), replayKey: test.replayKey}

			var owner syncEffectProvider = firstProvider
			if test.firstFails {
				firstProvider.result = effectsupervisor.Failed("known_failure")
			}

			if test.cancelAfterSuccess {
				owner = &completedThenCancelledEffect{cancel: cancel, recordingSyncEffectProvider: recordingSyncEffectProvider{result: effectsupervisor.Succeeded()}}
			}

			failed := &recordingSyncEffectProvider{result: effectsupervisor.Failed("known_failure")}
			evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
				syncEffects: map[string]syncEffectBinding{"mail/first_provider": {provider: owner}, "mail/second_provider": {provider: failed}}})
			finalization := decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit)

			response := evaluateRuntimeOutcomeContext(ctx, t, evaluator, target, &recordingEffectAcceptor{}, finalization).response
			if response.Status().Retryable() != test.wantRetry {
				t.Fatalf("code=%s retryable=%t want=%t", response.Status().Code(), response.Status().Retryable(), test.wantRetry)
			}

			if !test.wantRetry && response.Status().Code() != decision.StatusCodeEffectReplayUnsafe {
				t.Fatalf("unsafe completed prefix status=%s", response.Status().Code())
			}
		})
	}
}
