package service

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestCompletedEffectPlanSurvivesLateCancellation preserves the selected outcome once all owners confirm completion.
func TestCompletedEffectPlanSurvivesLateCancellation(t *testing.T) {
	for _, selected := range []decision.Effect{decision.EffectPermit, decision.EffectDeny} {
		for _, execution := range []registry.ExecutionClass{registry.ExecutionHostSync, registry.ExecutionHostPostAction} {
			t.Run(string(selected)+"/"+string(execution), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				evaluator, target, work := completedEffectRuntime(t, selected, execution, cancel)

				supervisor, err := effectsupervisor.New(effectsupervisor.Config{Capacity: 1, Workers: 1},
					effectsupervisor.ProviderBinding{Name: completedEffectProvider, Provider: effectsupervisor.NewExecutableProvider()})
				if err != nil {
					t.Fatal(err)
				}

				t.Cleanup(func() {
					if err := supervisor.Shutdown(context.Background()); err != nil {
						t.Error(err)
					}
				})

				finalization := decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit)

				outcome := evaluateRuntimeOutcomeContext(ctx, t, evaluator, target,
					cancelAfterAcceptance{Acceptor: supervisor, cancel: cancel}, finalization)
				if ctx.Err() != context.Canceled {
					t.Fatalf("context error = %v", ctx.Err())
				}

				if outcome.response.Effect() != selected {
					t.Fatalf("effect=%s status=%s, want %s", outcome.response.Effect(), outcome.response.Status().Code(), selected)
				}

				finalization.Complete()

				if err := supervisor.WaitIdle(t.Context()); err != nil {
					t.Fatal(err)
				}

				if execution == registry.ExecutionHostPostAction {
					if work.executeCount() != 1 || work.cleanupCount() != 1 {
						t.Fatalf("execution/cleanup=%d/%d", work.executeCount(), work.cleanupCount())
					}
				}
			})
		}
	}
}

type cancelAfterAcceptance struct {
	effectsupervisor.Acceptor
	cancel context.CancelFunc
}

// Accept injects cancellation only after the real supervisor has confirmed ownership.
func (a cancelAfterAcceptance) Accept(ctx context.Context, plan effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	receipt, err := a.Acceptor.Accept(ctx, plan)
	if err == nil {
		a.cancel()
	}

	return receipt, err
}

const completedEffectProvider = "mail/completed_provider"

// completedEffectRuntime builds one fully owned effect whose completion can race cancellation.
func completedEffectRuntime(t *testing.T, selected decision.Effect, execution registry.ExecutionClass, cancel context.CancelFunc) (checkpointEvaluator, decision.Target, *recordingPostActionWork) {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatal(err)
	}

	const effectID = "mail/completed"

	effect := decisionRuntimeEffect(t, target, effectID, completedEffectProvider, registry.EffectKindObligation, execution)
	provider := decisionRuntimeHostProvider(t, target, completedEffectProvider, execution, &recordingEffectAcceptor{})
	catalog, target := decisionRuntimeCatalogWithSelections(t, selected, registry.NoMatchDeny, nil,
		[]registry.ProviderDefinition{provider}, []registry.EffectDefinition{effect},
		[]registry.EffectUse{decisionRuntimeEffectUse(t, effectID)}, nil)
	work := &recordingPostActionWork{result: effectsupervisor.Succeeded()}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{completedEffectProvider: {provider: &completedThenCancelledEffect{
			cancel: cancel, recordingSyncEffectProvider: recordingSyncEffectProvider{result: effectsupervisor.Succeeded()},
		}}},
		postActions: map[string]postActionBinding{completedEffectProvider: {provider: &recordingPostActionProvider{work: work}}},
	})

	return evaluator, target, work
}
