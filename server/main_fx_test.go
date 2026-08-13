package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"go.uber.org/fx"
)

type incompleteGenerationDrainTestError struct {
	cause error
}

// Error describes an incomplete generation drain test failure.
func (e incompleteGenerationDrainTestError) Error() string {
	return e.cause.Error()
}

// Unwrap exposes the caller cancellation behind the test failure.
func (e incompleteGenerationDrainTestError) Unwrap() error {
	return e.cause
}

// GenerationDrainIncomplete marks a caller wait failure without claiming completed retirement.
func (incompleteGenerationDrainTestError) GenerationDrainIncomplete() bool {
	return true
}

func TestRootContextOptionProvidesContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := fx.New(
		fx.NopLogger,
		rootContextOption(ctx, cancel),
		fx.Invoke(func(context.Context, context.CancelFunc) {}),
	)

	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("unexpected fx start error: %v", err)
	}

	if err := app.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected fx stop error: %v", err)
	}
}

func TestFxOnStopHookRuns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stopped atomic.Bool

	app := fx.New(
		fx.NopLogger,
		rootContextOption(ctx, cancel),
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.Hook{
				OnStop: func(context.Context) error {
					stopped.Store(true)

					return nil
				},
			})
		}),
	)

	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("unexpected fx start error: %v", err)
	}

	if err := app.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected fx stop error: %v", err)
	}

	if !stopped.Load() {
		t.Fatal("expected OnStop hook to be executed")
	}
}

// TestGenerationLifecycleStopsProcessOwnersOnlyAfterDrain protects shutdown ownership ordering.
func TestGenerationLifecycleStopsProcessOwnersOnlyAfterDrain(t *testing.T) {
	testCases := []struct {
		name        string
		shutdownErr error
		wantStops   int32
	}{
		{
			name:        "incomplete drain",
			shutdownErr: incompleteGenerationDrainTestError{cause: context.DeadlineExceeded},
			wantStops:   0,
		},
		{
			name:        "completed drain with resource deadline failure",
			shutdownErr: fmt.Errorf("generation resource close: %w", context.DeadlineExceeded),
			wantStops:   1,
		},
		{name: "completed drain", wantStops: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var (
				pluginStops atomic.Int32
				luaStops    atomic.Int32
			)

			err := stopGenerationOwnedRuntime(
				context.Background(),
				func(context.Context) error { return testCase.shutdownErr },
				func(context.Context) error { pluginStops.Add(1); return nil },
				func() { luaStops.Add(1) },
			)

			if testCase.shutdownErr == nil && err != nil {
				t.Fatalf("stopGenerationOwnedRuntime() error = %v", err)
			}

			if testCase.shutdownErr != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("stopGenerationOwnedRuntime() error = %v, want deadline error", err)
			}

			if pluginStops.Load() != testCase.wantStops || luaStops.Load() != testCase.wantStops {
				t.Fatalf(
					"process owner stops = plugin:%d Lua:%d, want %d/%d",
					pluginStops.Load(), luaStops.Load(), testCase.wantStops, testCase.wantStops,
				)
			}
		})
	}
}
