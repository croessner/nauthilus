package main

import (
	"context"
	"sync/atomic"
	"testing"

	"go.uber.org/fx"
)

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
