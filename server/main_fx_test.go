package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/croessner/nauthilus/v4/server/app/bootfx"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/app/policyfx"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"

	"go.uber.org/fx"
)

type initialGenerationCoordinatorStub struct {
	apply func(configfx.Snapshot) error
}

// Apply records one startup generation candidate.
func (c initialGenerationCoordinatorStub) Apply(_ context.Context, snapshot configfx.Snapshot) error {
	return c.apply(snapshot)
}

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

// TestInitialPolicyGenerationCapturesStartupCatalogBeforeCommit protects startup authority ordering.
func TestInitialPolicyGenerationCapturesStartupCatalogBeforeCommit(t *testing.T) {
	var generationCommitted atomic.Bool

	prepared := &config.FileSettings{}
	startup := policyfx.NewStartupCatalog()
	coordinator := initialGenerationCoordinatorStub{apply: func(snapshot configfx.Snapshot) error {
		if snapshot.File != prepared || snapshot.Version != 1 {
			t.Fatalf("initial snapshot = %#v, want prepared version 1", snapshot)
		}

		if err := startup.Capture(prepared, bootfx.LuaInitCatalogPreparation{}); err == nil {
			t.Fatal("coordinator ran before startup catalog capture")
		}

		generationCommitted.Store(true)

		return nil
	}}

	if err := prepareInitialPolicyGeneration(
		t.Context(),
		configfx.Snapshot{File: prepared, Version: 1},
		nil,
		nil,
		nil,
		localization.NewMapCatalog(nil),
		startup,
		coordinator,
	); err != nil {
		t.Fatalf("prepareInitialPolicyGeneration() error = %v", err)
	}

	if !generationCommitted.Load() {
		t.Fatal("initial generation was not committed")
	}
}

// TestInitialLuaFailurePreventsStartupCaptureAndGenerationCommit protects fail-closed boot.
func TestInitialLuaFailurePreventsStartupCaptureAndGenerationCommit(t *testing.T) {
	configured := &config.FileSettings{Lua: &config.LuaSection{Config: &config.LuaConf{
		InitScriptPaths: []string{"missing-precompiled-startup.lua"},
	}}}
	startup := policyfx.NewStartupCatalog()

	var generationCommitted atomic.Bool

	coordinator := initialGenerationCoordinatorStub{apply: func(configfx.Snapshot) error {
		generationCommitted.Store(true)

		return nil
	}}

	err := prepareInitialPolicyGeneration(
		t.Context(),
		configfx.Snapshot{File: configured, Version: 1},
		nil,
		nil,
		nil,
		localization.NewMapCatalog(nil),
		startup,
		coordinator,
	)
	if err == nil {
		t.Fatal("prepareInitialPolicyGeneration() accepted a failed startup script")
	}

	if generationCommitted.Load() {
		t.Fatal("initial generation committed after startup Lua failure")
	}

	if captureErr := startup.Capture(
		&config.FileSettings{},
		bootfx.LuaInitCatalogPreparation{},
	); captureErr != nil {
		t.Fatalf("failed startup attempt captured catalog state: %v", captureErr)
	}
}

func TestInitialLuaMutationBetweenExecutionAndCapturePreventsGenerationCommit(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "init.lua")
	replacement := `function nauthilus_run_hook(request)
	return {}
end
`

	script := fmt.Sprintf(`function nauthilus_run_hook(request)
	local output = assert(io.open(%q, "w"))
	assert(output:write(%q))
	assert(output:close())
	return {}
end
`, scriptPath, replacement)
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write mutating startup script: %v", err)
	}

	configured := &config.FileSettings{Lua: &config.LuaSection{Config: &config.LuaConf{
		InitScriptPaths: []string{scriptPath},
	}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Cleanup(func() {
		if err := vmpool.GetManager().Delete(vmpool.PoolKey("hook:default")); err != nil {
			t.Errorf("retire hook VM pool: %v", err)
		}
	})

	startup := policyfx.NewStartupCatalog()

	var generationCommitted atomic.Bool

	coordinator := initialGenerationCoordinatorStub{apply: func(configfx.Snapshot) error {
		generationCommitted.Store(true)

		return nil
	}}

	err := prepareInitialPolicyGeneration(
		t.Context(),
		configfx.Snapshot{File: configured, Version: 1},
		logger,
		nil,
		nil,
		localization.NewMapCatalog(nil),
		startup,
		coordinator,
	)
	if err == nil {
		t.Fatal("prepareInitialPolicyGeneration() accepted startup script drift")
	}

	if generationCommitted.Load() {
		t.Fatal("initial generation committed with mismatched startup overlays and source bytes")
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
