// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/redis/go-redis/v9"
	"go.uber.org/fx"
)

// newWarnJSONLogger returns a logger that keeps only WARN and ERROR records, as in production.
func newWarnJSONLogger() (*slog.Logger, *bytes.Buffer) {
	buffer := &bytes.Buffer{}

	return slog.New(slog.NewJSONHandler(buffer, &slog.HandlerOptions{Level: slog.LevelWarn})), buffer
}

func TestScriptUploadTaskStopCancelsAndWaitsForTheUpload(t *testing.T) {
	logger, _ := newWarnJSONLogger()
	started := make(chan struct{})

	var observed error

	task := startScriptUpload(t.Context(), logger, nil, func(ctx context.Context, _ *slog.Logger, _ rediscli.Client) error {
		close(started)
		<-ctx.Done()
		observed = ctx.Err()

		return ctx.Err()
	})

	<-started

	if !task.stop(t.Context()) {
		t.Fatal("stop() = false, want the upload to have returned")
	}

	if !errors.Is(observed, context.Canceled) {
		t.Fatalf("upload observed %v, want context.Canceled", observed)
	}
}

func TestScriptUploadTaskStopHonorsTheWaitBudget(t *testing.T) {
	logger, _ := newWarnJSONLogger()
	release := make(chan struct{})

	task := startScriptUpload(t.Context(), logger, nil, func(context.Context, *slog.Logger, rediscli.Client) error {
		<-release

		return nil
	})

	waitCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	if task.stop(waitCtx) {
		t.Fatal("stop() = true, want false while the upload ignores cancellation")
	}

	close(release)

	if !task.stop(t.Context()) {
		t.Fatal("stop() = false after release, want true")
	}
}

func TestScriptUploadSlotReplaceStopsThePreviousUpload(t *testing.T) {
	logger, _ := newWarnJSONLogger()
	slot := &scriptUploadSlot{}
	firstStopped := make(chan struct{})

	first := startScriptUpload(t.Context(), logger, nil, func(ctx context.Context, _ *slog.Logger, _ rediscli.Client) error {
		<-ctx.Done()
		close(firstStopped)

		return ctx.Err()
	})
	slot.replace(t.Context(), logger, first)

	second := startScriptUpload(t.Context(), logger, nil, func(ctx context.Context, _ *slog.Logger, _ rediscli.Client) error {
		<-ctx.Done()

		return ctx.Err()
	})
	slot.replace(t.Context(), logger, second)

	select {
	case <-firstStopped:
	default:
		t.Fatal("replace() returned before the previous upload stopped")
	}

	slot.stop(t.Context(), logger)

	if slot.current.Load() != nil {
		t.Fatal("slot still holds an upload after stop()")
	}
}

func TestScriptUploadLogsOnlyRealFailuresAsWarnings(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantWarn bool
	}{
		{name: "closed client", err: fmt.Errorf("upload: %w", redis.ErrClosed)},
		{name: "canceled", err: context.Canceled},
		{name: "outage", err: errors.New("dial tcp: connection refused"), wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buffer := newWarnJSONLogger()

			task := startScriptUpload(t.Context(), logger, nil, func(context.Context, *slog.Logger, rediscli.Client) error {
				return tt.err
			})
			task.stop(t.Context())

			if gotWarn := strings.Contains(buffer.String(), `"level":"WARN"`); gotWarn != tt.wantWarn {
				t.Fatalf("WARN logged = %v, want %v; output:\n%s", gotWarn, tt.wantWarn, buffer.String())
			}
		})
	}
}

func TestStartupScriptUploadNeverRunsThroughAClosedClient(t *testing.T) {
	server := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: server.Addr()})
	client := rediscli.NewTestClient(db)
	logger, _ := newWarnJSONLogger()

	var (
		mu     sync.Mutex
		closed bool
		misuse bool
	)

	started := make(chan struct{})

	// The upload keeps issuing commands until it is cancelled, like the real upload
	// over a slow TLS cluster. The owner must stop it before closing the client.
	task := startScriptUpload(t.Context(), logger, client, func(ctx context.Context, _ *slog.Logger, c rediscli.Client) error {
		close(started)

		for ctx.Err() == nil {
			mu.Lock()
			if closed {
				misuse = true
			}
			mu.Unlock()

			_ = c.GetWriteHandle().Ping(ctx).Err()
		}

		return ctx.Err()
	})

	<-started

	slot := &scriptUploadSlot{}
	slot.replace(t.Context(), logger, task)
	slot.stop(t.Context(), logger)

	mu.Lock()
	closed = true
	mu.Unlock()

	if err := db.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if misuse {
		t.Fatal("startup upload used the Redis client after it was closed")
	}
}

func TestReportFxStartFailureIsVisibleAtWarnLevel(t *testing.T) {
	logger, buffer := newWarnJSONLogger()

	reportFxStartFailure(logger, errors.New("start HTTP entry points: privilege drop failed"))

	output := buffer.String()
	if !strings.Contains(output, `"level":"ERROR"`) || !strings.Contains(output, "privilege drop failed") {
		t.Fatalf("start failure is not visible at level warn:\n%s", output)
	}
}

// runtimeStartupFailureChildEnv marks the child process of the runtime startup failure test.
const runtimeStartupFailureChildEnv = "NAUTHILUS_TEST_RUNTIME_STARTUP_FAILURE_CHILD"

// TestRuntimeStartupFailureCancelsRuntimeBeforeRedisCloses reproduces the production
// sequence: HTTP is already serving, a later startup step fails, and fx rolls back
// the earlier hooks, which closes the Redis client. The failed hook's OnStop is not
// called by fx, so the runtime must cancel itself and stop the script upload.
//
// The config source can be bound once per process, so the scenario runs in a child
// process of the test binary.
func TestRuntimeStartupFailureCancelsRuntimeBeforeRedisCloses(t *testing.T) {
	if os.Getenv(runtimeStartupFailureChildEnv) == "1" {
		runRuntimeStartupFailureScenario(t)

		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeStartupFailureCancelsRuntimeBeforeRedisCloses$", "-test.count=1")

	cmd.Env = append(os.Environ(), runtimeStartupFailureChildEnv+"=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runtime startup failure scenario failed: %v\n%s", err, output)
	}

	if !strings.Contains(string(output), "PASS") {
		t.Fatalf("runtime startup failure scenario did not pass:\n%s", output)
	}
}

// runRuntimeStartupFailureScenario starts the production module graph with a startup step that fails after HTTP.
func runRuntimeStartupFailureScenario(t *testing.T) {
	t.Helper()

	miniRedis, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer miniRedis.Close()

	listenAddress := reserveLoopbackAddress(t)
	configPath := writeHookOnlyConfig(t, miniRedis.Addr(), listenAddress)

	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	// A missing run_as_user makes the privilege drop fail after HTTP started.
	body = []byte(strings.Replace(string(body), "runtime:\n", "runtime:\n  process:\n    run_as_user: \"nauthilus-missing-user-for-test\"\n", 1))
	if err = os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prepared := prepareHookOnlyConfiguration(t, configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var store *contextStore

	probe := &lifecycleTestPlugin{name: "lifecycle_probe"}
	probeState := loadLifecycleTestState(t, probe)

	app := newHookOnlyTestApp(ctx, cancel, prepared, fx.Populate(&store),
		fx.Decorate(func(*pluginloader.State) *pluginloader.State { return probeState }))

	startCtx, startCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer startCancel()

	err = app.Start(startCtx)
	if err == nil {
		_ = app.Stop(context.Background())

		t.Fatal("app start succeeded, want the privilege drop to fail")
	}

	if !strings.Contains(err.Error(), "start HTTP entry points") || !strings.Contains(err.Error(), "privilege drop failed") {
		t.Fatalf("start error = %v, want the failing step and its cause", err)
	}

	requireRuntimeStartupRolledBack(ctx, t, store, probe)
}

// requireRuntimeStartupRolledBack checks that a failed runtime startup cancelled the runtime, released the
// script upload, and stopped the plugin runner that had started the probe module.
func requireRuntimeStartupRolledBack(ctx context.Context, t *testing.T, store *contextStore, probe *lifecycleTestPlugin) {
	t.Helper()

	if ctx.Err() == nil {
		t.Fatal("root context still live after the runtime startup failed")
	}

	if store == nil {
		t.Fatal("context store was not populated")
	}

	if store.scriptUploads.current.Load() != nil {
		t.Fatal("script upload still owned by the store after the runtime startup failed")
	}

	if !probe.started.Load() {
		t.Fatal("plugin runner did not start the probe module before the later step failed")
	}

	if !probe.stopped.Load() || store.pluginRunner != nil {
		t.Fatal("plugin runner still running after a later startup step failed")
	}
}

// lifecycleTestOpener serves one lifecycleTestPlugin as a native plugin artifact.
type lifecycleTestOpener struct {
	plugin *lifecycleTestPlugin
}

// Open returns the handle of the synthetic plugin.
func (o lifecycleTestOpener) Open(string) (pluginloader.PluginHandle, error) {
	return o, nil
}

// Lookup returns the plugin factory for every symbol.
func (o lifecycleTestOpener) Lookup(string) (any, error) {
	return func() (pluginapi.Plugin, error) { return o.plugin, nil }, nil
}

// loadLifecycleTestState loads plugin through the production loader with a synthetic artifact.
func loadLifecycleTestState(t *testing.T, plugin *lifecycleTestPlugin) *pluginloader.State {
	t.Helper()

	artifact := filepath.Join(t.TempDir(), plugin.name+".so")
	if err := os.WriteFile(artifact, []byte("lifecycle-test-artifact"), 0o600); err != nil {
		t.Fatalf("write plugin artifact: %v", err)
	}

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("digest plugin artifact: %v", err)
	}

	loader := pluginloader.NewLoader(pluginloader.WithLoaderArtifactReader(os.ReadFile), pluginloader.WithOpener(lifecycleTestOpener{plugin: plugin}))

	state, err := loader.Load([]pluginloader.VerifiedModule{{
		Module:         config.PluginModule{Name: plugin.name, Type: config.PluginModuleTypeGo, Path: artifact},
		ArtifactPath:   artifact,
		ArtifactDigest: digest,
	}})
	if err != nil {
		t.Fatalf("load plugin state: %v", err)
	}

	return state
}

// lifecycleTestPlugin is a native runtime plugin whose Start result is fixed.
type lifecycleTestPlugin struct {
	name     string
	startErr error
	started  atomic.Bool
	stopped  atomic.Bool
}

// Metadata describes the synthetic lifecycle plugin.
func (p *lifecycleTestPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: p.name, Version: "test", APIVersion: pluginapi.APIVersion}
}

// Register registers no components.
func (p *lifecycleTestPlugin) Register(pluginapi.Registrar) error {
	return nil
}

// Start records the start and returns the configured result.
func (p *lifecycleTestPlugin) Start(context.Context, pluginapi.Host) error {
	p.started.Store(true)

	return p.startErr
}

// Stop records that the plugin was stopped.
func (p *lifecycleTestPlugin) Stop(context.Context) error {
	p.stopped.Store(true)

	return nil
}

// TestFailedPluginStartStopsModulesStartedBefore mirrors the production failure: a
// required module (reputation) fails Start after other modules started.
func TestFailedPluginStartStopsModulesStartedBefore(t *testing.T) {
	first := &lifecycleTestPlugin{name: "first"}
	failing := &lifecycleTestPlugin{name: "reputation", startErr: errors.New("state unavailable")}

	var instances []pluginloader.ModuleInstance

	for _, plugin := range []*lifecycleTestPlugin{first, failing} {
		module := config.PluginModule{Name: plugin.name, Type: config.PluginModuleTypeGo, Path: "/plugins/" + plugin.name + ".so"}
		instances = append(instances, pluginloader.ModuleInstance{
			Plugin:       plugin,
			Module:       module,
			ModuleName:   module.Name,
			Status:       pluginloader.ModuleStatusRegistered,
			ArtifactPath: module.Path,
		})
	}

	runner := pluginruntime.NewRunnerFromInstances(pluginregistry.NewRegistry(), instances)

	err := startPluginRunnerOrStop(t.Context(), runner)
	if err == nil || !strings.Contains(err.Error(), "state unavailable") {
		t.Fatalf("startPluginRunnerOrStop() error = %v, want the failing module's error", err)
	}

	if !first.stopped.Load() {
		t.Fatal("module started before the failing module was not stopped")
	}
}
