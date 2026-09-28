// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	reloadModuleA = "alpha"
	reloadModuleB = "bravo"
	reloadModuleC = "charlie"
)

var errReloadRejected = errors.New("candidate rejected")

// reloadCalls records plugin lifecycle calls in invocation order across modules.
type reloadCalls struct {
	entries []string
}

// add appends one module method call.
func (c *reloadCalls) add(module string, method string) {
	c.entries = append(c.entries, module+"."+method)
}

// reloadRecorder is a reloadable plugin without a validator.
type reloadRecorder struct {
	calls          *reloadCalls
	reconfigureErr error
	name           string
}

func (p *reloadRecorder) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: p.name, Version: testRuntimePluginVersion, APIVersion: pluginapi.APIVersion}
}

func (p *reloadRecorder) Register(pluginapi.Registrar) error { return nil }

func (p *reloadRecorder) Reconfigure(context.Context, pluginapi.ConfigView) error {
	p.calls.add(p.name, methodReconfigure)

	return p.reconfigureErr
}

// validatingReloadRecorder adds ValidateReconfigure to reloadRecorder.
type validatingReloadRecorder struct {
	reloadRecorder
	validateErr error
}

func (p *validatingReloadRecorder) ValidateReconfigure(context.Context, pluginapi.ConfigView) error {
	p.calls.add(p.name, methodValidateReconfigure)

	return p.validateErr
}

// staticPlugin does not support config reloads.
type staticPlugin struct {
	name string
}

func (p *staticPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: p.name, Version: testRuntimePluginVersion, APIVersion: pluginapi.APIVersion}
}

func (p *staticPlugin) Register(pluginapi.Registrar) error { return nil }

// ObservePluginReload records reload outcomes for assertions.
func (o *recordingObserver) ObservePluginReload(record ReloadRecord) {
	o.reloads = append(o.reloads, record)
}

// reloadResults returns the recorded outcome per module name.
func (o *recordingObserver) reloadResults() map[string]ReloadResult {
	results := make(map[string]ReloadResult, len(o.reloads))
	for _, record := range o.reloads {
		results[record.ModuleName] = record.Result
	}

	return results
}

// newReloadTestRunner builds a runner over several named modules with one config value each.
func newReloadTestRunner(t *testing.T, observer *recordingObserver, plugins ...pluginapi.Plugin) *Runner {
	t.Helper()

	instances := make([]pluginloader.ModuleInstance, 0, len(plugins))
	modules := make([]config.PluginModule, 0, len(plugins))

	for _, plugin := range plugins {
		module := reloadTestModule(plugin.Metadata().Name, testRuntimeOldValue)
		modules = append(modules, module)
		instances = append(instances, pluginloader.ModuleInstance{
			Plugin: plugin, Module: module, ModuleName: module.Name, Status: pluginloader.ModuleStatusRegistered,
		})
	}

	return NewRunnerFromInstances(
		pluginregistry.NewRegistry(),
		instances,
		WithObserver(observer),
		WithPluginConfig(&config.PluginsSection{Modules: modules}),
	)
}

// reloadTestModule builds one module declaration with a single plugin-owned value.
func reloadTestModule(name string, value string) config.PluginModule {
	return config.PluginModule{
		Config: map[string]any{testRuntimeConfigKey: value},
		Name:   name,
		Type:   config.PluginModuleTypeGo,
		Path:   "/plugins/" + name + ".so",
	}
}

// reloadCandidate builds a candidate in which the named modules carry the new value.
func reloadCandidate(names []string, changed ...string) *config.FileSettings {
	modules := make([]config.PluginModule, 0, len(names))

	for _, name := range names {
		value := testRuntimeOldValue
		if slices.Contains(changed, name) {
			value = testRuntimeNewValue
		}

		modules = append(modules, reloadTestModule(name, value))
	}

	return &config.FileSettings{Plugins: &config.PluginsSection{Modules: modules}}
}

// assertModuleValue checks the host-owned config view of one module.
func assertModuleValue(t *testing.T, runner *Runner, module string, want string) {
	t.Helper()

	value, ok := runner.ModuleConfig(module).Get(testRuntimeConfigKey)
	if !ok || value != want {
		t.Fatalf("ModuleConfig(%s) value = %#v, %v; want %q", module, value, ok, want)
	}
}

// assertReloadResults compares recorded outcomes with the expected per-module results.
func assertReloadResults(t *testing.T, observer *recordingObserver, want map[string]ReloadResult) {
	t.Helper()

	got := observer.reloadResults()
	if len(got) != len(want) || len(observer.reloads) != len(want) {
		t.Fatalf("reload records = %#v, want exactly one per module %#v", observer.reloads, want)
	}

	for module, result := range want {
		if got[module] != result {
			t.Fatalf("reload result of %q = %q, want %q (all: %#v)", module, got[module], result, got)
		}
	}
}

func TestRunnerReconfigureValidationFailureChangesNothing(t *testing.T) {
	calls := &reloadCalls{}
	observer := &recordingObserver{}
	alpha := &validatingReloadRecorder{reloadRecorder: reloadRecorder{calls: calls, name: reloadModuleA}}
	bravo := &validatingReloadRecorder{
		reloadRecorder: reloadRecorder{calls: calls, name: reloadModuleB}, validateErr: errReloadRejected,
	}
	runner := newReloadTestRunner(t, observer, alpha, bravo)

	err := runner.Reconfigure(t.Context(), reloadCandidate([]string{reloadModuleA, reloadModuleB}, reloadModuleA, reloadModuleB))
	if !errors.Is(err, errReloadRejected) || errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Reconfigure() error = %v, want the validation rejection only", err)
	}

	if !strings.Contains(err.Error(), fmt.Sprintf("%q", reloadModuleB)) {
		t.Fatalf("Reconfigure() error = %v, want the rejecting module name", err)
	}

	for _, entry := range calls.entries {
		if strings.HasSuffix(entry, "."+methodReconfigure) {
			t.Fatalf("calls = %#v, want no Reconfigure after a rejected validation", calls.entries)
		}
	}

	assertModuleValue(t, runner, reloadModuleA, testRuntimeOldValue)
	assertModuleValue(t, runner, reloadModuleB, testRuntimeOldValue)
	assertReloadResults(t, observer, map[string]ReloadResult{
		reloadModuleA: ReloadResultAborted, reloadModuleB: ReloadResultRejected,
	})
}

func TestRunnerReconfigureClassifiesMixedChanges(t *testing.T) {
	calls := &reloadCalls{}
	observer := &recordingObserver{}
	runner := newReloadTestRunner(t, observer,
		&reloadRecorder{calls: calls, name: reloadModuleA},
		&staticPlugin{name: reloadModuleB},
		&reloadRecorder{calls: calls, name: reloadModuleC},
	)
	names := []string{reloadModuleA, reloadModuleB, reloadModuleC}

	err := runner.Reconfigure(t.Context(), reloadCandidate(names, reloadModuleA, reloadModuleB))
	if !errors.Is(err, ErrRestartRequired) || !strings.Contains(err.Error(), fmt.Sprintf("%q", reloadModuleB)) {
		t.Fatalf("Reconfigure() error = %v, want restart required naming %q", err, reloadModuleB)
	}

	if len(calls.entries) != 0 {
		t.Fatalf("calls = %#v, want none for a restart-bound candidate", calls.entries)
	}

	assertModuleValue(t, runner, reloadModuleA, testRuntimeOldValue)
	assertReloadResults(t, observer, map[string]ReloadResult{
		reloadModuleA: ReloadResultAborted,
		reloadModuleB: ReloadResultRestartRequired,
		reloadModuleC: ReloadResultUnchanged,
	})
}

func TestRunnerReconfigureSectionChangeReportsOnceWithoutModule(t *testing.T) {
	observer := &recordingObserver{}
	runner := newReloadTestRunner(t, observer, &reloadRecorder{calls: &reloadCalls{}, name: reloadModuleA})
	candidate := reloadCandidate([]string{reloadModuleA}, reloadModuleA)
	candidate.Plugins.VerificationPolicy = "strict"

	if err := runner.Reconfigure(t.Context(), candidate); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Reconfigure() error = %v, want restart required", err)
	}

	assertReloadResults(t, observer, map[string]ReloadResult{"": ReloadResultRestartRequired})
}

func TestRunnerReconfigurePluginDeclaredRestartBoundKey(t *testing.T) {
	calls := &reloadCalls{}
	observer := &recordingObserver{}
	plugin := &validatingReloadRecorder{
		reloadRecorder: reloadRecorder{calls: calls, name: reloadModuleA},
		validateErr:    fmt.Errorf("mail.enabled: %w", pluginapi.ErrRestartRequired),
	}
	runner := newReloadTestRunner(t, observer, plugin)

	err := runner.Reconfigure(t.Context(), reloadCandidate([]string{reloadModuleA}, reloadModuleA))
	if !errors.Is(err, ErrRestartRequired) || !errors.Is(err, pluginapi.ErrRestartRequired) {
		t.Fatalf("Reconfigure() error = %v, want host and plugin restart sentinels", err)
	}

	assertModuleValue(t, runner, reloadModuleA, testRuntimeOldValue)
	assertReloadResults(t, observer, map[string]ReloadResult{reloadModuleA: ReloadResultRestartRequired})
}

func TestRunnerReconfigureCommitsChangedModulesInDeclarationOrder(t *testing.T) {
	calls := &reloadCalls{}
	observer := &recordingObserver{}
	runner := newReloadTestRunner(t, observer,
		&validatingReloadRecorder{reloadRecorder: reloadRecorder{calls: calls, name: reloadModuleA}},
		&validatingReloadRecorder{reloadRecorder: reloadRecorder{calls: calls, name: reloadModuleB}},
		&validatingReloadRecorder{reloadRecorder: reloadRecorder{calls: calls, name: reloadModuleC}},
	)
	names := []string{reloadModuleA, reloadModuleB, reloadModuleC}

	if err := runner.Reconfigure(t.Context(), reloadCandidate(names, reloadModuleC, reloadModuleA)); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	want := []string{
		reloadModuleA + "." + methodValidateReconfigure,
		reloadModuleC + "." + methodValidateReconfigure,
		reloadModuleA + "." + methodReconfigure,
		reloadModuleC + "." + methodReconfigure,
	}
	if !sameStrings(calls.entries, want) {
		t.Fatalf("calls = %#v, want validation of every change before commit in declaration order %#v", calls.entries, want)
	}

	assertModuleValue(t, runner, reloadModuleA, testRuntimeNewValue)
	assertModuleValue(t, runner, reloadModuleB, testRuntimeOldValue)
	assertModuleValue(t, runner, reloadModuleC, testRuntimeNewValue)
	assertReloadResults(t, observer, map[string]ReloadResult{
		reloadModuleA: ReloadResultReloaded, reloadModuleB: ReloadResultUnchanged, reloadModuleC: ReloadResultReloaded,
	})
}

func TestRunnerReconfigureCommitFailureKeepsModuleAndRetries(t *testing.T) {
	calls := &reloadCalls{}
	observer := &recordingObserver{}
	alpha := &reloadRecorder{calls: calls, name: reloadModuleA, reconfigureErr: errReloadRejected}
	runner := newReloadTestRunner(t, observer, alpha, &reloadRecorder{calls: calls, name: reloadModuleB})
	candidate := reloadCandidate([]string{reloadModuleA, reloadModuleB}, reloadModuleA, reloadModuleB)

	err := runner.Reconfigure(t.Context(), candidate)
	if !errors.Is(err, ErrReconfigureFailed) || !errors.Is(err, errReloadRejected) {
		t.Fatalf("Reconfigure() error = %v, want commit failure", err)
	}

	assertModuleValue(t, runner, reloadModuleA, testRuntimeOldValue)
	assertModuleValue(t, runner, reloadModuleB, testRuntimeNewValue)
	assertReloadResults(t, observer, map[string]ReloadResult{
		reloadModuleA: ReloadResultFailed, reloadModuleB: ReloadResultReloaded,
	})

	alpha.reconfigureErr = nil
	calls.entries = nil
	observer.reloads = nil

	if err = runner.Reconfigure(t.Context(), candidate); err != nil {
		t.Fatalf("Reconfigure(retry) error = %v", err)
	}

	if !sameStrings(calls.entries, []string{reloadModuleA + "." + methodReconfigure}) {
		t.Fatalf("retry calls = %#v, want only the previously failed module", calls.entries)
	}

	assertModuleValue(t, runner, reloadModuleA, testRuntimeNewValue)
}

func TestRunnerReconfigurePlanDiscardAndStaleness(t *testing.T) {
	calls := &reloadCalls{}
	observer := &recordingObserver{}
	runner := newReloadTestRunner(t, observer, &reloadRecorder{calls: calls, name: reloadModuleA})
	candidate := reloadCandidate([]string{reloadModuleA}, reloadModuleA)

	discarded, err := runner.PrepareReconfigure(t.Context(), candidate)
	if err != nil {
		t.Fatalf("PrepareReconfigure(discarded) error = %v", err)
	}

	discarded.Discard()

	if err = discarded.Commit(t.Context()); err != nil || len(calls.entries) != 0 {
		t.Fatalf("Commit(after Discard) = %v, calls %#v; want a finished no-op plan", err, calls.entries)
	}

	assertReloadResults(t, observer, map[string]ReloadResult{reloadModuleA: ReloadResultAborted})

	first, err := runner.PrepareReconfigure(t.Context(), candidate)
	if err != nil {
		t.Fatalf("PrepareReconfigure(first) error = %v", err)
	}

	second, err := runner.PrepareReconfigure(t.Context(), candidate)
	if err != nil {
		t.Fatalf("PrepareReconfigure(second) error = %v", err)
	}

	if err = first.Commit(t.Context()); err != nil {
		t.Fatalf("Commit(first) error = %v", err)
	}

	if err = second.Commit(t.Context()); !errors.Is(err, ErrReconfigurePlanStale) {
		t.Fatalf("Commit(second) error = %v, want stale plan", err)
	}

	if len(calls.entries) != 1 {
		t.Fatalf("calls = %#v, want exactly one Reconfigure", calls.entries)
	}
}

func TestRunnerReconfigureRejectsStoppedRunner(t *testing.T) {
	calls := &reloadCalls{}
	runner := newReloadTestRunner(t, &recordingObserver{}, &reloadRecorder{calls: calls, name: reloadModuleA})

	if err := runner.Stop(t.Context()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	err := runner.Reconfigure(t.Context(), reloadCandidate([]string{reloadModuleA}, reloadModuleA))
	if !errors.Is(err, ErrNotReady) || len(calls.entries) != 0 {
		t.Fatalf("Reconfigure(stopped) = %v, calls %#v; want ErrNotReady without calls", err, calls.entries)
	}
}

func TestReloadClassifierRestartBoundDropsOnlyReloadableConfig(t *testing.T) {
	classifier := NewReloadClassifier([]pluginloader.ModuleInstance{
		{Plugin: &reloadRecorder{name: reloadModuleA}, ModuleName: reloadModuleA},
		{Plugin: &staticPlugin{name: reloadModuleB}, ModuleName: reloadModuleB},
		{Plugin: &reloadRecorder{name: reloadModuleC}, ModuleName: reloadModuleC, Status: pluginloader.ModuleStatusFailed},
	})
	section := reloadCandidate([]string{reloadModuleA, reloadModuleB, reloadModuleC}).Plugins

	projected := classifier.RestartBound(section)
	if projected.Modules[0].Config != nil {
		t.Fatal("RestartBound() kept the config of a reloadable module")
	}

	if projected.Modules[1].Config == nil || projected.Modules[2].Config == nil {
		t.Fatal("RestartBound() dropped the config of a module that cannot reload")
	}

	if section.Modules[0].Config == nil {
		t.Fatal("RestartBound() modified its input")
	}

	if classifier.RestartBound(nil) != nil {
		t.Fatal("RestartBound(nil) must stay nil")
	}
}

func TestOperationalObserverRecordsReloadOutcomesWithoutConfigValues(t *testing.T) {
	const secretValue = "password=hunter2"

	var buf bytes.Buffer

	metrics := stats.GetMetrics()
	counter := metrics.GetPluginReconfigureTotal().WithLabelValues(reloadModuleA, string(ReloadResultReloaded))
	before := testutil.ToFloat64(counter)
	observer := NewOperationalObserver(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	instances := []pluginloader.ModuleInstance{{
		Plugin: &reloadRecorder{calls: &reloadCalls{}, name: reloadModuleA}, Module: reloadTestModule(reloadModuleA, testRuntimeOldValue),
		ModuleName: reloadModuleA, Status: pluginloader.ModuleStatusRegistered,
	}}
	runner := NewRunnerFromInstances(pluginregistry.NewRegistry(), instances, WithObserver(observer),
		WithPluginConfig(&config.PluginsSection{Modules: []config.PluginModule{instances[0].Module}}))

	candidate := reloadCandidate([]string{reloadModuleA})
	candidate.Plugins.Modules[0].Config = map[string]any{testRuntimeConfigKey: secretValue}

	if err := runner.Reconfigure(t.Context(), candidate); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Fatalf("plugin_reconfigure_total{result=reloaded} delta = %v, want 1", got)
	}

	logs := buf.String()
	if !strings.Contains(logs, `"plugin_reload_result":"reloaded"`) || !strings.Contains(logs, `"plugin_module":"`+reloadModuleA+`"`) {
		t.Fatalf("reload log lacks bounded fields: %s", logs)
	}

	if strings.Contains(logs, secretValue) {
		t.Fatalf("reload log leaked a config value: %s", logs)
	}
}

func TestReconfigurerRefusesReloadsAfterDetach(t *testing.T) {
	calls := &reloadCalls{}
	runner := newReloadTestRunner(t, &recordingObserver{}, &reloadRecorder{calls: calls, name: reloadModuleA})
	candidate := reloadCandidate([]string{reloadModuleA}, reloadModuleA)
	reconfigurer := NewReconfigurer()

	if plan, err := reconfigurer.PrepareReconfigure(t.Context(), candidate); plan != nil || err != nil {
		t.Fatalf("PrepareReconfigure(before attach) = %v, %v; want nothing to reconfigure", plan, err)
	}

	reconfigurer.Attach(runner)

	plan, err := reconfigurer.PrepareReconfigure(t.Context(), candidate)
	if err != nil || plan == nil {
		t.Fatalf("PrepareReconfigure(attached) = %v, %v; want a plan", plan, err)
	}

	plan.Discard()
	reconfigurer.Detach(runner)

	if _, err = reconfigurer.PrepareReconfigure(t.Context(), candidate); !errors.Is(err, ErrNotReady) {
		t.Fatalf("PrepareReconfigure(after detach) error = %v, want ErrNotReady", err)
	}

	if len(calls.entries) != 0 {
		t.Fatalf("calls = %#v, want none", calls.entries)
	}
}

// blockingReloadPlugin blocks Reconfigure until released and records Stop.
type blockingReloadPlugin struct {
	entered  chan struct{}
	release  chan struct{}
	finished atomic.Bool
	stopped  atomic.Bool
	overlap  atomic.Bool
}

func (p *blockingReloadPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: reloadModuleA, Version: testRuntimePluginVersion, APIVersion: pluginapi.APIVersion}
}

func (p *blockingReloadPlugin) Register(pluginapi.Registrar) error { return nil }

func (p *blockingReloadPlugin) Start(context.Context, pluginapi.Host) error { return nil }

func (p *blockingReloadPlugin) Stop(context.Context) error {
	if !p.finished.Load() {
		p.overlap.Store(true)
	}

	p.stopped.Store(true)

	return nil
}

func (p *blockingReloadPlugin) Reconfigure(context.Context, pluginapi.ConfigView) error {
	close(p.entered)
	<-p.release
	p.finished.Store(true)

	return nil
}

func TestRunnerStopWaitsForRunningReconfigure(t *testing.T) {
	plugin := &blockingReloadPlugin{entered: make(chan struct{}), release: make(chan struct{})}
	runner := newReloadTestRunner(t, &recordingObserver{}, plugin)

	if err := runner.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	committed := make(chan error, 1)

	go func() {
		committed <- runner.Reconfigure(context.Background(), reloadCandidate([]string{reloadModuleA}, reloadModuleA))
	}()

	<-plugin.entered

	stopped := make(chan error, 1)

	go func() {
		stopped <- runner.Stop(context.Background())
	}()

	select {
	case err := <-stopped:
		t.Fatalf("Stop() returned %v while Reconfigure was running", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(plugin.release)

	if err := <-committed; err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	if err := <-stopped; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if plugin.overlap.Load() || !plugin.stopped.Load() {
		t.Fatal("plugin Stop overlapped a running Reconfigure")
	}
}
