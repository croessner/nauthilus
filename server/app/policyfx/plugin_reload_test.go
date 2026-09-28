// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	reloadTestReloadable = "reloadable"
	reloadTestFixed      = "fixed"
	reloadTestKey        = "value"
	reloadTestOld        = "old"
	reloadTestNew        = "new"
)

var errReloadTestRejected = errors.New("reload test candidate rejected")

// reloadTestProbe records which generation was active when the plugin was validated or reconfigured.
type reloadTestProbe struct {
	store             *policyruntime.GenerationStore
	validateErr       error
	reconfigureErr    error
	validatedAt       []uint64
	reconfiguredAt    []uint64
	reconfiguredValue []any
}

// activeID returns the active generation identity or zero.
func (p *reloadTestProbe) activeID() uint64 {
	if active := p.store.Active(); active != nil {
		return active.ID()
	}

	return 0
}

type reloadTestPlugin struct {
	probe *reloadTestProbe
	name  string
}

// Metadata returns one compatible test plugin contract.
func (p *reloadTestPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: p.name, Version: "1.0.0", APIVersion: pluginapi.APIVersion}
}

// Register declares no components.
func (*reloadTestPlugin) Register(pluginapi.Registrar) error { return nil }

// ValidateReconfigure records the active generation and returns the configured verdict.
func (p *reloadTestPlugin) ValidateReconfigure(context.Context, pluginapi.ConfigView) error {
	p.probe.validatedAt = append(p.probe.validatedAt, p.probe.activeID())

	return p.probe.validateErr
}

// Reconfigure records the active generation and the applied value.
func (p *reloadTestPlugin) Reconfigure(_ context.Context, view pluginapi.ConfigView) error {
	p.probe.reconfiguredAt = append(p.probe.reconfiguredAt, p.probe.activeID())

	if p.probe.reconfigureErr != nil {
		return p.probe.reconfigureErr
	}

	value, _ := view.Get(reloadTestKey)
	p.probe.reconfiguredValue = append(p.probe.reconfiguredValue, value)

	return nil
}

// fixedTestPlugin cannot reload its config.
type fixedTestPlugin struct{}

// Metadata returns one compatible test plugin contract.
func (fixedTestPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: reloadTestFixed, Version: "1.0.0", APIVersion: pluginapi.APIVersion}
}

// Register declares no components.
func (fixedTestPlugin) Register(pluginapi.Registrar) error { return nil }

// reloadTestOpener hands out the test plugins in module declaration order.
type reloadTestOpener struct {
	plugins *[]pluginapi.Plugin
}

// Open returns a handle for the next test plugin.
func (o reloadTestOpener) Open(string) (pluginloader.PluginHandle, error) {
	next := (*o.plugins)[0]
	*o.plugins = (*o.plugins)[1:]

	return reloadTestHandle{plugin: next}, nil
}

type reloadTestHandle struct {
	plugin pluginapi.Plugin
}

// Lookup returns the exact required public factory symbol.
func (h reloadTestHandle) Lookup(symbol string) (any, error) {
	if symbol != "NauthilusPlugin" {
		return nil, errors.New("unexpected plugin symbol")
	}

	return func() (pluginapi.Plugin, error) { return h.plugin, nil }, nil
}

// pluginReloadHarness owns one production coordinator, runner, and plugin probe.
type pluginReloadHarness struct {
	coordinator *Coordinator
	store       *policyruntime.GenerationStore
	probe       *reloadTestProbe
	runner      *pluginruntime.Runner
	gate        *candidateFactoryGate
	artifacts   map[string]string
	version     uint64
}

// newPluginReloadHarness loads both test modules and commits the initial generation.
func newPluginReloadHarness(t *testing.T) *pluginReloadHarness {
	t.Helper()

	harness := &pluginReloadHarness{
		store: policyruntime.NewGenerationStore(), gate: &candidateFactoryGate{},
		artifacts: make(map[string]string, 2),
	}
	harness.probe = &reloadTestProbe{store: harness.store}

	verified := make([]pluginloader.VerifiedModule, 0, 2)

	for _, name := range []string{reloadTestReloadable, reloadTestFixed} {
		artifact := filepath.Join(t.TempDir(), name+".so")
		if err := os.WriteFile(artifact, []byte(name), 0o600); err != nil {
			t.Fatalf("write plugin artifact: %v", err)
		}

		digest, err := pluginloader.DigestArtifact(artifact)
		if err != nil {
			t.Fatalf("DigestArtifact() error = %v", err)
		}

		harness.artifacts[name] = artifact
		verified = append(verified, pluginloader.VerifiedModule{
			Module: harness.module(name, reloadTestOld), ArtifactPath: artifact, ArtifactDigest: digest,
		})
	}

	plugins := []pluginapi.Plugin{&reloadTestPlugin{probe: harness.probe, name: reloadTestReloadable}, fixedTestPlugin{}}

	state, err := pluginloader.NewLoader(
		pluginloader.WithLoaderArtifactReader(os.ReadFile),
		pluginloader.WithOpener(reloadTestOpener{plugins: &plugins}),
	).Load(verified)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	initial := harness.candidate(t, nil)
	harness.runner = pluginruntime.NewRunner(state, pluginruntime.WithPluginConfig(initial.GetPlugins()))
	reconfigurer := pluginruntime.NewReconfigurer()
	reconfigurer.Attach(harness.runner)

	harness.coordinator, err = NewCoordinator(
		harness.store, nil, state, harness.gate.tokenValidator, harness.gate.transportCapabilities,
		localization.NewMapCatalog(nil), mustStartupCatalog(t, initial, nil),
		mustReloadableRestartBaseline(t, initial, state),
		WithPluginReconfigurer(reconfigurer),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = harness.apply(t, initial); err != nil {
		t.Fatalf("Apply(initial) error = %v", err)
	}

	return harness
}

// mustReloadableRestartBaseline freezes the boot baseline with production plugin reload classification.
func mustReloadableRestartBaseline(
	t *testing.T,
	configured config.File,
	state *pluginloader.State,
) RestartBaselineValidator {
	t.Helper()

	baseline, err := NewRestartBaseline(
		configured, WithReloadablePlugins(pluginruntime.NewReloadClassifier(state.Instances())),
	)
	if err != nil {
		t.Fatalf("capture restart baseline: %v", err)
	}

	return baseline
}

// module builds one declaration of a named test module with one plugin-owned value.
func (h *pluginReloadHarness) module(name string, value string) config.PluginModule {
	return config.PluginModule{
		Name: name, Type: config.PluginModuleTypeGo, Path: h.artifacts[name],
		Config: map[string]any{reloadTestKey: value},
	}
}

// candidate builds a fresh config file whose modules can be adjusted by mutate.
func (h *pluginReloadHarness) candidate(t *testing.T, mutate func(reloadable *config.PluginModule, fixed *config.PluginModule)) *config.FileSettings {
	t.Helper()

	reloadable := h.module(reloadTestReloadable, reloadTestOld)
	fixed := h.module(reloadTestFixed, reloadTestOld)

	if mutate != nil {
		mutate(&reloadable, &fixed)
	}

	configured := productionNonAuthDecisionCandidate(t)
	configured.Plugins = &config.PluginsSection{
		VerificationPolicy: config.PluginVerificationPolicyOff,
		Modules:            []config.PluginModule{reloadable, fixed},
	}

	return configured
}

// apply submits one candidate under the next generation identity.
func (h *pluginReloadHarness) apply(t *testing.T, configured *config.FileSettings) error {
	t.Helper()

	h.version++

	return h.coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: h.version})
}

// changedReloadable sets the new value on the reloadable module only.
func changedReloadable(reloadable *config.PluginModule, _ *config.PluginModule) {
	reloadable.Config = map[string]any{reloadTestKey: reloadTestNew}
}

// assertActiveGeneration checks the published generation identity.
func (h *pluginReloadHarness) assertActiveGeneration(t *testing.T, want uint64) {
	t.Helper()

	if got := h.probe.activeID(); got != want {
		t.Fatalf("active generation = %d, want %d", got, want)
	}
}

// assertRunnerValue checks the host-owned config view of the reloadable module.
func (h *pluginReloadHarness) assertRunnerValue(t *testing.T, want string) {
	t.Helper()

	if value, _ := h.runner.ModuleConfig(reloadTestReloadable).Get(reloadTestKey); value != want {
		t.Fatalf("runner config value = %#v, want %q", value, want)
	}
}

func TestPluginReloadAppliesConfigOnlyChangeAfterGenerationCommit(t *testing.T) {
	harness := newPluginReloadHarness(t)

	if err := harness.apply(t, harness.candidate(t, changedReloadable)); err != nil {
		t.Fatalf("Apply(config-only change) error = %v", err)
	}

	harness.assertActiveGeneration(t, 2)
	harness.assertRunnerValue(t, reloadTestNew)

	if fmt.Sprint(harness.probe.validatedAt) != "[1]" || fmt.Sprint(harness.probe.reconfiguredAt) != "[2]" {
		t.Fatalf("validated at %v, reconfigured at %v; want validation under generation 1 and reconfigure after commit of 2",
			harness.probe.validatedAt, harness.probe.reconfiguredAt)
	}

	if fmt.Sprint(harness.probe.reconfiguredValue) != "["+reloadTestNew+"]" {
		t.Fatalf("reconfigured values = %v, want the candidate value", harness.probe.reconfiguredValue)
	}

	if err := harness.apply(t, harness.candidate(t, changedReloadable)); err != nil {
		t.Fatalf("Apply(unchanged) error = %v", err)
	}

	if len(harness.probe.validatedAt) != 1 || len(harness.probe.reconfiguredAt) != 1 {
		t.Fatal("an unchanged module config was validated or reconfigured again")
	}
}

func TestPluginReloadRejectionsKeepGenerationAndPluginState(t *testing.T) {
	tests := []struct {
		mutate    func(*config.PluginModule, *config.PluginModule)
		prepare   func(*pluginReloadHarness)
		want      error
		name      string
		mentions  string
		validates bool
	}{
		{
			name: "plugin validation rejects", mutate: changedReloadable, want: errReloadTestRejected, validates: true,
			prepare: func(h *pluginReloadHarness) { h.probe.validateErr = errReloadTestRejected },
		},
		{
			name: "plugin declares a restart-bound key", mutate: changedReloadable, validates: true,
			want: pluginapi.ErrRestartRequired, mentions: reloadTestReloadable,
			prepare: func(h *pluginReloadHarness) {
				h.probe.validateErr = fmt.Errorf("mail.enabled: %w", pluginapi.ErrRestartRequired)
			},
		},
		{
			name: "non-reloadable module config", want: pluginruntime.ErrRestartRequired, mentions: reloadTestFixed,
			mutate: func(_ *config.PluginModule, fixed *config.PluginModule) {
				fixed.Config = map[string]any{reloadTestKey: reloadTestNew}
			},
		},
		{
			name: "artifact path", want: pluginruntime.ErrRestartRequired, mentions: reloadTestReloadable,
			mutate: func(reloadable *config.PluginModule, fixed *config.PluginModule) {
				changedReloadable(reloadable, fixed)
				reloadable.Path = fixed.Path
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newPluginReloadHarness(t)
			if test.prepare != nil {
				test.prepare(harness)
			}

			err := harness.apply(t, harness.candidate(t, test.mutate))
			if !errors.Is(err, test.want) || !strings.Contains(err.Error(), test.mentions) {
				t.Fatalf("Apply() error = %v, want %v mentioning %q", err, test.want, test.mentions)
			}

			harness.assertActiveGeneration(t, 1)
			harness.assertRunnerValue(t, reloadTestOld)

			if (len(harness.probe.validatedAt) == 1) != test.validates || len(harness.probe.reconfiguredAt) != 0 {
				t.Fatalf("validated at %v, reconfigured at %v; want validation %v and no reconfigure",
					harness.probe.validatedAt, harness.probe.reconfiguredAt, test.validates)
			}
		})
	}
}

func TestPluginReloadIsDiscardedWhenGenerationPreparationFails(t *testing.T) {
	harness := newPluginReloadHarness(t)
	harness.gate.rejected = "transport"

	err := harness.apply(t, harness.candidate(t, changedReloadable))
	if !errors.Is(err, errCandidateTransport) {
		t.Fatalf("Apply() error = %v, want the candidate transport failure", err)
	}

	harness.assertActiveGeneration(t, 1)
	harness.assertRunnerValue(t, reloadTestOld)

	if len(harness.probe.reconfiguredAt) != 0 {
		t.Fatal("a plugin was reconfigured for a rejected generation")
	}

	harness.gate.rejected = ""

	if err = harness.apply(t, harness.candidate(t, changedReloadable)); err != nil {
		t.Fatalf("Apply(retry) error = %v", err)
	}

	harness.assertRunnerValue(t, reloadTestNew)
}

func TestPluginReloadCommitFailureIsReportedAfterPublication(t *testing.T) {
	harness := newPluginReloadHarness(t)
	harness.probe.reconfigureErr = errReloadTestRejected

	err := harness.apply(t, harness.candidate(t, changedReloadable))
	if !errors.Is(err, pluginruntime.ErrReconfigureFailed) || !errors.Is(err, errReloadTestRejected) {
		t.Fatalf("Apply() error = %v, want the plugin commit failure", err)
	}

	var committed interface{ GenerationCommitted() bool }
	if !errors.As(err, &committed) || !committed.GenerationCommitted() {
		t.Fatalf("Apply() error = %v, want it marked as raised after publication", err)
	}

	harness.assertActiveGeneration(t, 2)
	harness.assertRunnerValue(t, reloadTestOld)
}
