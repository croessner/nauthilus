package main

import (
	"context"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const pluginName = "reputation"

var observeTarget = pluginapi.DecisionTargetSelector{Namespace: pluginName, Action: "observe"}

// Plugin owns immutable admission semantics and process-bound opaque services.
type Plugin struct {
	state      *stateOwner
	config     *configuration
	tagger     pluginapi.OpaqueIdentifierTagger
	registered map[executionKey]struct{}
	mu         sync.RWMutex
}

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)

// NewPlugin creates an inactive module without state writers or implicit source defaults.
func NewPlugin() *Plugin { return &Plugin{registered: make(map[executionKey]struct{})} }

// NauthilusPlugin exposes the native loader factory.
func NauthilusPlugin() (pluginapi.Plugin, error) { return NewPlugin(), nil }

// Metadata declares the exact native artifact contract and fact-only capability.
func (*Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Build: pluginapi.BuildInfo{ArtifactIdentity: pluginapi.NativeArtifactIdentity()}, Name: pluginName, Version: "0.1.0", APIVersion: pluginapi.APIVersion,
		Description: "Configuration-bound independent evidence admission and reputation.", Features: []pluginapi.Feature{"decision_fact_provider"}}
}

// Register validates the complete catalog before exposing one observation fact provider.
func (p *Plugin) Register(registrar pluginapi.Registrar) error {
	if registrar == nil {
		return errConfiguration
	}

	cfg, err := decodeConfig(registrar.Config())
	if err != nil {
		return err
	}

	decisionRegistrar, ok := registrar.(pluginapi.DecisionRegistrar)
	if !ok {
		return errConfiguration
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config != nil {
		return errConfiguration
	}

	if err := decisionRegistrar.RegisterDecisionFactProvider(observationProvider{plugin: p}); err != nil {
		return err
	}

	if err := p.registerAssessments(decisionRegistrar, cfg); err != nil {
		return err
	}

	p.config = cfg

	return nil
}

// Start admits the module only after source cross-checks and durable model/allocation activation.
func (p *Plugin) Start(ctx context.Context, host pluginapi.Host) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config == nil || host == nil {
		return errConfiguration
	}

	if err := p.config.validateStartup(host.Config(), p.registered); err != nil {
		return err
	}

	tagger, err := host.OpaqueIdentifierTagger()
	if err != nil {
		return err
	}

	if _, err := tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: p.config.raw.SubjectScope, Kind: taggerProbe, Value: "startup"}); err != nil {
		return err
	}

	state, err := newStateOwner(p.config, tagger, host.Redis())
	if err != nil {
		return err
	}

	if err := state.start(ctx); err != nil {
		return err
	}

	p.state = state
	p.tagger = tagger

	return nil
}

// Stop removes local readiness without quiescing independent writers or altering durable state.
func (p *Plugin) Stop(context.Context) error {
	p.mu.Lock()
	if p.state != nil {
		p.state.ready.Store(false)
	}
	p.tagger = nil
	p.mu.Unlock()

	return nil
}

// snapshot returns the immutable process configuration and service facade under one readiness lock.
func (p *Plugin) snapshot() (*configuration, pluginapi.OpaqueIdentifierTagger) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config, p.tagger
}
