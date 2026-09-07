package main

import (
	"context"
	"sync"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const pluginName = "reputation"

var observeTarget = pluginapi.DecisionTargetSelector{Namespace: pluginName, Action: "observe"}

// Plugin owns immutable admission semantics and process-bound opaque services.
type Plugin struct {
	learningCounter *telemetry.Counter
	telemetry       *reputationTelemetry
	state           *stateOwner
	config          *configuration
	tagger          pluginapi.OpaqueIdentifierTagger
	registered      map[executionKey]struct{}
	mu              sync.RWMutex
}

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)

// NewPlugin creates an inactive module without state writers or implicit source defaults.
func NewPlugin() *Plugin { return &Plugin{registered: make(map[executionKey]struct{})} }

// NauthilusPlugin exposes the native loader factory.
func NauthilusPlugin() (pluginapi.Plugin, error) { return NewPlugin(), nil }

// Metadata declares the coherent native artifact and explicitly Policy-selected fact/effect capabilities.
func (*Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Build: pluginapi.BuildInfo{ArtifactIdentity: pluginapi.NativeArtifactIdentity()}, Name: pluginName, Version: "0.1.0", APIVersion: pluginapi.APIVersion,
		Description: "Configuration-bound independent evidence admission and reputation.", Features: []pluginapi.Feature{"decision_fact_provider", "decision_effect_provider", extensionPostAction}}
}

// Register validates the complete catalog before exposing observation, assessment and selected storage capabilities.
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

	if err := decisionRegistrar.RegisterDecisionFactProvider(observationProvider{plugin: p, config: cfg}); err != nil {
		return err
	}

	if err := decisionRegistrar.RegisterDecisionEffectProvider(observationStorageProvider{plugin: p}); err != nil {
		return err
	}

	if err := p.registerAssessments(decisionRegistrar, cfg); err != nil {
		return err
	}

	if err := p.registerAuthentication(registrar, cfg); err != nil {
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

	if err := p.initializeLearningMetrics(host); err != nil {
		return err
	}

	metrics, err := newReputationTelemetry(p.config, host.Metrics(pluginName))
	if err != nil {
		return err
	}

	p.telemetry = metrics

	state, err := newStateOwner(p.config, tagger, host.Redis())
	if err != nil {
		return err
	}

	state.telemetry = metrics

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
