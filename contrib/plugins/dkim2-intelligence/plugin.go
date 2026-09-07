package main

import (
	"context"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"sync"
)

// Plugin owns immutable operator configuration and fact-only composition registration.
type Plugin struct {
	config *configuration
	mu     sync.RWMutex
}

// NauthilusPlugin exposes the native artifact factory.
func NauthilusPlugin() (pluginapi.Plugin, error) { return NewPlugin(), nil }

// NewPlugin creates an unconfigured composition owner without storage or network resources.
func NewPlugin() *Plugin { return &Plugin{} }

// Metadata declares the native contract without credential, Redis or HTTP capabilities.
func (*Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: "dkim2_intelligence", Version: "0.1.0", APIVersion: pluginapi.APIVersion,
		Build:       pluginapi.BuildInfo{ArtifactIdentity: pluginapi.NativeArtifactIdentity()},
		Description: "Correlated verifier, reputation and current-peer intelligence for Policy.",
		Features:    []pluginapi.Feature{"decision_fact_provider", "reconfigure"}}
}

// Register freezes exact dependency contracts before exposing the single fact provider.
func (p *Plugin) Register(registrar pluginapi.Registrar) error {
	if registrar == nil {
		return errConfig
	}

	cfg, err := decodeConfig(registrar.Config())
	if err != nil {
		return err
	}

	decisionRegistrar, ok := registrar.(pluginapi.DecisionRegistrar)
	if !ok {
		return errConfig
	}

	if err := decisionRegistrar.RegisterDecisionFactProvider(decisionProvider{plugin: p, config: cfg}); err != nil {
		return err
	}

	p.mu.Lock()
	p.config = cfg
	p.mu.Unlock()

	return nil
}

// Start requires registration but acquires no resources.
func (p *Plugin) Start(context.Context, pluginapi.Host) error {
	if p.snapshot() == nil {
		return errConfig
	}

	return nil
}

// Stop releases no resources because composition uses only immutable admitted facts.
func (*Plugin) Stop(context.Context) error { return nil }

// Reconfigure permits operator contract updates while requiring restart for dependency or profile changes.
func (p *Plugin) Reconfigure(_ context.Context, input pluginapi.ConfigView) error {
	cfg, err := decodeConfig(input)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	old := p.config
	if old == nil || old.raw.ReputationProvider != cfg.raw.ReputationProvider || old.raw.ReputationFact != cfg.raw.ReputationFact ||
		old.raw.GeoIPProvider != cfg.raw.GeoIPProvider || old.raw.DecisionProfile != cfg.raw.DecisionProfile {
		return errConfig
	}

	p.config = cfg

	return nil
}

// snapshot retains one coherent immutable configuration for the entire request.
func (p *Plugin) snapshot() *configuration {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config
}
