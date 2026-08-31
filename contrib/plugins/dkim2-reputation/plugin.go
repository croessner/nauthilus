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

package main

import (
	"context"
	"fmt"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	pluginName        = "dkim2_reputation"
	pluginVersion     = "0.1.0"
	providerNamespace = "dkim2"
	providerName      = "assessment"
)

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)
var _ pluginapi.ReloadablePlugin = (*Plugin)(nil)

// NauthilusPlugin is the factory symbol loaded by the Nauthilus native plugin loader.
func NauthilusPlugin() (pluginapi.Plugin, error) {
	return NewPlugin(), nil
}

// Plugin owns immutable reputation configuration and generic provider registration.
type Plugin struct {
	config *assessmentConfig
	mu     sync.RWMutex
}

// NewPlugin creates one unconfigured DKIM2 reputation plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{}
}

// Metadata returns the public plugin identity and API contract.
func (p *Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:        pluginName,
		Version:     pluginVersion,
		APIVersion:  pluginapi.APIVersion,
		Description: "Generic Policy fact provider for DKIM2 verifier-chain reputation assessment.",
		DocsURL:     "contrib/plugins/dkim2-reputation/README.md",
		Features:    []pluginapi.Feature{"decision_fact_provider", "reconfigure"},
	}
}

// Register validates module configuration and declares the generic fact provider.
func (p *Plugin) Register(registrar pluginapi.Registrar) error {
	if registrar == nil {
		return fmt.Errorf("registrar is nil")
	}

	config, err := decodeAssessmentConfig(registrar.Config())
	if err != nil {
		return err
	}

	decisionRegistrar, ok := registrar.(pluginapi.DecisionRegistrar)
	if !ok {
		return fmt.Errorf("registrar does not support the required generic decision fact provider")
	}

	p.swapConfig(config)

	return decisionRegistrar.RegisterDecisionFactProvider(decisionFactProvider{plugin: p})
}

// Start verifies that registration installed an immutable configuration snapshot.
func (p *Plugin) Start(_ context.Context, _ pluginapi.Host) error {
	if p.snapshot() == nil {
		return fmt.Errorf("dkim2 reputation plugin has no configuration")
	}

	return nil
}

// Stop releases no resources because assessments are memory-only.
func (p *Plugin) Stop(context.Context) error {
	return nil
}

// Reconfigure validates and atomically replaces the assessment snapshot.
func (p *Plugin) Reconfigure(_ context.Context, view pluginapi.ConfigView) error {
	config, err := decodeAssessmentConfig(view)
	if err != nil {
		return err
	}

	p.swapConfig(config)

	return nil
}

// snapshot returns the current immutable configuration pointer.
func (p *Plugin) snapshot() *assessmentConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config
}

// swapConfig publishes a fully validated immutable configuration snapshot.
func (p *Plugin) swapConfig(config *assessmentConfig) {
	p.mu.Lock()
	p.config = config
	p.mu.Unlock()
}
