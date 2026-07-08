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
	"errors"
	"fmt"
	"sync"

	"github.com/croessner/nauthilus/v3/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	pluginName            = "haveibeenpwnd"
	pluginVersion         = "0.1.0"
	componentPostAction   = "post_action"
	connectionTargetName  = "haveibeenpwnd"
	connectionTargetLabel = "service"
	docsURL               = "contrib/plugins/haveibeenpwnd/README.md"
)

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)
var _ pluginapi.ReloadablePlugin = (*Plugin)(nil)
var _ pluginapi.PostActionTarget = (*postActionTarget)(nil)

var errMailCapabilityNotActive = errors.New("haveibeenpwnd mail capability was not active at registration")

// NauthilusPlugin is the factory symbol loaded by the Nauthilus native plugin loader.
func NauthilusPlugin() (pluginapi.Plugin, error) {
	return NewPlugin(), nil
}

// Plugin coordinates HIBP post-action lifecycle and host services.
type Plugin struct {
	host                 pluginapi.Host
	logger               pluginapi.Logger
	tracer               pluginapi.Tracer
	http                 pluginapi.HTTPClient
	mailer               pluginapi.Mailer
	redis                pluginapi.Redis
	cache                pluginapi.Cache
	metrics              pluginMetrics
	config               moduleConfig
	mu                   sync.RWMutex
	mailCapabilityActive bool
}

// NewPlugin creates a Have I Been Pwned native post-action plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{}
}

// Metadata returns the public plugin identity and API contract.
func (p *Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:        pluginName,
		Version:     pluginVersion,
		APIVersion:  pluginapi.APIVersion,
		Description: "Have I Been Pwned k-anonymity native post-action plugin.",
		DocsURL:     docsURL,
		Features: []pluginapi.Feature{
			"post_action",
			"hibp_k_anonymity",
			"redis_gate",
			"local_cache",
			"mail_notification",
			"reconfigure",
		},
		Capabilities: []pluginapi.Capability{pluginapi.CapabilityCredentials, pluginapi.CapabilityMail},
	}
}

// Register declares the HIBP post-action target and credentials requirement.
func (p *Plugin) Register(registrar pluginapi.Registrar) error {
	if registrar == nil {
		return fmt.Errorf("registrar is nil")
	}

	config, err := decodeModuleConfig(registrar.Config())
	if err != nil {
		return err
	}

	if err := registrar.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
		return err
	}

	mailCapabilityActive := false

	if config.Mail.Enabled {
		if err := registrar.RequireCapability(pluginapi.CapabilityMail); err != nil {
			return err
		}

		mailCapabilityActive = true
	}

	p.mu.Lock()
	p.config = config
	p.mailCapabilityActive = mailCapabilityActive
	p.mu.Unlock()

	return registrar.RegisterPostActionTarget(postActionTarget{plugin: p})
}

// Start captures host facades and registers HIBP observability.
func (p *Plugin) Start(ctx context.Context, host pluginapi.Host) error {
	if host == nil {
		return fmt.Errorf("plugin host is nil")
	}

	logger := host.Logger(pluginName)
	tracer := host.Tracer(pluginName)

	metrics, err := registerMetrics(host.Metrics(pluginName))
	if err != nil {
		return err
	}

	cache, err := host.Cache(pluginName)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.host = host
	p.logger = logger
	p.tracer = tracer
	p.http = host.HTTP(pluginName)
	config := p.config
	p.mailer = mailerForConfig(host, config)
	p.redis = host.Redis()
	p.cache = cache
	p.metrics = metrics
	p.mu.Unlock()

	p.registerConnectionTarget(ctx, host, config)
	logger.Info(
		ctx,
		"haveibeenpwnd plugin started",
		pluginapi.LogField{Key: logFieldRedisPool, Value: configuredRedisPoolClass(config.RedisPool)},
		pluginapi.LogField{Key: logFieldRuntimeGap, Value: postActionRuntimeParityGap},
	)

	return nil
}

// Stop releases host facade references held by the plugin instance.
func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	logger := p.logger
	p.host = nil
	p.logger = nil
	p.tracer = nil
	p.http = nil
	p.mailer = nil
	p.redis = nil
	p.cache = nil
	p.metrics = pluginMetrics{}
	p.mu.Unlock()

	if logger != nil {
		logger.Info(ctx, "haveibeenpwnd plugin stopped")
	}

	return nil
}

// Reconfigure validates and atomically swaps plugin-owned config.
func (p *Plugin) Reconfigure(ctx context.Context, view pluginapi.ConfigView) error {
	config, err := decodeModuleConfig(view)
	if err != nil {
		return err
	}

	p.mu.Lock()
	host := p.host
	if config.Mail.Enabled && !p.mailCapabilityActive {
		p.mu.Unlock()

		return errMailCapabilityNotActive
	}

	p.config = config
	p.mailer = mailerForConfig(host, config)
	p.mu.Unlock()

	if host != nil {
		p.registerConnectionTarget(ctx, host, config)
	}

	return nil
}

// snapshot returns the current lifecycle state needed by request-time code.
func (p *Plugin) snapshot() pluginState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return pluginState{
		config:  p.config,
		logger:  p.logger,
		tracer:  p.tracer,
		http:    p.http,
		mailer:  p.mailer,
		redis:   p.redis,
		cache:   p.cache,
		metrics: p.metrics,
	}
}

// mailerForConfig returns the scoped mail facade only when notifications are enabled.
func mailerForConfig(host pluginapi.Host, config moduleConfig) pluginapi.Mailer {
	if host == nil || !config.Mail.Enabled {
		return nil
	}

	return host.Mail(pluginName)
}

// registerConnectionTarget records the remote HIBP endpoint without URL paths.
func (p *Plugin) registerConnectionTarget(ctx context.Context, host pluginapi.Host, config moduleConfig) {
	if host == nil || config.APIBaseURL == "" {
		return
	}

	address, ok := pluginutil.RemoteAddressFromURL(config.APIBaseURL)
	if !ok {
		return
	}

	targets := host.ConnectionTargets(pluginName)
	if targets == nil {
		return
	}

	err := targets.Register(ctx, pluginapi.ConnectionTarget{
		Name:        connectionTargetName,
		Address:     address,
		Direction:   pluginapi.ConnectionTargetDirectionRemote,
		Description: "Have I Been Pwned range API endpoint",
		Labels:      map[string]string{connectionTargetLabel: pluginName},
	})
	if err != nil {
		state := p.snapshot()
		if state.logger != nil {
			state.logger.Warn(ctx, "haveibeenpwnd connection target registration failed", pluginapi.LogField{Key: logFieldResult, Value: "connection_target_error"})
		}
	}
}

// configuredRedisPoolClass returns a bounded class for Redis pool observability.
func configuredRedisPoolClass(pool string) string {
	if pool == defaultRedisPool {
		return "default"
	}

	return "custom_ignored"
}

type pluginState struct {
	config  moduleConfig
	logger  pluginapi.Logger
	tracer  pluginapi.Tracer
	http    pluginapi.HTTPClient
	mailer  pluginapi.Mailer
	redis   pluginapi.Redis
	cache   pluginapi.Cache
	metrics pluginMetrics
}

type postActionTarget struct {
	plugin *Plugin
}

// Name returns the local post-action component name.
func (t postActionTarget) Name() string {
	return componentPostAction
}
