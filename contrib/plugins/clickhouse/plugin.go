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

	"github.com/croessner/nauthilus/v3/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	pluginName            = "clickhouse"
	pluginVersion         = "0.1.0"
	componentPostAction   = "post_action"
	connectionTargetName  = "clickhouse"
	connectionTargetLabel = "service"
	debugModuleBatch      = "batch"
	docsURL               = "contrib/plugins/clickhouse/README.md"
)

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)
var _ pluginapi.ReloadablePlugin = (*Plugin)(nil)
var _ pluginapi.PostActionTarget = (*postActionTarget)(nil)

// NauthilusPlugin is the factory symbol loaded by the Nauthilus native plugin loader.
func NauthilusPlugin() (pluginapi.Plugin, error) {
	return NewPlugin(), nil
}

// Plugin coordinates ClickHouse post-action lifecycle and host services.
type Plugin struct {
	host        pluginapi.Host
	logger      pluginapi.Logger
	debugLogger pluginapi.Logger
	tracer      pluginapi.Tracer
	http        pluginapi.HTTPClient
	redis       pluginapi.Redis
	cache       pluginapi.Cache
	metrics     pluginMetrics
	config      moduleConfig
	mu          sync.RWMutex
}

// NewPlugin creates a ClickHouse native post-action plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{}
}

// Metadata returns the public plugin identity and API contract.
func (p *Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:        pluginName,
		Version:     pluginVersion,
		APIVersion:  pluginapi.APIVersion,
		Description: "ClickHouse JSONEachRow native post-action plugin.",
		DocsURL:     docsURL,
		Features: []pluginapi.Feature{
			"post_action",
			"clickhouse_json_each_row",
			"redis_dedup",
			"batch_cache",
			"reconfigure",
		},
	}
}

// Register declares the ClickHouse post-action target.
func (p *Plugin) Register(registrar pluginapi.Registrar) error {
	if registrar == nil {
		return fmt.Errorf("registrar is nil")
	}

	config, err := decodeModuleConfig(registrar.Config())
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.config = config
	p.mu.Unlock()

	if err := registrar.RegisterDebugModule(pluginapi.DebugModuleDefinition{
		Name:        debugModuleBatch,
		Description: "Batch queueing, flushing, and insert diagnostics.",
	}); err != nil {
		return err
	}

	return registrar.RegisterPostActionTarget(postActionTarget{plugin: p})
}

// Start captures host facades and registers ClickHouse observability.
func (p *Plugin) Start(ctx context.Context, host pluginapi.Host) error {
	if host == nil {
		return fmt.Errorf("plugin host is nil")
	}

	logger := host.Logger(pluginName)
	debugLogger := host.Logger(debugModuleBatch)
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
	p.debugLogger = debugLogger
	p.tracer = tracer
	p.http = host.HTTP(debugModuleBatch)
	p.redis = host.Redis()
	p.cache = cache
	p.metrics = metrics
	config := p.config
	p.mu.Unlock()

	p.registerConnectionTarget(ctx, host, config)
	logger.Info(ctx, "clickhouse plugin started", pluginapi.LogField{Key: logFieldURLConfigured, Value: config.InsertURL != ""})

	return nil
}

// Stop releases host facade references held by the plugin instance.
func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	logger := p.logger
	p.host = nil
	p.logger = nil
	p.debugLogger = nil
	p.tracer = nil
	p.http = nil
	p.redis = nil
	p.cache = nil
	p.metrics = pluginMetrics{}
	p.mu.Unlock()

	if logger != nil {
		logger.Info(ctx, "clickhouse plugin stopped")
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
	p.config = config
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
		config:      p.config,
		logger:      p.logger,
		debugLogger: p.debugLogger,
		tracer:      p.tracer,
		http:        p.http,
		redis:       p.redis,
		cache:       p.cache,
		metrics:     p.metrics,
	}
}

// registerConnectionTarget records the remote ClickHouse endpoint without URL paths or query text.
func (p *Plugin) registerConnectionTarget(ctx context.Context, host pluginapi.Host, config moduleConfig) {
	if host == nil || config.InsertURL == "" {
		return
	}

	address, ok := pluginutil.RemoteAddressFromURL(config.InsertURL)
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
		Description: "ClickHouse insert endpoint",
		Labels:      map[string]string{connectionTargetLabel: pluginName},
	})
	if err != nil {
		state := p.snapshot()
		if state.logger != nil {
			state.logger.Warn(ctx, "clickhouse connection target registration failed", pluginapi.LogField{Key: logFieldResult, Value: "connection_target_error"})
		}
	}
}

type pluginState struct {
	config      moduleConfig
	logger      pluginapi.Logger
	debugLogger pluginapi.Logger
	tracer      pluginapi.Tracer
	http        pluginapi.HTTPClient
	redis       pluginapi.Redis
	cache       pluginapi.Cache
	metrics     pluginMetrics
}

type postActionTarget struct {
	plugin *Plugin
}

// Name returns the local post-action component name.
func (t postActionTarget) Name() string {
	return componentPostAction
}
