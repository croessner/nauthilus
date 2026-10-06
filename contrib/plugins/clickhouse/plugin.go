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
	"time"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	pluginName            = "clickhouse"
	pluginVersion         = "0.1.0"
	componentPostAction   = "post_action"
	connectionTargetName  = "clickhouse"
	connectionTargetLabel = "service"
	debugModuleBatch      = "batch"
	docsURL               = "contrib/plugins/clickhouse/README.md"
	flushTriggerInterval  = "interval"
	flushTriggerStop      = "stop"
	resultFlushFailed     = "flush_failed"
	resultWorkerTimeout   = "worker_stop_timeout"
)

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)
var _ pluginapi.ReloadablePlugin = (*Plugin)(nil)
var _ pluginapi.ReconfigureValidator = (*Plugin)(nil)
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
	flushes     flushScheduler
	metrics     pluginMetrics
	config      moduleConfig
	retryAfter  time.Time
	pendingRows int
	retryDelay  time.Duration
	flushing    bool
	mu          sync.RWMutex
	lifecycleMu sync.Mutex
}

// NewPlugin creates a ClickHouse native post-action plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{flushes: flushScheduler{newTicker: newTimeTicker}}
}

// Metadata returns the public plugin identity and API contract.
func (p *Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Build:        pluginapi.BuildInfo{ArtifactIdentity: pluginapi.NativeArtifactIdentity()},
		Name:         pluginName,
		Version:      pluginVersion,
		APIVersion:   pluginapi.APIVersion,
		Description:  "ClickHouse JSONEachRow native post-action plugin.",
		Capabilities: []pluginapi.Capability{pluginapi.CapabilityPasswordHash},
		DocsURL:      docsURL,
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

	if err := registrar.RequireCapability(pluginapi.CapabilityPasswordHash); err != nil {
		return err
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

// Start captures host facades, registers ClickHouse observability, and starts the optional flush worker.
func (p *Plugin) Start(ctx context.Context, host pluginapi.Host) error {
	if host == nil {
		return fmt.Errorf("plugin host is nil")
	}

	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	logger := host.Logger(pluginName)
	debugLogger := host.Logger(debugModuleBatch)
	tracer := host.Tracer(pluginName)

	metrics, err := registerMetrics(host.Metrics(pluginName))
	if err != nil {
		return err
	}

	metrics.initializeResultSeries(ctx)

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

	p.applyFlushWorker(ctx, host, config)
	logger.Info(ctx, "clickhouse plugin started", pluginapi.LogField{Key: logFieldURLConfigured, Value: config.InsertURL != ""})

	return nil
}

// Stop ends the flush worker, flushes the pending local batch once, and releases host facade references.
// It is safe after a failed Start and when called repeatedly.
func (p *Plugin) Stop(ctx context.Context) error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	if err := p.flushes.stop(ctx); err != nil {
		warnBounded(ctx, p.snapshot().logger, "clickhouse flush worker did not stop before the shutdown deadline",
			pluginapi.LogField{Key: logFieldResult, Value: resultWorkerTimeout})
	}

	p.flushOnStop(ctx)

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

// ValidateReconfigure checks a candidate config without touching the running plugin.
func (p *Plugin) ValidateReconfigure(_ context.Context, view pluginapi.ConfigView) error {
	_, err := decodeModuleConfig(view)

	return err
}

// Reconfigure validates and atomically swaps plugin-owned config and restarts the flush worker
// when flush_interval changed.
func (p *Plugin) Reconfigure(ctx context.Context, view pluginapi.ConfigView) error {
	config, err := decodeModuleConfig(view)
	if err != nil {
		return err
	}

	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	p.mu.Lock()
	host := p.host
	previousKey := p.config.CacheKey
	p.config = config
	p.movePendingRowsLocked(ctx, previousKey)
	p.mu.Unlock()

	if host == nil {
		return nil
	}

	p.registerConnectionTarget(ctx, host, config)
	p.applyFlushWorker(ctx, host, config)

	return nil
}

// applyFlushWorker aligns the periodic flush worker with config and logs when its state changed.
// The caller holds the lifecycle mutex.
func (p *Plugin) applyFlushWorker(ctx context.Context, host pluginapi.Host, config moduleConfig) {
	if !p.flushes.apply(ctx, host, config.FlushInterval, p.flushOnTick) {
		return
	}

	state := "stopped"
	if p.flushes.running() {
		state = "running"
	}

	if logger := p.snapshot().logger; logger != nil {
		logger.Info(ctx, "clickhouse flush worker updated", pluginapi.LogField{Key: logFieldFlushWorker, Value: state})
	}
}

// movePendingRowsLocked migrates the buffer and applies a reduced limit while holding the write lock.
func (p *Plugin) movePendingRowsLocked(ctx context.Context, previousKey string) {
	if p.cache == nil || previousKey == "" {
		return
	}

	rows := p.cache.PopAll(ctx, previousKey)
	p.pendingRows = 0
	p.pushRowsLocked(ctx, rows...)
}

// pushRows admits rows under the current key up to the buffer limit; -1 means none were admitted.
func (p *Plugin) pushRows(ctx context.Context, rows ...any) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.pushRowsLocked(ctx, rows...)
}

// pushRowsLocked applies the shared admission policy while the caller holds the write lock.
func (p *Plugin) pushRowsLocked(ctx context.Context, rows ...any) int {
	length := p.pendingRows
	accepted := 0

	if p.cache == nil {
		return -1
	}

	for _, row := range rows {
		if p.pendingRows >= p.config.MaxBufferRows {
			p.metrics.recordQueueResult(ctx, resultDropped)
			continue
		}

		length = p.cache.Push(ctx, p.config.CacheKey, row)
		p.pendingRows = length
		accepted++
	}

	if accepted == 0 {
		return -1
	}

	return length
}

// flushOnTick flushes the pending local batch for the periodic flush worker.
func (p *Plugin) flushOnTick(ctx context.Context) {
	p.flushPending(ctx, flushTriggerInterval)
}

// flushOnStop flushes the pending local batch once, bounded by the configured request timeout.
func (p *Plugin) flushOnStop(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	flushCtx, cancel := context.WithTimeout(ctx, p.snapshot().config.Timeout)
	defer cancel()

	p.flushPending(flushCtx, flushTriggerStop)
}

// flushPending flushes whatever the local batch holds and logs a bounded failure record.
// It is a no-op before Start, after Stop, and when the batch is empty.
func (p *Plugin) flushPending(ctx context.Context, trigger string) {
	state := p.snapshot()
	if state.cache == nil {
		return
	}

	// The error text is not logged: transport errors can carry the insert URL and its query.
	if err := flushBatch(ctx, state); err != nil {
		warnBounded(ctx, state.logger, "clickhouse pending batch flush failed",
			pluginapi.LogField{Key: logFieldResult, Value: resultFlushFailed},
			pluginapi.LogField{Key: logFieldTrigger, Value: trigger},
		)
	}
}

// warnBounded emits a warning with bounded fields when a logger is attached.
func warnBounded(ctx context.Context, logger pluginapi.Logger, message string, fields ...pluginapi.LogField) {
	if logger == nil {
		return
	}

	logger.Warn(ctx, message, fields...)
}

// snapshot returns the current lifecycle state needed by request-time code.
func (p *Plugin) snapshot() pluginState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return pluginState{
		queue:       p,
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

// rowQueue coordinates bounded admission and exclusive flush attempts under the current cache key.
type rowQueue interface {
	pushRows(ctx context.Context, rows ...any) int
	beginFlush(context.Context) []any
	finishFlush(bool)
}

type pluginState struct {
	queue       rowQueue
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
