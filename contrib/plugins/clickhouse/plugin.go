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
	host         pluginapi.Host
	logger       pluginapi.Logger
	debugLogger  pluginapi.Logger
	tracer       pluginapi.Tracer
	http         pluginapi.HTTPClient
	redis        pluginapi.Redis
	cache        pluginapi.Cache
	flushes      flushScheduler
	eventFlushes flushScheduler
	bfFlushes    flushScheduler
	config       moduleConfig
	// logins batches authentication rows; events batches host step events into their own table.
	logins rowStream
	events rowStream
	// bfLifecycle, bfCounted, and bfHits batch brute-force events with independent buffers, so a hammered banned
	// network cannot evict counted contributions or lifecycle transitions.
	bfLifecycle rowStream
	bfCounted   rowStream
	bfHits      rowStream
	mu          sync.RWMutex
	lifecycleMu sync.Mutex
}

// NewPlugin creates a ClickHouse native post-action plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{
		flushes:      flushScheduler{newTicker: newTimeTicker},
		eventFlushes: flushScheduler{newTicker: newTimeTicker},
		bfFlushes:    flushScheduler{newTicker: newTimeTicker},
		logins:       rowStream{target: loginStreamTarget, names: loginMetricNames},
		events:       rowStream{target: eventStreamTarget, names: eventMetricNames},
		bfLifecycle:  rowStream{target: bruteForceLifecycleStreamTarget, names: streamMetricNames("bruteforce_lifecycle")},
		bfCounted:    rowStream{target: bruteForceCountedStreamTarget, names: streamMetricNames("bruteforce_counted")},
		bfHits:       rowStream{target: bruteForceHitsStreamTarget, names: streamMetricNames("bruteforce_hits")},
	}
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
			"auth_events",
			"bruteforce_events",
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

	if err := registrar.RegisterPostActionTarget(postActionTarget{plugin: p}); err != nil {
		return err
	}

	// Hosts without the additive event registrars keep the post-action-only contract.
	if eventRegistrar, ok := registrar.(pluginapi.AuthEventRegistrar); ok {
		if err := eventRegistrar.RegisterAuthEventSink(authEventTarget{plugin: p}); err != nil {
			return err
		}
	}

	if bruteForceRegistrar, ok := registrar.(pluginapi.BruteForceEventRegistrar); ok {
		return bruteForceRegistrar.RegisterBruteForceEventSink(bruteForceEventTarget{plugin: p})
	}

	return nil
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

	streamMetrics := make([]pluginMetrics, 0, len(p.allStreams()))

	for _, stream := range p.allStreams() {
		metrics, err := registerMetrics(host.Metrics(pluginName), stream.names)
		if err != nil {
			return err
		}

		metrics.initializeResultSeries(ctx)
		streamMetrics = append(streamMetrics, metrics)
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

	for index, stream := range p.allStreams() {
		stream.metrics = streamMetrics[index]
	}

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

	for _, scheduler := range []*flushScheduler{&p.flushes, &p.eventFlushes, &p.bfFlushes} {
		if err := scheduler.stop(ctx); err != nil {
			warnBounded(ctx, p.snapshot().logger, "clickhouse flush worker did not stop before the shutdown deadline",
				pluginapi.LogField{Key: logFieldResult, Value: resultWorkerTimeout})
		}
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

	for _, stream := range p.allStreams() {
		stream.metrics = pluginMetrics{}
	}

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
	previous := p.config
	p.config = config
	for _, stream := range p.allStreams() {
		p.movePendingRowsLocked(ctx, stream, previous)
	}
	p.mu.Unlock()

	if host == nil {
		return nil
	}

	p.registerConnectionTarget(ctx, host, config)
	p.applyFlushWorker(ctx, host, config)

	return nil
}

// applyFlushWorker aligns both periodic flush workers with config and logs when a state changed. The step-event
// worker always runs while an events insert URL is configured, because event volume rarely reaches batch_size.
// The caller holds the lifecycle mutex.
func (p *Plugin) applyFlushWorker(ctx context.Context, host pluginapi.Host, config moduleConfig) {
	p.applyStreamFlushWorker(ctx, host, &p.flushes, config.FlushInterval, p.flushOnTick, flushWorkerLogins)

	eventInterval := time.Duration(0)
	if config.EventsInsertURL != "" {
		eventInterval = config.EventsFlushInterval
	}

	p.applyStreamFlushWorker(ctx, host, &p.eventFlushes, eventInterval, p.flushEventsOnTick, flushWorkerEvents)

	bruteForceInterval := time.Duration(0)
	if config.BruteForceLifecycleInsertURL != "" || config.BruteForceAttemptsInsertURL != "" {
		bruteForceInterval = config.BruteForceFlushInterval
	}

	p.applyStreamFlushWorker(ctx, host, &p.bfFlushes, bruteForceInterval, p.flushBruteForceOnTick, flushWorkerBruteForce)
}

// allStreams lists every row stream in a stable order for lifecycle handling.
func (p *Plugin) allStreams() []*rowStream {
	return []*rowStream{&p.logins, &p.events, &p.bfLifecycle, &p.bfCounted, &p.bfHits}
}

// bruteForceStreams lists the brute-force event streams that share one flush worker.
func (p *Plugin) bruteForceStreams() []*rowStream {
	return []*rowStream{&p.bfLifecycle, &p.bfCounted, &p.bfHits}
}

// flushBruteForceOnTick flushes every brute-force stream for their periodic flush worker.
func (p *Plugin) flushBruteForceOnTick(ctx context.Context) {
	for _, stream := range p.bruteForceStreams() {
		p.flushPending(ctx, stream, flushTriggerInterval)
	}
}

// applyStreamFlushWorker starts, replaces, or stops one stream's interval worker and logs the change.
func (p *Plugin) applyStreamFlushWorker(
	ctx context.Context,
	host pluginapi.Host,
	scheduler *flushScheduler,
	interval time.Duration,
	flush func(context.Context),
	stream string,
) {
	if !scheduler.apply(ctx, host, interval, flush) {
		return
	}

	state := "stopped"
	if scheduler.running() {
		state = "running"
	}

	if logger := p.snapshot().logger; logger != nil {
		logger.Info(ctx, "clickhouse flush worker updated",
			pluginapi.LogField{Key: logFieldFlushWorker, Value: state},
			pluginapi.LogField{Key: logFieldStream, Value: stream})
	}
}

// movePendingRowsLocked migrates one stream's buffer and applies a reduced limit while holding the write lock.
func (p *Plugin) movePendingRowsLocked(ctx context.Context, stream *rowStream, previous moduleConfig) {
	_, previousKey := stream.target(previous)
	if p.cache == nil || previousKey == "" {
		return
	}

	rows := p.cache.PopAll(ctx, previousKey)
	stream.pendingRows = 0
	p.pushRowsLocked(ctx, stream, rows...)
}

// pushRowsLocked admits rows into one stream under its current key up to the buffer limit while the caller holds
// the write lock; -1 means none were admitted. Drops are counted in the stream's own metrics.
func (p *Plugin) pushRowsLocked(ctx context.Context, stream *rowStream, rows ...any) int {
	length := stream.pendingRows
	accepted := 0

	if p.cache == nil {
		return -1
	}

	_, cacheKey := stream.target(p.config)

	for _, row := range rows {
		if stream.pendingRows >= p.config.MaxBufferRows {
			stream.metrics.recordQueueResult(ctx, resultDropped)
			continue
		}

		length = p.cache.Push(ctx, cacheKey, row)
		stream.pendingRows = length
		accepted++
	}

	if accepted == 0 {
		return -1
	}

	return length
}

// flushOnTick flushes the pending local login batch for the periodic flush worker.
func (p *Plugin) flushOnTick(ctx context.Context) {
	p.flushPending(ctx, &p.logins, flushTriggerInterval)
}

// flushEventsOnTick flushes the pending local step-event batch for its periodic flush worker.
func (p *Plugin) flushEventsOnTick(ctx context.Context) {
	p.flushPending(ctx, &p.events, flushTriggerInterval)
}

// flushOnStop flushes the pending local batch once, bounded by the configured request timeout.
func (p *Plugin) flushOnStop(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	flushCtx, cancel := context.WithTimeout(ctx, p.snapshot().config.Timeout)
	defer cancel()

	for _, stream := range p.allStreams() {
		p.flushPending(flushCtx, stream, flushTriggerStop)
	}
}

// flushPending flushes whatever the local batch holds and logs a bounded failure record.
// It is a no-op before Start, after Stop, and when the batch is empty.
func (p *Plugin) flushPending(ctx context.Context, stream *rowStream, trigger string) {
	state := p.snapshotFor(stream)
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

// snapshot returns the current lifecycle state of the login stream needed by request-time code.
func (p *Plugin) snapshot() pluginState {
	return p.snapshotFor(&p.logins)
}

// snapshotFor captures the shared lifecycle state bound to one stream's queue, target, and metrics.
func (p *Plugin) snapshotFor(stream *rowStream) pluginState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	insertURL, cacheKey := stream.target(p.config)

	return pluginState{
		queue:       streamQueue{plugin: p, stream: stream},
		insertURL:   insertURL,
		cacheKey:    cacheKey,
		config:      p.config,
		logger:      p.logger,
		debugLogger: p.debugLogger,
		tracer:      p.tracer,
		http:        p.http,
		redis:       p.redis,
		cache:       p.cache,
		metrics:     stream.metrics,
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
	insertURL   string
	cacheKey    string
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
