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
	"net/netip"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
)

const (
	pluginName         = "geoip"
	pluginVersion      = "0.1.0"
	componentDatabase  = "database"
	componentSource    = "environment"
	metricLookupTotal  = "geoip_lookup_total"
	metricLookupTime   = "geoip_lookup_seconds"
	metricRecords      = "geoip_database_records"
	metricLabelResult  = "result"
	metricLabelState   = "state"
	metricStateLoaded  = "loaded"
	resultError        = "error"
	resultInvalidIP    = "invalid_ip"
	resultMatched      = "matched"
	resultMiss         = "miss"
	traceAttrComponent = "plugin.component"
	traceAttrModule    = "plugin.module"
)

var _ pluginapi.Plugin = (*Plugin)(nil)
var _ pluginapi.RuntimePlugin = (*Plugin)(nil)
var _ pluginapi.ReloadablePlugin = (*Plugin)(nil)

// NauthilusPlugin is the factory symbol loaded by the Nauthilus native plugin loader.
func NauthilusPlugin() (pluginapi.Plugin, error) {
	return NewPlugin(), nil
}

// Plugin coordinates lifecycle, state, and environment source registration.
type Plugin struct {
	database      geoDatabase
	host          pluginapi.Host
	logger        pluginapi.Logger
	tracer        pluginapi.Tracer
	asnRegistry   *asnRegistrySnapshot
	databaseLoad  databaseLoader
	asnFetch      asnRegistryFetcher
	lookupCounter pluginapi.Counter
	lookupLatency pluginapi.Histogram
	recordGauge   pluginapi.Gauge
	refreshCancel context.CancelFunc
	asnCancel     context.CancelFunc
	config        moduleConfig
	mu            sync.RWMutex
}

// NewPlugin creates a GeoIP reference plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{
		databaseLoad: loadConfiguredDatabase,
		asnFetch:     httpASNRegistryFetcher{},
	}
}

// Metadata returns the public plugin identity and API contract.
func (p *Plugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:        pluginName,
		Version:     pluginVersion,
		APIVersion:  pluginapi.APIVersion,
		Description: "Reference GeoIP and ASN environment enrichment plugin.",
		DocsURL:     "server/docs/examples/go_plugin_geoip.yml",
		Features: []pluginapi.Feature{
			"asn_registry_refresh",
			"environment_source",
			"init_task",
			"maxmind_mmdb",
			"reconfigure",
		},
	}
}

// Register declares the init task, environment source, and policy facts.
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

	if err := registerPolicyAttributes(registrar); err != nil {
		return err
	}

	if err := registrar.RegisterInitTask(geoIPInitTask{plugin: p}); err != nil {
		return err
	}

	return registrar.RegisterEnvironmentSource(geoIPEnvironmentSource{plugin: p})
}

// Start captures host facades and registers bounded plugin-owned metrics.
func (p *Plugin) Start(ctx context.Context, host pluginapi.Host) error {
	if host == nil {
		return fmt.Errorf("plugin host is nil")
	}

	logger := host.Logger(pluginName)
	tracer := host.Tracer(pluginName)
	metrics := host.Metrics(pluginName)

	lookupCounter, lookupLatency, recordGauge, err := registerMetrics(metrics)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.host = host
	p.logger = logger
	p.tracer = tracer
	p.lookupCounter = lookupCounter
	p.lookupLatency = lookupLatency
	p.recordGauge = recordGauge
	p.mu.Unlock()

	logger.Info(ctx, "geoip plugin started")

	return nil
}

// Stop cancels refresh work and keeps no request-time resources alive.
func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	p.stopWorkersLocked()
	p.closeDatabaseLocked()
	logger := p.logger
	p.mu.Unlock()

	if logger != nil {
		logger.Info(ctx, "geoip plugin stopped")
	}

	return nil
}

// Reconfigure validates and atomically swaps database-backed plugin state.
func (p *Plugin) Reconfigure(ctx context.Context, view pluginapi.ConfigView) error {
	config, database, err := p.loadConfigAndDatabase(ctx, view)
	if err != nil {
		return err
	}

	p.swapDatabase(ctx, config, database, true)

	return nil
}

// loadConfigAndDatabase validates config and loads the referenced database.
func (p *Plugin) loadConfigAndDatabase(ctx context.Context, view pluginapi.ConfigView) (moduleConfig, geoDatabase, error) {
	config, err := decodeModuleConfig(view)
	if err != nil {
		return moduleConfig{}, nil, err
	}

	database, err := p.loadDatabase(ctx, config)
	if err != nil {
		return moduleConfig{}, nil, err
	}

	return config, database, nil
}

// swapDatabase publishes a validated database and optionally restarts refresh work.
func (p *Plugin) swapDatabase(ctx context.Context, config moduleConfig, database geoDatabase, restartRefresh bool) {
	p.mu.Lock()
	oldDatabase := p.database

	p.config = config
	p.database = database

	if !config.ASNRegistry.Enabled {
		p.asnRegistry = nil
	}

	if restartRefresh {
		p.startWorkersLocked()
	}

	recordGauge := p.recordGauge
	logger := p.logger
	p.mu.Unlock()

	closeDatabase(oldDatabase)

	if recordGauge != nil {
		recordGauge.Set(ctx, float64(database.Records()), pluginapi.LabelValue{Name: metricLabelState, Value: metricStateLoaded})
	}

	if logger != nil {
		logger.Info(ctx, "geoip database loaded", pluginapi.LogField{Key: "records", Value: database.Records()})
	}
}

// currentConfig returns the config snapshot and whether a database is loaded.
func (p *Plugin) currentConfig() (moduleConfig, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config, p.database != nil
}

// lookupRecord runs a database lookup while protecting the active reader from replacement.
func (p *Plugin) lookupRecord(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.database == nil {
		return geoRecord{}, false, fmt.Errorf("geoip database is not loaded")
	}

	record, matched, err := p.database.Lookup(ctx, addr)
	if err != nil || !matched || record.ASN <= 0 || p.asnRegistry == nil {
		return record, matched, err
	}

	if asnRecord, ok := p.asnRegistry.Lookup(record.ASN); ok {
		record.ASNRegistry = asnRecord.Registry
		record.ASNCountryISO = asnRecord.CountryISO
		record.ASNAllocated = asnRecord.Allocated
		record.ASNStatus = asnRecord.Status
	}

	return record, matched, nil
}

// startWorkersLocked starts or replaces all optional background workers.
func (p *Plugin) startWorkersLocked() {
	p.stopWorkersLocked()
	p.startDatabaseRefreshWorkerLocked()
	p.startASNRegistryWorkerLocked()
}

// stopWorkersLocked cancels all active background workers.
func (p *Plugin) stopWorkersLocked() {
	p.stopDatabaseRefreshWorkerLocked()
	p.stopASNRegistryWorkerLocked()
}

// startDatabaseRefreshWorkerLocked starts or replaces the optional database refresh worker.
func (p *Plugin) startDatabaseRefreshWorkerLocked() {
	if p.host == nil || p.config.RefreshInterval <= 0 {
		return
	}

	workerCtx, cancel := context.WithCancel(p.host.ServiceContext())
	p.refreshCancel = cancel
	interval := p.config.RefreshInterval

	p.host.Go(workerCtx, "geoip.refresh", func(ctx context.Context) error {
		return p.refreshLoop(ctx, interval)
	})
}

// stopDatabaseRefreshWorkerLocked cancels the active database refresh worker when one exists.
func (p *Plugin) stopDatabaseRefreshWorkerLocked() {
	if p.refreshCancel == nil {
		return
	}

	p.refreshCancel()
	p.refreshCancel = nil
}

// startASNRegistryWorkerLocked starts the optional delegated registry refresh worker.
func (p *Plugin) startASNRegistryWorkerLocked() {
	if p.host == nil || !p.config.ASNRegistry.Enabled {
		return
	}

	workerCtx, cancel := context.WithCancel(p.host.ServiceContext())
	p.asnCancel = cancel
	config := p.config.ASNRegistry

	p.host.Go(workerCtx, "geoip.asn_registry", func(ctx context.Context) error {
		return p.asnRegistryLoop(ctx, config)
	})
}

// stopASNRegistryWorkerLocked cancels the active ASN registry refresh worker when one exists.
func (p *Plugin) stopASNRegistryWorkerLocked() {
	if p.asnCancel == nil {
		return
	}

	p.asnCancel()
	p.asnCancel = nil
}

// refreshLoop periodically reloads the configured local database.
func (p *Plugin) refreshLoop(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.refreshOnce(ctx)
		}
	}
}

// asnRegistryLoop refreshes delegated registry data immediately and then periodically.
func (p *Plugin) asnRegistryLoop(ctx context.Context, config asnRegistryConfig) error {
	p.refreshASNRegistryOnce(ctx, config)

	ticker := time.NewTicker(config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.refreshASNRegistryOnce(ctx, config)
		}
	}
}

// refreshOnce reloads the current database path without replacing state on failure.
func (p *Plugin) refreshOnce(ctx context.Context) {
	config, ready := p.currentConfig()
	if !ready {
		return
	}

	database, err := p.loadDatabase(ctx, config)
	if err != nil {
		p.recordLookup(ctx, resultError, 0)
		p.logError(ctx, "geoip database refresh failed", err)

		return
	}

	p.swapDatabase(ctx, config, database, false)
}

// refreshASNRegistryOnce fetches and publishes delegated ASN registry metadata.
func (p *Plugin) refreshASNRegistryOnce(ctx context.Context, config asnRegistryConfig) {
	snapshot, err := fetchASNRegistrySnapshot(ctx, p.asnRegistryFetcher(), config.SourceURLs, config.Timeout)
	if err != nil {
		p.logError(ctx, "geoip ASN registry refresh failed", err)

		return
	}

	p.mu.Lock()
	p.asnRegistry = snapshot
	logger := p.logger
	p.mu.Unlock()

	if logger != nil {
		logger.Info(
			ctx,
			"geoip ASN registry loaded",
			pluginapi.LogField{Key: "ranges", Value: snapshot.Records()},
			pluginapi.LogField{Key: "loaded_at", Value: snapshot.loadedAt.Format(time.RFC3339)},
		)
	}
}

// closeDatabaseLocked releases the active database while the plugin is stopped.
func (p *Plugin) closeDatabaseLocked() {
	closeDatabase(p.database)
	p.database = nil
}

// closeDatabase releases database resources and intentionally ignores close errors during replacement.
func closeDatabase(database geoDatabase) {
	if database == nil {
		return
	}

	_ = database.Close()
}

// loadDatabase loads a configured database through the production or test loader.
func (p *Plugin) loadDatabase(ctx context.Context, config moduleConfig) (geoDatabase, error) {
	loader := p.databaseLoad
	if loader == nil {
		loader = loadConfiguredDatabase
	}

	return loader(ctx, config)
}

// asnRegistryFetcher returns the production or test registry fetcher.
func (p *Plugin) asnRegistryFetcher() asnRegistryFetcher {
	if p.asnFetch != nil {
		return p.asnFetch
	}

	return httpASNRegistryFetcher{}
}

// recordLookup records bounded request-time metric labels.
func (p *Plugin) recordLookup(ctx context.Context, result string, duration time.Duration) {
	p.mu.RLock()
	counter := p.lookupCounter
	latency := p.lookupLatency
	p.mu.RUnlock()

	label := pluginapi.LabelValue{Name: metricLabelResult, Value: result}
	if counter != nil {
		counter.Add(ctx, 1, label)
	}

	if latency != nil && duration > 0 {
		latency.Observe(ctx, duration.Seconds(), label)
	}
}

// logError writes an error through the host logger when available.
func (p *Plugin) logError(ctx context.Context, message string, err error) {
	p.mu.RLock()
	logger := p.logger
	p.mu.RUnlock()

	if logger != nil {
		logger.Error(ctx, message, pluginapi.LogField{Key: "error", Value: err})
	}
}

// registerMetrics declares the plugin-owned metric handles.
func registerMetrics(metrics pluginapi.Metrics) (pluginapi.Counter, pluginapi.Histogram, pluginapi.Gauge, error) {
	if metrics == nil {
		return nil, nil, nil, fmt.Errorf("plugin metrics facade is nil")
	}

	lookupCounter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   metricLookupTotal,
		Help:   "GeoIP environment source lookup attempts.",
		Labels: []string{metricLabelResult},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	lookupLatency, err := metrics.Histogram(pluginapi.MetricDefinition{
		Name:    metricLookupTime,
		Help:    "GeoIP environment source lookup latency.",
		Labels:  []string{metricLabelResult},
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	recordGauge, err := metrics.Gauge(pluginapi.MetricDefinition{
		Name:   metricRecords,
		Help:   "Loaded GeoIP database records.",
		Labels: []string{metricLabelState},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return lookupCounter, lookupLatency, recordGauge, nil
}
