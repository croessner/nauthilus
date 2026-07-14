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
	"reflect"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	pluginName           = "geoip"
	pluginVersion        = "0.1.0"
	componentASNLookup   = "asn_lookup"
	componentDatabase    = "database"
	componentSource      = "environment"
	metricLookupTotal    = "geoip_lookup_total"
	metricLookupTime     = "geoip_lookup_seconds"
	metricRecords        = "geoip_database_records"
	metricPrivacyRefresh = "geoip_privacy_source_refresh_total"
	metricPrivacyEntries = "geoip_privacy_snapshot_entries"
	metricLabelResult    = "result"
	metricLabelSource    = "source"
	metricLabelState     = "state"
	metricStateLoaded    = "loaded"
	resultError          = "error"
	resultInvalidIP      = "invalid_ip"
	resultMatched        = "matched"
	resultMiss           = "miss"
	logFieldLoadedAt     = "loaded_at"
	traceAttrComponent   = "plugin.component"
	traceAttrModule      = "plugin.module"
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
	databaseOwner  *geoDatabaseOwner
	host           pluginapi.Host
	logger         pluginapi.Logger
	tracer         pluginapi.Tracer
	asnRegistry    *asnRegistrySnapshot
	asnLookup      *asnLookupService
	privacy        *privacyEngine
	databaseLoad   databaseLoader
	asnFetch       asnRegistryFetcher
	asnRouteFetch  asnRouteFetcher
	lookupCounter  pluginapi.Counter
	lookupLatency  pluginapi.Histogram
	recordGauge    pluginapi.Gauge
	privacyRefresh pluginapi.Counter
	privacyEntries pluginapi.Gauge
	refreshCancel  context.CancelFunc
	asnCancel      context.CancelFunc
	asnRouteCancel context.CancelFunc
	privacyCancel  []context.CancelFunc
	config         moduleConfig
	mu             sync.RWMutex
}

// NewPlugin creates a GeoIP reference plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{
		databaseOwner: newGeoDatabaseOwner(geoDatabases{}),
		databaseLoad:  loadConfiguredDatabase,
		asnFetch:      httpASNRegistryFetcher{},
		asnRouteFetch: httpASNRouteFetcher{},
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
			"asn_routing_snapshot",
			"asn_registry_refresh",
			"asn_mmdb",
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

	privacyRefresh, privacyEntries, err := registerPrivacyMetrics(metrics)
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
	p.privacyRefresh = privacyRefresh
	p.privacyEntries = privacyEntries
	p.mu.Unlock()

	logger.Info(ctx, "geoip plugin started")

	return nil
}

// Stop cancels refresh work and keeps no request-time resources alive.
func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	p.stopWorkersLocked()
	owner := p.databaseOwner
	p.databaseOwner = newGeoDatabaseOwner(geoDatabases{})
	logger := p.logger
	p.mu.Unlock()

	if err := owner.WaitRetired(ctx); err != nil {
		return err
	}

	if logger != nil {
		logger.Info(ctx, "geoip plugin stopped")
	}

	return nil
}

// Reconfigure validates and atomically swaps database-backed plugin state.
func (p *Plugin) Reconfigure(ctx context.Context, view pluginapi.ConfigView) error {
	config, databases, privacy, err := p.loadConfigAndDatabases(ctx, view)
	if err != nil {
		return err
	}

	p.swapState(ctx, config, databases, privacy, true)

	return nil
}

// loadConfigAndDatabases validates config and loads the referenced databases.
func (p *Plugin) loadConfigAndDatabases(ctx context.Context, view pluginapi.ConfigView) (moduleConfig, geoDatabases, *privacyEngine, error) {
	config, err := decodeModuleConfig(view)
	if err != nil {
		return moduleConfig{}, geoDatabases{}, nil, err
	}

	databases, err := p.loadDatabases(ctx, config)
	if err != nil {
		return moduleConfig{}, geoDatabases{}, nil, err
	}

	p.mu.RLock()
	host := p.host
	currentPrivacy := p.privacy
	currentPrivacyConfig := p.config.Privacy
	p.mu.RUnlock()

	privacy := currentPrivacy
	if currentPrivacy == nil || !reflect.DeepEqual(currentPrivacyConfig, config.Privacy) {
		privacy, err = loadPrivacyEngine(ctx, config.Privacy, host)
		if err != nil {
			closeDatabases(databases)

			return moduleConfig{}, geoDatabases{}, nil, err
		}
	}

	return config, databases, privacy, nil
}

// swapState publishes validated GeoIP and privacy state as one lifecycle transition.
func (p *Plugin) swapState(ctx context.Context, config moduleConfig, databases geoDatabases, privacy *privacyEngine, restartRefresh bool) {
	p.mu.Lock()
	p.privacy = privacy
	privacyEntries := p.privacyEntries
	p.mu.Unlock()

	if privacyEntries != nil && privacy != nil {
		privacyEntries.Set(ctx, float64(privacy.Records()))
	}

	p.swapDatabases(ctx, config, databases, restartRefresh)
}

// swapDatabases publishes validated databases and optionally restarts refresh work.
func (p *Plugin) swapDatabases(ctx context.Context, config moduleConfig, databases geoDatabases, restartRefresh bool) {
	nextOwner := newGeoDatabaseOwner(databases)

	p.mu.Lock()
	oldOwner := p.databaseOwner

	p.config = config
	p.databaseOwner = nextOwner

	if config.ASNLookup.Enabled {
		if p.asnLookup == nil || restartRefresh {
			p.asnLookup = newASNLookupService()
		}
	} else {
		p.asnLookup = nil
	}

	if !config.ASNRegistry.Enabled {
		p.asnRegistry = nil
	}

	if restartRefresh {
		p.startWorkersLocked()
	}

	recordGauge := p.recordGauge
	logger := p.logger
	p.mu.Unlock()

	oldOwner.Retire()

	if recordGauge != nil {
		recordGauge.Set(ctx, float64(databases.Records()), pluginapi.LabelValue{Name: metricLabelState, Value: metricStateLoaded})
	}

	if logger != nil {
		logger.Info(
			ctx,
			"geoip database loaded",
			pluginapi.LogField{Key: "records", Value: databases.PrimaryRecords()},
			pluginapi.LogField{Key: "asn_records", Value: databases.ASNRecords()},
		)
	}
}

// currentConfig returns the config snapshot and whether a database is loaded.
func (p *Plugin) currentConfig() (moduleConfig, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config, p.databaseOwner.Ready()
}

type geoLookupResources struct {
	lease       *geoDatabaseLease
	tracer      pluginapi.Tracer
	asnLookup   *asnLookupService
	asnRegistry *asnRegistrySnapshot
}

// acquireLookupResources snapshots request resources and leases replaceable databases.
func (p *Plugin) acquireLookupResources() (*geoLookupResources, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	lease, ready := p.databaseOwner.Acquire()
	if !ready {
		return nil, false
	}

	return &geoLookupResources{
		lease:       lease,
		tracer:      p.tracer,
		asnLookup:   p.asnLookup,
		asnRegistry: p.asnRegistry,
	}, true
}

// lookupRecord runs database and ASN lookups without retaining the plugin state lock.
func (p *Plugin) lookupRecord(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	resources, ready := p.acquireLookupResources()
	if !ready {
		return geoRecord{}, false, fmt.Errorf("geoip database is not loaded")
	}
	defer resources.lease.Release()

	return resources.lookupRecord(ctx, addr)
}

// lookupRecord executes the immutable database and ASN enrichment chain.
func (r *geoLookupResources) lookupRecord(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	databases := r.lease.databases

	record, matched, err := traceGeoIPLookup(ctx, r.tracer, spanGeoIPPrimaryDatabaseLookup, func(spanCtx context.Context) (geoRecord, bool, error) {
		return databases.primary.Lookup(spanCtx, addr)
	})
	if err != nil || !matched {
		return record, matched, err
	}

	if err := r.enrichASNLookup(ctx, addr, &record); err != nil {
		return record, matched, err
	}

	if err := r.enrichASNDatabase(ctx, addr, &record); err != nil {
		return record, matched, err
	}

	r.enrichASNRegistry(ctx, &record)

	return record, matched, nil
}

// enrichASNLookup adds local routing snapshot data when configured.
func (r *geoLookupResources) enrichASNLookup(ctx context.Context, addr netip.Addr, record *geoRecord) error {
	if r.asnLookup == nil {
		return nil
	}

	asnRecord, matched, err := traceGeoIPLookup(ctx, r.tracer, spanGeoIPASNRoutingLookup, func(spanCtx context.Context) (geoRecord, bool, error) {
		return r.asnLookup.Lookup(spanCtx, addr)
	})
	if err != nil {
		return err
	}

	if matched {
		mergeASNLookupRecord(record, asnRecord)
	}

	return nil
}

// enrichASNDatabase adds secondary ASN database data when configured.
func (r *geoLookupResources) enrichASNDatabase(ctx context.Context, addr netip.Addr, record *geoRecord) error {
	database := r.lease.databases.asn
	if database == nil {
		return nil
	}

	asnRecord, matched, err := traceGeoIPLookup(ctx, r.tracer, spanGeoIPASNDatabaseLookup, func(spanCtx context.Context) (geoRecord, bool, error) {
		return database.Lookup(spanCtx, addr)
	})
	if err != nil {
		return err
	}

	if matched {
		mergeASNDatabaseRecord(record, asnRecord)
	}

	return nil
}

// enrichASNRegistry adds delegated registry metadata for a resolved ASN.
func (r *geoLookupResources) enrichASNRegistry(ctx context.Context, record *geoRecord) {
	if record.ASN <= 0 || r.asnRegistry == nil {
		return
	}

	asnRecord, matched, _ := traceGeoIPLookup(ctx, r.tracer, spanGeoIPASNRegistryLookup, func(context.Context) (asnRegistryRecord, bool, error) {
		registryRecord, found := r.asnRegistry.Lookup(record.ASN)

		return registryRecord, found, nil
	})
	if !matched {
		return
	}

	record.ASNRegistry = asnRecord.Registry
	record.ASNCountryISO = asnRecord.CountryISO
	record.ASNStatus = asnRecord.Status

	if record.ASNAllocated == "" {
		record.ASNAllocated = asnRecord.Allocated
	}
}

// startWorkersLocked starts or replaces all optional background workers.
func (p *Plugin) startWorkersLocked() {
	p.stopWorkersLocked()
	p.startDatabaseRefreshWorkerLocked()
	p.startASNLookupWorkerLocked()
	p.startASNRegistryWorkerLocked()
	p.startPrivacyWorkersLocked()
}

// stopWorkersLocked cancels all active background workers.
func (p *Plugin) stopWorkersLocked() {
	p.stopDatabaseRefreshWorkerLocked()
	p.stopASNLookupWorkerLocked()
	p.stopASNRegistryWorkerLocked()
	p.stopPrivacyWorkersLocked()
}

// startPrivacyWorkersLocked supervises one shared-coordinator loop per remote source.
func (p *Plugin) startPrivacyWorkersLocked() {
	p.stopPrivacyWorkersLocked()

	if p.host == nil || p.privacy == nil {
		return
	}

	engine := p.privacy
	for _, coordinator := range engine.coordinators {
		workerCtx, cancel := context.WithCancel(p.host.ServiceContext())
		p.privacyCancel = append(p.privacyCancel, cancel)
		sourceID := coordinator.config.ID

		p.host.Go(workerCtx, "geoip.privacy."+sourceID, func(ctx context.Context) error {
			return p.runPrivacyRefreshLoop(ctx, engine, coordinator)
		})
	}
}

// stopPrivacyWorkersLocked cancels every active remote-source coordinator loop.
func (p *Plugin) stopPrivacyWorkersLocked() {
	for _, cancel := range p.privacyCancel {
		cancel()
	}

	p.privacyCancel = nil
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

// startASNLookupWorkerLocked starts the optional routing snapshot refresh worker.
func (p *Plugin) startASNLookupWorkerLocked() {
	if p.host == nil || !p.config.ASNLookup.Enabled {
		return
	}

	if p.asnLookup == nil {
		p.asnLookup = newASNLookupService()
	}

	workerCtx, cancel := context.WithCancel(p.host.ServiceContext())
	p.asnRouteCancel = cancel
	config := p.config.ASNLookup

	p.host.Go(workerCtx, "geoip."+componentASNLookup, func(ctx context.Context) error {
		return p.asnLookupLoop(ctx, config)
	})
}

// stopASNLookupWorkerLocked cancels the active routing snapshot worker when one exists.
func (p *Plugin) stopASNLookupWorkerLocked() {
	if p.asnRouteCancel == nil {
		return
	}

	p.asnRouteCancel()
	p.asnRouteCancel = nil
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

// asnLookupLoop refreshes routing prefixes immediately and then periodically.
func (p *Plugin) asnLookupLoop(ctx context.Context, config asnLookupConfig) error {
	p.refreshASNLookupOnce(ctx, config)

	ticker := time.NewTicker(config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.refreshASNLookupOnce(ctx, config)
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

	databases, err := p.loadDatabases(ctx, config)
	if err != nil {
		p.recordLookup(ctx, resultError, 0)
		p.logError(ctx, "geoip database refresh failed", err)

		return
	}

	p.swapDatabases(ctx, config, databases, false)
}

// refreshASNLookupOnce fetches and publishes local ASN routing prefixes.
func (p *Plugin) refreshASNLookupOnce(ctx context.Context, config asnLookupConfig) {
	snapshot, err := fetchASNLookupSnapshot(ctx, p.asnLookupFetcher(), config.SourceURLs, config.Timeout)
	if err != nil {
		p.logError(ctx, "geoip ASN routing refresh failed", err)

		return
	}

	p.mu.Lock()
	lookup := p.asnLookup

	if lookup == nil && config.Enabled {
		lookup = newASNLookupService()
		p.asnLookup = lookup
	}

	logger := p.logger
	p.mu.Unlock()

	if lookup != nil {
		lookup.Swap(snapshot)
	}

	if logger != nil {
		logger.Info(
			ctx,
			"geoip ASN routing loaded",
			pluginapi.LogField{Key: "prefixes", Value: snapshot.Records()},
			pluginapi.LogField{Key: logFieldLoadedAt, Value: snapshot.loadedAt.Format(time.RFC3339)},
		)
	}
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
			pluginapi.LogField{Key: logFieldLoadedAt, Value: snapshot.loadedAt.Format(time.RFC3339)},
		)
	}
}

// closeDatabases releases database resources and intentionally ignores close errors during replacement.
func closeDatabases(databases geoDatabases) {
	closeDatabase(databases.primary)
	closeDatabase(databases.asn)
}

// closeDatabase releases one database resource and intentionally ignores close errors during replacement.
func closeDatabase(database geoDatabase) {
	if database == nil {
		return
	}

	_ = database.Close()
}

// loadDatabases loads the required primary database and the optional ASN database.
func (p *Plugin) loadDatabases(ctx context.Context, config moduleConfig) (geoDatabases, error) {
	primary, err := p.loadDatabase(ctx, config)
	if err != nil {
		return geoDatabases{}, err
	}

	databases := geoDatabases{primary: primary}
	if config.ASNDatabasePath == "" {
		return databases, nil
	}

	asnConfig := config
	asnConfig.DatabasePath = config.ASNDatabasePath
	asnConfig.DatabaseFormat = config.ASNDatabaseFormat

	asn, err := p.loadDatabase(ctx, asnConfig)
	if err != nil {
		closeDatabases(databases)

		return geoDatabases{}, err
	}

	databases.asn = asn

	return databases, nil
}

// loadDatabase loads a configured database through the production or test loader.
func (p *Plugin) loadDatabase(ctx context.Context, config moduleConfig) (geoDatabase, error) {
	loader := p.databaseLoad
	if loader == nil {
		loader = loadConfiguredDatabase
	}

	return loader(ctx, config)
}

// asnLookupFetcher returns the production or test route fetcher.
func (p *Plugin) asnLookupFetcher() asnRouteFetcher {
	if p.asnRouteFetch != nil {
		return p.asnRouteFetch
	}

	return httpASNRouteFetcher{}
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

// registerPrivacyMetrics declares bounded lifecycle metrics without request identifiers.
func registerPrivacyMetrics(metrics pluginapi.Metrics) (pluginapi.Counter, pluginapi.Gauge, error) {
	refresh, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   metricPrivacyRefresh,
		Help:   "Privacy source refresh attempts.",
		Labels: []string{metricLabelSource, metricLabelResult},
	})
	if err != nil {
		return nil, nil, err
	}

	entries, err := metrics.Gauge(pluginapi.MetricDefinition{
		Name: metricPrivacyEntries,
		Help: "Published privacy intelligence prefix entries.",
	})
	if err != nil {
		return nil, nil, err
	}

	return refresh, entries, nil
}
