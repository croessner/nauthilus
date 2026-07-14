// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

type privacyEngine struct {
	coordinators []*privacySourceCoordinator
	state        *privacyLookupState
	now          func() time.Time
	indexBuilder func([]privacySnapshot) *privacyLookupIndex
	mu           sync.RWMutex
	publishMu    sync.Mutex
}

type privacyLookupState struct {
	snapshots  map[string]privacySnapshot
	overrides  []privacyOverrideConfig
	required   map[string]struct{}
	index      *privacyLookupIndex
	hosting    privacyHostingConfig
	configured int
}

// loadPrivacyEngine builds every initial source candidate before publishing a lookup engine.
func loadPrivacyEngine(ctx context.Context, config privacyConfig, host pluginapi.Host) (*privacyEngine, error) {
	if !config.Enabled {
		return nil, nil
	}

	configured := len(config.Sources)
	if config.Hosting.Enabled {
		configured++
	}

	engine := &privacyEngine{
		state: &privacyLookupState{
			snapshots:  make(map[string]privacySnapshot),
			overrides:  append([]privacyOverrideConfig(nil), config.Overrides...),
			required:   make(map[string]struct{}),
			hosting:    config.Hosting,
			configured: configured,
		},
		now:          time.Now,
		indexBuilder: newPrivacyLookupIndex,
	}
	semaphore := make(chan struct{}, config.Refresh.MaxConcurrentDownloads)

	for _, source := range config.Sources {
		if err := engine.loadSource(ctx, source, config.Refresh, host, semaphore); err != nil {
			return nil, err
		}
	}

	engine.addHostingSnapshot(config.Hosting)
	engine.state.index = engine.buildIndex(engine.state.snapshots)

	return engine, nil
}

// loadSource initializes one required or optional local or remote source.
func (e *privacyEngine) loadSource(ctx context.Context, source privacySourceConfig, refresh privacyRefreshConfig, host pluginapi.Host, semaphore chan struct{}) error {
	if source.Required {
		e.state.required[source.ID] = struct{}{}
	}

	if source.Path != "" {
		return e.loadLocalSource(ctx, source)
	}

	return e.loadRemoteSource(ctx, source, refresh, host, semaphore)
}

// loadLocalSource publishes one lifecycle-loaded local snapshot.
func (e *privacyEngine) loadLocalSource(ctx context.Context, source privacySourceConfig) error {
	snapshot, err := loadLocalPrivacySnapshot(ctx, source, e.now())
	if err != nil {
		if source.Required {
			return err
		}

		return nil
	}

	e.state.snapshots[source.ID] = snapshot

	return nil
}

// loadRemoteSource restores cache state and schedules or performs initial refresh.
func (e *privacyEngine) loadRemoteSource(ctx context.Context, source privacySourceConfig, refresh privacyRefreshConfig, host pluginapi.Host, semaphore chan struct{}) error {
	if host == nil {
		if source.Required {
			return fmt.Errorf("required privacy source %q has no host HTTP facade", source.ID)
		}

		return nil
	}

	coordinator := newPrivacySourceCoordinator(source, host.HTTP("privacy"), semaphore)
	cacheErr := coordinator.LoadCache()

	cached := coordinator.Snapshot()
	if cacheErr == nil && cached.SourceID != "" {
		e.state.snapshots[source.ID] = cached
	}

	if privacyCacheCanDefer(source, cached, e.now()) {
		coordinator.DeferUntil(e.now().Add(privacyRandomJitter(refresh.StartupJitter)))
		e.coordinators = append(e.coordinators, coordinator)

		return nil
	}

	refreshErr := coordinator.Refresh(ctx)
	if refreshErr == nil {
		e.state.snapshots[source.ID] = coordinator.Snapshot()
	} else if source.Required && coordinator.Snapshot().SourceID == "" {
		return fmt.Errorf("load required privacy source %q: %w", source.ID, refreshErr)
	}

	e.coordinators = append(e.coordinators, coordinator)

	return nil
}

// privacyCacheCanDefer reports whether startup may wait for background refresh.
func privacyCacheCanDefer(source privacySourceConfig, cached privacySnapshot, now time.Time) bool {
	if cached.SourceID == "" {
		return !source.Required
	}

	return cached.MaxAge > 0 && now.Sub(cached.ConfirmedAt) <= cached.MaxAge
}

// loadLocalPrivacySnapshot reads and validates one operator-managed file during lifecycle work.
func loadLocalPrivacySnapshot(ctx context.Context, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return privacySnapshot{}, err
	}

	raw, err := os.ReadFile(config.Path)
	if err != nil {
		return privacySnapshot{}, fmt.Errorf("read privacy source %q: %w", config.ID, err)
	}

	if int64(len(raw)) > config.MaxDownloadBytes {
		return privacySnapshot{}, fmt.Errorf("privacy source %q exceeds size limit", config.ID)
	}

	return parsePrivacySnapshotCandidate(raw, config, now)
}

// Lookup evaluates only the immutable in-memory index and applies operator overrides locally.
func (e *privacyEngine) Lookup(addr netip.Addr) privacyLookupResult {
	return e.LookupWithRecord(addr, geoRecord{})
}

// LookupWithRecord evaluates address evidence plus derived ASN and organization hosting rules.
func (e *privacyEngine) LookupWithRecord(addr netip.Addr, record geoRecord) privacyLookupResult {
	if e == nil {
		return privacyLookupResult{State: privacyLookupStateNoSources}
	}

	state := e.currentState()
	if state == nil {
		return privacyLookupResult{State: privacyLookupStateNoSources}
	}

	if state.configured == 0 && len(state.snapshots) == 0 {
		return privacyLookupResult{State: privacyLookupStateNoSources}
	}

	if len(state.snapshots) == 0 {
		return privacyLookupResult{State: privacyLookupStateUnavailable}
	}

	now := e.now()
	evidence := state.index.Lookup(addr)
	evidence = append(evidence, state.hostingEvidence(addr, record, now)...)
	requiredStale := state.requiredSourceStale(now)

	result := mergePrivacyEvidence(applyPrivacyOverrides(addr, evidence, state.overrides, now), now)

	result.State = privacyLookupStateEvaluated
	if result.Stale || requiredStale {
		result.State = privacyLookupStateStale
		result.Stale = true
	}

	return result
}

// currentState returns the immutable request-side privacy state.
func (e *privacyEngine) currentState() *privacyLookupState {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.state
}

// hostingEvidence derives hosting classification without creating VPN evidence.
func (s *privacyLookupState) hostingEvidence(addr netip.Addr, record geoRecord, now time.Time) []privacyEvidence {
	if !s.hosting.Enabled || !s.hosting.matches(record) {
		return nil
	}

	return []privacyEvidence{{
		GeneratedAt: now,
		ConfirmedAt: now,
		Prefix:      netip.PrefixFrom(addr, addr.BitLen()),
		Class:       privacyClassHosting,
		Authority:   privacyAuthorityDerived,
		SourceID:    string(privacyClassHosting),
		MaxAge:      defaultPrivacySourceMaxAge,
		Confidence:  s.hosting.Confidence,
	}}
}

// requiredSourceStale reports stale or missing required source state.
func (s *privacyLookupState) requiredSourceStale(now time.Time) bool {
	for sourceID := range s.required {
		snapshot, found := s.snapshots[sourceID]
		if !found || (snapshot.MaxAge > 0 && now.Sub(snapshot.ConfirmedAt) > snapshot.MaxAge) {
			return true
		}
	}

	return false
}

// Records returns the combined immutable snapshot entry count for bounded metrics.
func (e *privacyEngine) Records() int {
	if e == nil {
		return 0
	}

	state := e.currentState()
	if state == nil {
		return 0
	}

	records := 0
	for _, snapshot := range state.snapshots {
		records += len(snapshot.Entries)
	}

	return records
}

// Refresh updates one remote source and atomically rebuilds the combined immutable index.
func (e *privacyEngine) Refresh(ctx context.Context, coordinator *privacySourceCoordinator) error {
	if err := coordinator.Refresh(ctx); err != nil {
		return err
	}

	snapshot := coordinator.Snapshot()

	e.publishMu.Lock()
	defer e.publishMu.Unlock()

	current := e.currentState()
	next := current.withSnapshot(snapshot, e.buildIndex)

	e.mu.Lock()
	e.state = next
	e.mu.Unlock()

	return nil
}

// addHostingSnapshot represents configured CIDRs as derived hosting evidence only.
func (e *privacyEngine) addHostingSnapshot(config privacyHostingConfig) {
	if !config.Enabled {
		return
	}

	now := e.now()
	entries := make([]privacyEntry, 0, len(config.CIDRs))

	for _, prefix := range config.CIDRs {
		entries = append(entries, privacyEntry{Prefix: prefix, Class: privacyClassHosting, Confidence: config.Confidence})
	}

	e.state.snapshots[string(privacyClassHosting)] = privacySnapshot{Entries: entries, SourceID: string(privacyClassHosting), Kind: privacySourceKindNormalized, Authority: privacyAuthorityDerived, GeneratedAt: now, ConfirmedAt: now, LoadedAt: now, MaxAge: defaultPrivacySourceMaxAge}
}

// buildIndex builds a complete immutable index through the configured implementation.
func (e *privacyEngine) buildIndex(snapshots map[string]privacySnapshot) *privacyLookupIndex {
	builder := e.indexBuilder
	if builder == nil {
		builder = newPrivacyLookupIndex
	}

	values := make([]privacySnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		values = append(values, snapshot)
	}

	return builder(values)
}

// withSnapshot builds a replacement state without mutating the published state.
func (s *privacyLookupState) withSnapshot(snapshot privacySnapshot, build func(map[string]privacySnapshot) *privacyLookupIndex) *privacyLookupState {
	snapshots := make(map[string]privacySnapshot, len(s.snapshots)+1)
	maps.Copy(snapshots, s.snapshots)

	snapshots[snapshot.SourceID] = snapshot

	return &privacyLookupState{
		snapshots:  snapshots,
		overrides:  s.overrides,
		required:   s.required,
		index:      build(snapshots),
		hosting:    s.hosting,
		configured: s.configured,
	}
}

// runPrivacyRefreshLoop schedules remote refreshes without blocking request-time lookup.
func (p *Plugin) runPrivacyRefreshLoop(ctx context.Context, engine *privacyEngine, coordinator *privacySourceCoordinator) error {
	for {
		next := coordinator.NextAttempt()
		if next.IsZero() {
			next = time.Now().Add(coordinator.config.RefreshInterval)
		}

		timer := time.NewTimer(max(time.Until(next), 0))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			return nil
		case <-timer.C:
			err := engine.Refresh(ctx, coordinator)
			p.recordPrivacyRefresh(ctx, coordinator.config.ID, err)

			if err != nil {
				p.logPrivacyRefreshFailure(ctx, coordinator.config.ID)
			}
		}
	}
}

// logPrivacyRefreshFailure reports only the validated source ID, never URL or transport details.
func (p *Plugin) logPrivacyRefreshFailure(ctx context.Context, source string) {
	p.mu.RLock()
	logger := p.logger
	p.mu.RUnlock()

	if logger != nil {
		logger.Error(ctx, "geoip privacy source refresh failed", pluginapi.LogField{Key: metricLabelSource, Value: source})
	}
}

// recordPrivacyRefresh records bounded source and result labels after lifecycle refresh work.
func (p *Plugin) recordPrivacyRefresh(ctx context.Context, source string, err error) {
	result := "success"
	if err != nil {
		result = resultError
	}

	p.mu.RLock()
	refresh := p.privacyRefresh
	entries := p.privacyEntries
	engine := p.privacy
	p.mu.RUnlock()

	if refresh != nil {
		refresh.Add(ctx, 1,
			pluginapi.LabelValue{Name: metricLabelSource, Value: source},
			pluginapi.LabelValue{Name: metricLabelResult, Value: result},
		)
	}

	if entries != nil && engine != nil {
		entries.Set(ctx, float64(engine.Records()))
	}
}
