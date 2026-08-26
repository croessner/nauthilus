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
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	factASN           = "asn"
	factASNAllocated  = "asn_allocated"
	factASNCountryISO = "asn_country_iso"
	factASNOrg        = "asn_org"
	factASNPrefix     = "asn_prefix"
	factASNRegistry   = "asn_registry"
	factASNStatus     = "asn_status"
	factCityName      = "city_name"
	factCountryISO    = "country_iso"
	factCountryName   = "country_name"
	factMatched       = "matched"
)

var _ pluginapi.InitTask = (*geoIPInitTask)(nil)

type geoIPInitTask struct {
	plugin *Plugin
}

type geoIPLookupService struct {
	plugin *Plugin
}

type geoIPLookupFact struct {
	Value any
	Name  string
}

type geoIPLookupResult struct {
	Facts []geoIPLookupFact
}

// Name returns the lifecycle component name for database loading.
func (t geoIPInitTask) Name() string {
	return componentDatabase
}

// Start loads the configured local database before request-time execution begins.
func (t geoIPInitTask) Start(ctx context.Context, init pluginapi.InitContext) error {
	if t.plugin == nil {
		return fmt.Errorf("geoip init task has no plugin")
	}

	config, databases, privacy, err := t.plugin.loadConfigAndDatabases(ctx, init.Config)
	if err != nil {
		return err
	}

	t.plugin.swapState(ctx, config, databases, privacy, true)

	return nil
}

// Stop cancels optional database refresh work.
func (t geoIPInitTask) Stop(context.Context) error {
	if t.plugin == nil {
		return nil
	}

	t.plugin.mu.Lock()
	t.plugin.stopWorkersLocked()
	t.plugin.mu.Unlock()

	return nil
}

// evaluateClientIP executes the internal redacted lookup for the generic Policy provider.
func (s geoIPLookupService) evaluateClientIP(
	ctx context.Context,
	clientIP string,
) (geoIPLookupResult, error) {
	if s.plugin == nil {
		return geoIPLookupResult{}, fmt.Errorf("geoip lookup has no plugin")
	}

	config, ok := s.plugin.currentConfig()
	if !ok {
		return geoIPLookupResult{}, fmt.Errorf("geoip database is not loaded")
	}

	lookupCtx, cancel := context.WithTimeout(ctx, config.LookupTimeout)
	defer cancel()

	spanCtx, span := s.startSpan(lookupCtx)
	defer span.End()

	start := time.Now()

	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return s.invalidClientIPResult(spanCtx, config, start), nil
	}

	result, record, lookupResult, err := s.lookupGeoIPResult(spanCtx, span, addr, start)
	if err != nil {
		return geoIPLookupResult{}, err
	}

	if config.Privacy.Enabled {
		privacy, privacyErr := s.lookupPrivacy(spanCtx, config.Privacy, addr, record)
		if privacyErr != nil {
			span.RecordError(privacyErr)
			s.plugin.recordLookup(spanCtx, resultError, time.Since(start))

			return geoIPLookupResult{}, privacyErr
		}

		result = enrichPrivacyResult(result, privacy)
		span.SetAttributes(
			pluginapi.TraceAttribute{Key: "geoip.privacy_lookup_state", Value: privacy.State},
			pluginapi.TraceAttribute{Key: "geoip.privacy_primary_class", Value: string(privacy.PrimaryClass)},
			pluginapi.TraceAttribute{Key: "geoip.privacy_stale", Value: privacy.Stale},
		)
	}

	s.plugin.recordLookup(spanCtx, lookupResult, time.Since(start))

	return result, nil
}

// invalidClientIPResult records one invalid request and preserves the configured privacy fact vocabulary.
func (s geoIPLookupService) invalidClientIPResult(
	ctx context.Context,
	config moduleConfig,
	start time.Time,
) geoIPLookupResult {
	s.plugin.recordLookup(ctx, resultInvalidIP, time.Since(start))

	result := missResult()
	if config.Privacy.Enabled {
		result = enrichPrivacyResult(result, privacyLookupResult{State: privacyLookupStateInvalidIP})
	}

	return result
}

// lookupGeoIPResult resolves the base database record and records lookup failures on the active span.
func (s geoIPLookupService) lookupGeoIPResult(
	ctx context.Context,
	span pluginapi.Span,
	addr netip.Addr,
	start time.Time,
) (geoIPLookupResult, geoRecord, string, error) {
	record, matched, err := s.plugin.lookupRecord(ctx, addr)
	if err != nil {
		span.RecordError(err)
		s.plugin.recordLookup(ctx, resultError, time.Since(start))

		return geoIPLookupResult{}, geoRecord{}, "", err
	}

	if !matched {
		return missResult(), record, resultMiss, nil
	}

	span.SetAttributes(
		pluginapi.TraceAttribute{Key: "geoip.matched", Value: true},
		pluginapi.TraceAttribute{Key: "geoip.country_iso", Value: record.CountryISO},
	)

	return matchResult(record), record, resultMatched, nil
}

// lookupPrivacy evaluates the immutable privacy index within its tighter request deadline.
func (s geoIPLookupService) lookupPrivacy(ctx context.Context, config privacyConfig, addr netip.Addr, record geoRecord) (privacyLookupResult, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, config.LookupTimeout)
	defer cancel()

	if err := lookupCtx.Err(); err != nil {
		return privacyLookupResult{}, err
	}

	s.plugin.mu.RLock()
	engine := s.plugin.privacy
	tracer := s.plugin.tracer
	s.plugin.mu.RUnlock()

	result, _, err := traceGeoIPLookup(lookupCtx, tracer, spanGeoIPPrivacyLookup, func(spanCtx context.Context) (privacyLookupResult, bool, error) {
		if engine == nil {
			return privacyLookupResult{State: privacyLookupStateUnavailable}, false, nil
		}

		lookup := engine.LookupWithRecord(addr, record)

		if lookupErr := spanCtx.Err(); lookupErr != nil {
			return privacyLookupResult{}, false, lookupErr
		}

		return lookup, len(lookup.Classes) > 0, nil
	})

	return result, err
}

// startSpan creates a component-scoped child span for request-time lookup work.
func (s geoIPLookupService) startSpan(ctx context.Context) (context.Context, pluginapi.Span) {
	s.plugin.mu.RLock()
	tracer := s.plugin.tracer
	s.plugin.mu.RUnlock()

	if tracer == nil {
		return ctx, noopSpan{}
	}

	return tracer.Start(
		ctx,
		"geoip.environment.evaluate",
		pluginapi.TraceAttribute{Key: traceAttrModule, Value: pluginName},
		pluginapi.TraceAttribute{Key: traceAttrComponent, Value: componentSource},
	)
}

// missResult returns a non-triggering result for unknown or unparseable client IPs.
func missResult() geoIPLookupResult {
	return geoIPLookupResult{
		Facts: []geoIPLookupFact{
			{Name: factMatched, Value: false},
		},
	}
}

// matchResult returns all generic GeoIP facts for a match.
func matchResult(record geoRecord) geoIPLookupResult {
	facts := []geoIPLookupFact{{Name: factMatched, Value: true}}

	addStringFact(&facts, factCountryISO, record.CountryISO)
	addStringFact(&facts, factCountryName, record.CountryName)
	addStringFact(&facts, factCityName, record.CityName)
	addStringFact(&facts, factASNOrg, record.ASNOrg)
	addStringFact(&facts, factASNPrefix, record.ASNPrefix)
	addStringFact(&facts, factASNRegistry, record.ASNRegistry)
	addStringFact(&facts, factASNCountryISO, record.ASNCountryISO)
	addStringFact(&facts, factASNAllocated, record.ASNAllocated)
	addStringFact(&facts, factASNStatus, record.ASNStatus)

	if record.ASN > 0 {
		facts = append(facts, geoIPLookupFact{Name: factASN, Value: record.ASN})
	}

	return geoIPLookupResult{Facts: facts}
}

// addStringFact appends one generic string fact when the value is present.
func addStringFact(facts *[]geoIPLookupFact, name string, value string) {
	if value == "" {
		return
	}

	*facts = append(*facts, geoIPLookupFact{Name: name, Value: value})
}

type noopSpan struct{}

// AddEvent discards span events when no tracer is configured.
func (noopSpan) AddEvent(string, ...pluginapi.TraceAttribute) {}

// SetAttributes discards span attributes when no tracer is configured.
func (noopSpan) SetAttributes(...pluginapi.TraceAttribute) {}

// RecordError discards span errors when no tracer is configured.
func (noopSpan) RecordError(error) {}

// SetStatus records no status when tracing is unavailable.
func (noopSpan) SetStatus(pluginapi.SpanStatus, string) {}

// End completes the no-op span.
func (noopSpan) End() {}
