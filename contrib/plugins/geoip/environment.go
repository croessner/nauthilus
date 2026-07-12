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
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
)

const (
	factASN           = "plugin.environment.geoip.asn"
	factASNAllocated  = "plugin.environment.geoip.asn_allocated"
	factASNCountryISO = "plugin.environment.geoip.asn_country_iso"
	factASNOrg        = "plugin.environment.geoip.asn_org"
	factASNPrefix     = "plugin.environment.geoip.asn_prefix"
	factASNRegistry   = "plugin.environment.geoip.asn_registry"
	factASNStatus     = "plugin.environment.geoip.asn_status"
	factCityName      = "plugin.environment.geoip.city_name"
	factCountryISO    = "plugin.environment.geoip.country_iso"
	factCountryName   = "plugin.environment.geoip.country_name"
	factMatched       = "plugin.environment.geoip.matched"
	geoValueASN       = "asn"
	geoValueASNCC     = "asn_country_iso"
	geoValueAllocated = "asn_allocated"
	geoValueCity      = "city_name"
	geoValueCountry   = "country_iso"
	geoValueName      = "country_name"
	geoValueOrg       = "asn_org"
	geoValuePrefix    = "asn_prefix"
	geoValueRegistry  = "asn_registry"
	geoValueStatus    = "asn_status"
	logNamespaceGeoIP = "geoip"
	policyProducer    = "plugin.environment"
)

var _ pluginapi.InitTask = (*geoIPInitTask)(nil)
var _ pluginapi.EnvironmentSource = (*geoIPEnvironmentSource)(nil)

type geoIPInitTask struct {
	plugin *Plugin
}

type geoIPEnvironmentSource struct {
	plugin *Plugin
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

// Descriptor returns the dependency-scheduled environment source metadata.
func (s geoIPEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	timeout := defaultLookupTimeout

	if s.plugin != nil {
		config, _ := s.plugin.currentConfig()
		if config.LookupTimeout > 0 {
			timeout = config.LookupTimeout
		}
	}

	return pluginapi.SourceDescriptor{
		Name:        componentSource,
		Timeout:     timeout,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

// Evaluate enriches the request with local GeoIP and ASN facts.
func (s geoIPEnvironmentSource) Evaluate(ctx context.Context, request pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error) {
	if s.plugin == nil {
		return pluginapi.EnvironmentResult{}, fmt.Errorf("geoip source has no plugin")
	}

	config, ok := s.plugin.currentConfig()
	if !ok {
		return pluginapi.EnvironmentResult{}, fmt.Errorf("geoip database is not loaded")
	}

	lookupCtx, cancel := context.WithTimeout(ctx, config.LookupTimeout)
	defer cancel()

	spanCtx, span := s.startSpan(lookupCtx)
	defer span.End()

	start := time.Now()

	addr, err := netip.ParseAddr(request.Snapshot.ClientIP)
	if err != nil {
		s.plugin.recordLookup(spanCtx, resultInvalidIP, time.Since(start))

		result := missResult()
		if config.Privacy.Enabled {
			result = enrichPrivacyResult(result, privacyLookupResult{State: privacyLookupStateInvalidIP}, config.Privacy.PublicLogs)
		}

		return result, nil
	}

	record, matched, err := s.plugin.lookupRecord(spanCtx, addr)
	if err != nil {
		span.RecordError(err)
		s.plugin.recordLookup(spanCtx, resultError, time.Since(start))

		return pluginapi.EnvironmentResult{}, err
	}

	result := missResult()
	lookupResult := resultMiss

	if matched {
		result = matchResult(record, request.Snapshot.Session)
		lookupResult = resultMatched

		span.SetAttributes(
			pluginapi.TraceAttribute{Key: "geoip.matched", Value: true},
			pluginapi.TraceAttribute{Key: "geoip.country_iso", Value: record.CountryISO},
		)
	}

	if config.Privacy.Enabled {
		privacy, privacyErr := s.lookupPrivacy(spanCtx, config.Privacy, addr, record)
		if privacyErr != nil {
			span.RecordError(privacyErr)
			s.plugin.recordLookup(spanCtx, resultError, time.Since(start))

			return pluginapi.EnvironmentResult{}, privacyErr
		}

		result = enrichPrivacyResult(result, privacy, config.Privacy.PublicLogs)
		span.SetAttributes(
			pluginapi.TraceAttribute{Key: "geoip.privacy_lookup_state", Value: privacy.State},
			pluginapi.TraceAttribute{Key: "geoip.privacy_primary_class", Value: string(privacy.PrimaryClass)},
			pluginapi.TraceAttribute{Key: "geoip.privacy_stale", Value: privacy.Stale},
		)
	}

	s.plugin.recordLookup(spanCtx, lookupResult, time.Since(start))

	return result, nil
}

// lookupPrivacy evaluates the immutable privacy index within its tighter request deadline.
func (s geoIPEnvironmentSource) lookupPrivacy(ctx context.Context, config privacyConfig, addr netip.Addr, record geoRecord) (privacyLookupResult, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, config.LookupTimeout)
	defer cancel()

	if err := lookupCtx.Err(); err != nil {
		return privacyLookupResult{}, err
	}

	s.plugin.mu.RLock()
	engine := s.plugin.privacy
	s.plugin.mu.RUnlock()

	if engine == nil {
		return privacyLookupResult{State: privacyLookupStateUnavailable}, nil
	}

	result := engine.LookupWithRecord(addr, record)

	if err := lookupCtx.Err(); err != nil {
		return privacyLookupResult{}, err
	}

	return result, nil
}

// startSpan creates a component-scoped child span for request-time lookup work.
func (s geoIPEnvironmentSource) startSpan(ctx context.Context) (context.Context, pluginapi.Span) {
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
func missResult() pluginapi.EnvironmentResult {
	return pluginapi.EnvironmentResult{
		Facts: []pluginapi.PolicyFact{
			{Attribute: factMatched, Value: false},
		},
		RuntimeDelta: exchange.GeoIPRuntimeDelta(map[string]any{
			resultMatched: false,
		}),
	}
}

// matchResult returns all policy-visible and runtime-visible GeoIP data for a match.
func matchResult(record geoRecord, session string) pluginapi.EnvironmentResult {
	facts := []pluginapi.PolicyFact{
		{Attribute: factMatched, Value: true},
	}
	values := map[string]any{
		resultMatched: true,
	}
	if session != "" {
		values["guid"] = session
	}

	addStringFact(&facts, values, factCountryISO, geoValueCountry, record.CountryISO)
	addStringFact(&facts, values, factCountryName, geoValueName, record.CountryName)
	addStringFact(&facts, values, factCityName, geoValueCity, record.CityName)
	addStringFact(&facts, values, factASNOrg, geoValueOrg, record.ASNOrg)
	addStringFact(&facts, values, factASNPrefix, geoValuePrefix, record.ASNPrefix)
	addStringFact(&facts, values, factASNRegistry, geoValueRegistry, record.ASNRegistry)
	addStringFact(&facts, values, factASNCountryISO, geoValueASNCC, record.ASNCountryISO)
	addStringFact(&facts, values, factASNAllocated, geoValueAllocated, record.ASNAllocated)
	addStringFact(&facts, values, factASNStatus, geoValueStatus, record.ASNStatus)

	if record.ASN > 0 {
		facts = append(facts, pluginapi.PolicyFact{Attribute: factASN, Value: record.ASN})
		values[geoValueASN] = record.ASN
	}

	return pluginapi.EnvironmentResult{
		Logs:         publicGeoIPLogFields(record),
		Facts:        facts,
		RuntimeDelta: exchange.GeoIPRuntimeDelta(values),
	}
}

// addStringFact appends a string fact and runtime value when the value is present.
func addStringFact(facts *[]pluginapi.PolicyFact, values map[string]any, attribute string, key string, value string) {
	if value == "" {
		return
	}

	*facts = append(*facts, pluginapi.PolicyFact{Attribute: attribute, Value: value})
	values[key] = value
}

// publicGeoIPLogFields returns intentionally public GeoIP values for central request logging.
func publicGeoIPLogFields(record geoRecord) []pluginapi.LogField {
	fields := make([]pluginapi.LogField, 0, 3)
	addPublicGeoIPLogField(&fields, geoValueCountry, record.CountryISO)
	addPublicGeoIPLogField(&fields, geoValueASNCC, record.ASNCountryISO)

	if record.ASN > 0 {
		addPublicGeoIPLogField(&fields, geoValueASN, record.ASN)
	}

	return fields
}

// addPublicGeoIPLogField appends one validated public GeoIP log field.
func addPublicGeoIPLogField(fields *[]pluginapi.LogField, key string, value any) {
	if text, ok := value.(string); ok && text == "" {
		return
	}

	field, err := pluginapi.PublicPolicyFactLogField(logNamespaceGeoIP, key, value)
	if err != nil {
		return
	}

	*fields = append(*fields, field)
}

// registerPolicyAttributes declares all facts emitted by the GeoIP environment source.
func registerPolicyAttributes(registrar pluginapi.Registrar) error {
	for _, definition := range geoIPPolicyAttributes() {
		if err := registrar.RegisterPolicyAttribute(definition); err != nil {
			return err
		}
	}

	return nil
}

// geoIPPolicyAttributes returns the stable plugin policy fact definitions.
func geoIPPolicyAttributes() []pluginapi.AttributeDefinition {
	operations := []pluginapi.PolicyOperation{
		pluginapi.PolicyOperationAuthenticate,
		pluginapi.PolicyOperationLookupIdentity,
	}

	return []pluginapi.AttributeDefinition{
		environmentAttribute(factMatched, pluginapi.AttributeTypeBool, "Whether the client address matched the GeoIP database.", operations),
		environmentAttribute(factCountryISO, pluginapi.AttributeTypeString, "ISO 3166 country code from the GeoIP database.", operations),
		environmentAttribute(factCountryName, pluginapi.AttributeTypeString, "Country name from the GeoIP database.", operations),
		environmentAttribute(factCityName, pluginapi.AttributeTypeString, "City name from the GeoIP database.", operations),
		environmentAttribute(factASN, pluginapi.AttributeTypeNumber, "Autonomous system number from the GeoIP data or local ASN routing snapshot.", operations),
		environmentAttribute(factASNOrg, pluginapi.AttributeTypeString, "Autonomous system organization from the GeoIP data.", operations),
		environmentAttribute(factASNPrefix, pluginapi.AttributeTypeString, "Network prefix returned by the local ASN routing snapshot.", operations),
		environmentAttribute(factASNRegistry, pluginapi.AttributeTypeString, "RIR registry that allocated or assigned the ASN.", operations),
		environmentAttribute(factASNCountryISO, pluginapi.AttributeTypeString, "Country code from delegated RIR ASN registry data.", operations),
		environmentAttribute(factASNAllocated, pluginapi.AttributeTypeString, "Allocation date from delegated RIR ASN registry data.", operations),
		environmentAttribute(factASNStatus, pluginapi.AttributeTypeString, "Allocation status from delegated RIR ASN registry data.", operations),
		environmentAttribute(factPrivacyLookupState, pluginapi.AttributeTypeString, "Privacy intelligence lookup state.", operations),
		environmentAttribute(factPrivacyDetected, pluginapi.AttributeTypeBool, "Whether retained privacy evidence other than hosting matched.", operations),
		environmentAttribute(factPrivacyClasses, pluginapi.AttributeTypeStringList, "Deterministic retained privacy classifications.", operations),
		environmentAttribute(factPrivacyPrimaryClass, pluginapi.AttributeTypeString, "Highest-authority privacy presentation class.", operations),
		environmentAttribute(factPrivacyConfidence, pluginapi.AttributeTypeNumber, "Evidence confidence for the primary privacy class.", operations),
		environmentAttribute(factPrivacySourceAuthorities, pluginapi.AttributeTypeStringList, "Contributing privacy evidence authority categories.", operations),
		environmentAttribute(factPrivacyDataStale, pluginapi.AttributeTypeBool, "Whether required or contributing privacy snapshots are stale.", operations),
		environmentAttribute(factPrivacyDataAgeSeconds, pluginapi.AttributeTypeNumber, "Age in seconds of the oldest contributing privacy snapshot.", operations),
		environmentAttribute(factIsTorExitNode, pluginapi.AttributeTypeBool, "Whether official Tor exit evidence matched.", operations),
		environmentAttribute(factIsKnownVPNExit, pluginapi.AttributeTypeBool, "Whether official provider or operator VPN exit evidence matched.", operations),
		environmentAttribute(factIsCommunityVPNExit, pluginapi.AttributeTypeBool, "Whether community VPN exit evidence matched.", operations),
		environmentAttribute(factIsPublicProxy, pluginapi.AttributeTypeBool, "Whether attributed public proxy evidence matched.", operations),
		environmentAttribute(factIsPrivacyRelay, pluginapi.AttributeTypeBool, "Whether another attributed privacy relay matched.", operations),
		environmentAttribute(factIsHostingNetwork, pluginapi.AttributeTypeBool, "Whether hosting or cloud network evidence matched.", operations),
		environmentAttribute(factIsSharedEgress, pluginapi.AttributeTypeBool, "Whether operator-approved shared public egress evidence matched.", operations),
	}
}

// environmentAttribute builds one plugin.environment policy attribute definition.
func environmentAttribute(
	id string,
	valueType pluginapi.AttributeType,
	description string,
	operations []pluginapi.PolicyOperation,
) pluginapi.AttributeDefinition {
	return pluginapi.AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         pluginapi.PolicyStagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{policyProducer},
		Category:      pluginapi.AttributeCategoryEnvironment,
		Type:          valueType,
	}
}

type noopSpan struct{}

// AddEvent discards span events when no tracer is configured.
func (noopSpan) AddEvent(string, ...pluginapi.TraceAttribute) {}

// SetAttributes discards span attributes when no tracer is configured.
func (noopSpan) SetAttributes(...pluginapi.TraceAttribute) {}

// RecordError discards span errors when no tracer is configured.
func (noopSpan) RecordError(error) {}

// End completes the no-op span.
func (noopSpan) End() {}
