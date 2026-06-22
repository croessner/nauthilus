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
	policyProducer    = "plugin.environment"
	runtimeKey        = "plugin.environment.geoip"
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

	config, databases, err := t.plugin.loadConfigAndDatabases(ctx, init.Config)
	if err != nil {
		return err
	}

	t.plugin.swapDatabases(ctx, config, databases, true)

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

		return missResult(), nil
	}

	record, matched, err := s.plugin.lookupRecord(spanCtx, addr)
	if err != nil {
		span.RecordError(err)
		s.plugin.recordLookup(spanCtx, resultError, time.Since(start))

		return pluginapi.EnvironmentResult{}, err
	}

	if !matched {
		s.plugin.recordLookup(spanCtx, resultMiss, time.Since(start))

		return missResult(), nil
	}

	span.SetAttributes(
		pluginapi.TraceAttribute{Key: "geoip.matched", Value: true},
		pluginapi.TraceAttribute{Key: "geoip.country_iso", Value: record.CountryISO},
	)
	s.plugin.recordLookup(spanCtx, resultMatched, time.Since(start))

	return matchResult(record), nil
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
		RuntimeDelta: pluginapi.RuntimeDelta{
			Set: map[string]any{
				runtimeKey: map[string]any{
					resultMatched: false,
				},
			},
		},
	}
}

// matchResult returns all policy-visible and runtime-visible GeoIP data for a match.
func matchResult(record geoRecord) pluginapi.EnvironmentResult {
	facts := []pluginapi.PolicyFact{
		{Attribute: factMatched, Value: true},
	}
	values := map[string]any{
		resultMatched: true,
	}

	addStringFact(&facts, values, factCountryISO, "country_iso", record.CountryISO)
	addStringFact(&facts, values, factCountryName, "country_name", record.CountryName)
	addStringFact(&facts, values, factCityName, "city_name", record.CityName)
	addStringFact(&facts, values, factASNOrg, "asn_org", record.ASNOrg)
	addStringFact(&facts, values, factASNPrefix, "asn_prefix", record.ASNPrefix)
	addStringFact(&facts, values, factASNRegistry, "asn_registry", record.ASNRegistry)
	addStringFact(&facts, values, factASNCountryISO, "asn_country_iso", record.ASNCountryISO)
	addStringFact(&facts, values, factASNAllocated, "asn_allocated", record.ASNAllocated)
	addStringFact(&facts, values, factASNStatus, "asn_status", record.ASNStatus)

	if record.ASN > 0 {
		facts = append(facts, pluginapi.PolicyFact{Attribute: factASN, Value: record.ASN})
		values["asn"] = record.ASN
	}

	return pluginapi.EnvironmentResult{
		Facts: facts,
		RuntimeDelta: pluginapi.RuntimeDelta{
			Set: map[string]any{
				runtimeKey: values,
			},
		},
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
