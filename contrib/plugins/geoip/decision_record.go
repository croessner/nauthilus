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
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// collectRecords runs the same local lookup for each admitted matching IP and preserves only configured correlations.
func (p geoIPDecisionFactProvider) collectRecords(ctx context.Context, request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	records, ok := p.inputRecords(request)
	if !ok {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	output := make([]pluginapi.DecisionRecord, 0, len(records))
	for _, record := range records {
		values, matches := p.recordInput(record)
		if !matches {
			continue
		}

		address, err := parseGeoIPAddress(values[p.binding.input.Records.IPField])
		if err != nil {
			return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
		}

		result, err := (geoIPLookupService{plugin: p.plugin}).evaluateClientIP(ctx, address.String())
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		for _, name := range p.binding.input.Records.CorrelationFields {
			value, exists := values[name]
			if !exists {
				return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
			}

			result.Facts = append(result.Facts, geoIPLookupFact{Name: name, Value: value})
		}

		owned, err := geoIPLookupRecord(result)
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		output = append(output, owned)
	}

	list, err := pluginapi.NewDecisionRecordList(output)
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	return pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{Name: p.binding.outputFact, Value: value}}}, nil
}

// inputRecords selects only the exact target, admitted fact, category, and bounded record kind.
func (p geoIPDecisionFactProvider) inputRecords(request pluginapi.DecisionFactRequest) ([]pluginapi.DecisionRecord, bool) {
	if !slices.Contains(p.binding.descriptor.Targets, request.Target()) {
		return nil, false
	}

	for _, fact := range request.Facts() {
		if fact.ID() != p.binding.input.Fact {
			continue
		}

		list, valid := fact.Value().Records()
		if !valid || fact.Category() != p.binding.input.Category || len(list.Records()) > maximumGeoIPRecords {
			return nil, false
		}

		return list.Records(), true
	}

	return nil, false
}

// recordInput selects rows with exact configured string predicates without accepting caller geographic claims.
func (p geoIPDecisionFactProvider) recordInput(record pluginapi.DecisionRecord) (map[string]string, bool) {
	values := make(map[string]string)

	for _, field := range record.Fields() {
		if value, valid := field.Value().Value().StringValue(); valid {
			values[field.Name()] = value
		}
	}

	for name, expected := range p.binding.input.Records.Match {
		if values[name] != expected {
			return nil, false
		}
	}

	return values, true
}

// geoIPLookupRecord reuses the scalar conversion and public record constructors for one closed result.
func geoIPLookupRecord(result geoIPLookupResult) (pluginapi.DecisionRecord, error) {
	fields := make([]pluginapi.DecisionRecordField, 0, len(result.Facts))
	for _, fact := range result.Facts {
		value, err := geoIPDecisionValue(fact.Value)
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		leaf, err := pluginapi.NewDecisionRecordFieldValue(value)
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		field, err := pluginapi.NewDecisionRecordField(fact.Name, leaf)
		if err != nil {
			return pluginapi.DecisionRecord{}, fmt.Errorf("geoip record field: %w", err)
		}

		fields = append(fields, field)
	}

	return pluginapi.NewDecisionRecord(fields)
}
