// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"fmt"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"slices"
	"sort"
)

const (
	geoIPRecordsSchema  = "geoip.records.v1"
	maximumGeoIPRecords = 8
)

type rawDecisionRecordInput struct {
	Match             map[string]string `mapstructure:"match"`
	CorrelationFields []string          `mapstructure:"correlation_fields"`
	IPField           string            `mapstructure:"ip_field"`
}

// compileDecisionInputOutput binds scalar or correlated records to one closed output vocabulary.
func compileDecisionInputOutput(raw rawDecisionBinding, descriptor *pluginapi.DecisionFactProviderDescriptor) error {
	if raw.Input.Records == nil {
		if raw.OutputSchema != geoIPFactsSchema || raw.OutputFact != "" {
			return fmt.Errorf("scalar binding requires geoip.facts.v1 without output_fact")
		}

		return nil
	}

	if raw.OutputSchema != geoIPRecordsSchema || raw.OutputFact == "" {
		return fmt.Errorf("record binding requires geoip.records.v1 and one output_fact")
	}

	fields, err := compileDecisionRecordFields(*raw.Input.Records)
	if err != nil {
		return err
	}

	descriptor.Inputs[0].Kind = pluginapi.DecisionValueKindRecords
	descriptor.Inputs[0].Fields = fields
	descriptor.Outputs = []pluginapi.DecisionFactOutputDescriptor{{Name: raw.OutputFact, Category: pluginapi.DecisionFactCategoryEnvironment,
		Kind: pluginapi.DecisionValueKindRecords,
	}}

	return nil
}

// compileDecisionRecordFields declares every consumed field so candidate validation can reject hidden inputs.
func compileDecisionRecordFields(raw rawDecisionRecordInput) ([]pluginapi.DecisionFactInputFieldDescriptor, error) {
	if raw.IPField == "" || len(raw.Match) > 8 || len(raw.CorrelationFields) > 8 {
		return nil, fmt.Errorf("record input requires an IP field and bounded selectors")
	}

	names := map[string]struct{}{raw.IPField: {}}
	for name, value := range raw.Match {
		if name == raw.IPField || value == "" || len(value) > 64 {
			return nil, fmt.Errorf("invalid record match selector")
		}

		names[name] = struct{}{}
	}

	if err := validateDecisionCorrelations(raw.CorrelationFields); err != nil {
		return nil, err
	}

	for _, name := range raw.CorrelationFields {
		names[name] = struct{}{}
	}

	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}

	sort.Strings(ordered)

	fields := make([]pluginapi.DecisionFactInputFieldDescriptor, 0, len(ordered))
	for _, name := range ordered {
		fields = append(fields, pluginapi.DecisionFactInputFieldDescriptor{Name: name, Kind: pluginapi.DecisionValueKindString})
	}

	return fields, nil
}

// validateDecisionCorrelations prevents duplicate or provider-owned output names from being copied from caller records.
func validateDecisionCorrelations(fields []string) error {
	for index, name := range fields {
		if slices.Contains(fields[:index], name) {
			return fmt.Errorf("duplicate correlation field")
		}

		for _, output := range geoIPDecisionOutputSpecifications() {
			if output.name == name {
				return fmt.Errorf("correlation field collides with provider output")
			}
		}
	}

	return nil
}
