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
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const outputAssessedChain = "assessed_chain"

var _ pluginapi.DecisionFactProvider = (*decisionFactProvider)(nil)

type decisionFactProvider struct {
	plugin *Plugin
}

// Descriptor declares the exact generic target and sole bounded output.
func (decisionFactProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Targets: []pluginapi.DecisionTargetSelector{exactTarget},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{{
			Name: outputAssessedChain, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords,
		}},
		Namespace: providerNamespace,
		Name:      providerName,
		Timeout:   time.Second,
	}
}

// Collect validates admitted facts and emits one detached assessment chain.
func (p decisionFactProvider) Collect(
	_ context.Context,
	request pluginapi.DecisionFactRequest,
) (pluginapi.DecisionFactResult, error) {
	if p.plugin == nil {
		return pluginapi.DecisionFactResult{}, fmt.Errorf("dkim2 reputation provider has no plugin")
	}

	config := p.plugin.snapshot()
	if config == nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	projection, err := decodeVerifierProjection(request)
	if err != nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	value, err := assessmentDecisionValue(assessProjection(config, projection))
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	return pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{Name: outputAssessedChain, Value: value}}}, nil
}

// assessmentDecisionValue converts internal assessments into the public immutable record vocabulary.
func assessmentDecisionValue(assessments []hopAssessment) (pluginapi.DecisionValue, error) {
	records := make([]pluginapi.DecisionRecord, 0, len(assessments))

	for _, assessment := range assessments {
		record, err := assessmentRecord(assessment)
		if err != nil {
			return pluginapi.DecisionValue{}, err
		}

		records = append(records, record)
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		return pluginapi.DecisionValue{}, err
	}

	return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
}

// assessmentRecord constructs the exact ten-field policy-facing record.
func assessmentRecord(assessment hopAssessment) (pluginapi.DecisionRecord, error) {
	specifications := []recordFieldSpecification{
		{name: fieldSequence, value: decisionInteger(assessment.hop.sequence)},
		{name: fieldMessageInstance, value: decisionInteger(assessment.hop.messageInstance)},
		{name: fieldHopBinding, value: decisionBytes(assessment.hop.hopBinding)},
		{name: "signer_reputation", value: decisionString(assessment.domainReputation)},
		{name: "smtp_peer_reputation", value: decisionString(assessment.clientIPReputation)},
		{name: "contract_state", value: decisionString(assessment.contractState)},
		{name: "recipe_authorization", value: decisionString(assessment.recipeAuthorization)},
		{name: "assessment_complete", value: decisionBoolean(assessment.assessmentComplete)},
		{name: "acceptable", value: decisionBoolean(assessment.acceptable)},
		{name: "violation_classes", value: decisionStrings(assessment.violations)},
	}

	fields := make([]pluginapi.DecisionRecordField, 0, len(specifications))
	for _, specification := range specifications {
		value, err := specification.value()
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		leaf, err := pluginapi.NewDecisionRecordFieldValue(value)
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		field, err := pluginapi.NewDecisionRecordField(specification.name, leaf)
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		fields = append(fields, field)
	}

	return pluginapi.NewDecisionRecord(fields)
}

type recordFieldSpecification struct {
	value func() (pluginapi.DecisionValue, error)
	name  string
}

// decisionString returns a deferred strict string constructor.
func decisionString(value string) func() (pluginapi.DecisionValue, error) {
	return func() (pluginapi.DecisionValue, error) {
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &value})
	}
}

// decisionStrings returns a deferred strict string-list constructor.
func decisionStrings(value []string) func() (pluginapi.DecisionValue, error) {
	return func() (pluginapi.DecisionValue, error) {
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Strings: value})
	}
}

// decisionBytes returns a deferred strict byte constructor.
func decisionBytes(value []byte) func() (pluginapi.DecisionValue, error) {
	return func() (pluginapi.DecisionValue, error) {
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Bytes: value})
	}
}

// decisionInteger returns a deferred strict integer constructor.
func decisionInteger(value int64) func() (pluginapi.DecisionValue, error) {
	return func() (pluginapi.DecisionValue, error) {
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Integer: &value})
	}
}

// decisionBoolean returns a deferred strict boolean constructor.
func decisionBoolean(value bool) func() (pluginapi.DecisionValue, error) {
	return func() (pluginapi.DecisionValue, error) {
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Boolean: &value})
	}
}
