package main

import (
	"slices"
	"sort"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type outputInput struct {
	input pluginapi.DecisionValueInput
	name  string
}

// observationResult exposes closed summary facts and protects all raw evidence inside the admitted collection.
func observationResult(admitted admittedObservation, reason string) (pluginapi.DecisionFactResult, error) {
	valid := reason == reasonValid
	class, origin := summaryUnbound, summaryUnbound
	kinds := make([]string, 0, 6)

	records := make([]pluginapi.DecisionRecord, 0, len(admitted.subjects))
	if valid {
		class, origin = admitted.source.config.SourceClass, admitted.signal.config.EvidenceOrigin
		for _, subject := range admitted.subjects {
			if !slices.Contains(kinds, subject.kind) {
				kinds = append(kinds, subject.kind)
			}

			record, err := admittedSubjectRecord(subject)
			if err != nil {
				return pluginapi.DecisionFactResult{}, err
			}

			records = append(records, record)
		}
	}

	sort.Strings(kinds)

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	return factOutputs([]outputInput{
		{name: outputValid, input: pluginapi.DecisionValueInput{Boolean: &valid}},
		{name: outputEligible, input: pluginapi.DecisionValueInput{Boolean: &valid}},
		{name: outputReason, input: pluginapi.DecisionValueInput{String: &reason}},
		{name: outputSourceClass, input: pluginapi.DecisionValueInput{String: &class}},
		{name: outputOrigin, input: pluginapi.DecisionValueInput{String: &origin}},
		{name: outputKinds, input: pluginapi.DecisionValueInput{Strings: kinds}},
		{name: outputSubjects, input: pluginapi.DecisionValueInput{Records: &list}},
	})
}

// factOutputs uses the public strict value constructors for every provider-local output.
func factOutputs(inputs []outputInput) (pluginapi.DecisionFactResult, error) {
	facts := make([]pluginapi.DecisionFactOutput, 0, len(inputs))
	for _, input := range inputs {
		value, err := pluginapi.NewDecisionValue(input.input)
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		facts = append(facts, pluginapi.DecisionFactOutput{Name: input.name, Value: value})
	}

	return pluginapi.DecisionFactResult{Facts: facts}, nil
}

// admittedSubjectRecord contains only the validator-owned canonical plan for the selected effect.
func admittedSubjectRecord(subject admittedSubject) (pluginapi.DecisionRecord, error) {
	return recordInputs([]outputInput{
		{name: fieldRole, input: pluginapi.DecisionValueInput{String: &subject.role}},
		{name: fieldKind, input: pluginapi.DecisionValueInput{String: &subject.kind}},
		{name: fieldValue, input: pluginapi.DecisionValueInput{String: &subject.value}},
		{name: fieldSubjectTag, input: pluginapi.DecisionValueInput{String: &subject.tag}},
		{name: fieldWeight, input: pluginapi.DecisionValueInput{Double: &subject.weight}},
	})
}

// recordInputs constructs an immutable flat record through one shared conversion boundary.
func recordInputs(inputs []outputInput) (pluginapi.DecisionRecord, error) {
	facts, err := factOutputs(inputs)
	if err != nil {
		return pluginapi.DecisionRecord{}, err
	}

	fields := make([]pluginapi.DecisionRecordField, 0, len(facts.Facts))
	for _, fact := range facts.Facts {
		value, err := pluginapi.NewDecisionRecordFieldValue(fact.Value)
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		field, err := pluginapi.NewDecisionRecordField(fact.Name, value)
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		fields = append(fields, field)
	}

	return pluginapi.NewDecisionRecord(fields)
}
