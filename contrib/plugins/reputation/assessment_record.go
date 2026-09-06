package main

import (
	"sort"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	assessmentFieldState      = "state"
	assessmentFieldProfile    = "profile"
	assessmentFieldBand       = "band"
	assessmentFieldOverride   = "override"
	assessmentFieldRisk       = "risk_score"
	assessmentFieldTrust      = "trust_score"
	assessmentFieldConfidence = "confidence"
	assessmentFieldSamples    = "samples"
	assessmentFieldDiversity  = "source_diversity"
	assessmentFieldAge        = "age_seconds"
)

// assessmentRecord emits only validated conditional details plus explicit same-record correlation.
func assessmentRecord(subject extractedSubject, tuple assessmentTuple) (pluginapi.DecisionRecord, error) {
	if tuple.validate() != nil {
		return pluginapi.DecisionRecord{}, errAssessment
	}

	inputs := []outputInput{
		stringOutput(fieldRole, subject.role),
		stringOutput(fieldKind, subject.kind),
		stringOutput(assessmentFieldState, tuple.State),
		stringOutput(assessmentFieldProfile, tuple.Profile),
		stringOutput(assessmentFieldBand, tuple.Band),
		stringOutput(assessmentFieldOverride, tuple.Override),
	}
	if d := tuple.Details; d != nil {
		diversity := int64(d.Diversity)
		inputs = append(inputs,
			outputInput{name: assessmentFieldRisk, input: pluginapi.DecisionValueInput{Double: &d.Risk}},
			outputInput{name: assessmentFieldTrust, input: pluginapi.DecisionValueInput{Double: &d.Trust}},
			outputInput{name: assessmentFieldConfidence, input: pluginapi.DecisionValueInput{Double: &d.Confidence}},
			outputInput{name: assessmentFieldSamples, input: pluginapi.DecisionValueInput{Double: &d.Samples}},
			outputInput{name: assessmentFieldDiversity, input: pluginapi.DecisionValueInput{Integer: &diversity}},
			outputInput{name: assessmentFieldAge, input: pluginapi.DecisionValueInput{Integer: &d.AgeSeconds}})
	}

	record, err := recordInputs(inputs)
	if err != nil {
		return pluginapi.DecisionRecord{}, err
	}

	return correlateAssessmentRecord(record, subject.correlation)
}

// correlateAssessmentRecord rejects collisions with provider-owned fields before constructing an immutable record.
func correlateAssessmentRecord(record pluginapi.DecisionRecord, correlation map[string]pluginapi.DecisionRecordFieldValue) (pluginapi.DecisionRecord, error) {
	fields := record.Fields()

	names := make([]string, 0, len(correlation))
	for name := range correlation {
		if assessmentField(name) {
			return pluginapi.DecisionRecord{}, errAssessment
		}

		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		field, err := pluginapi.NewDecisionRecordField(name, correlation[name])
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		fields = append(fields, field)
	}

	return pluginapi.NewDecisionRecord(fields)
}

// assessmentField reserves the complete conditional schema, even fields absent from missing-state tuples.
func assessmentField(name string) bool {
	switch name {
	case fieldRole, fieldKind, assessmentFieldState, assessmentFieldProfile, assessmentFieldBand, assessmentFieldOverride, assessmentFieldRisk, assessmentFieldTrust, assessmentFieldConfidence, assessmentFieldSamples, assessmentFieldDiversity, assessmentFieldAge:
		return true
	}

	return false
}
