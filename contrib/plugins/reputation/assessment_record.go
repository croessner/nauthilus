package main

import (
	"sort"

	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// assessmentRecord emits only validated conditional details plus explicit same-record correlation.
func assessmentRecord(subject extractedSubject, tuple assessmentTuple) (pluginapi.DecisionRecord, error) {
	fields, err := view.Encode(view.Tuple(tuple))
	if err != nil {
		return pluginapi.DecisionRecord{}, err
	}

	record, err := recordInputs([]outputInput{stringOutput(fieldRole, subject.role), stringOutput(fieldKind, subject.kind)})
	if err != nil {
		return pluginapi.DecisionRecord{}, err
	}

	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}

	sort.Strings(names)

	output := record.Fields()

	for _, name := range names {
		field, fieldErr := pluginapi.NewDecisionRecordField(name, fields[name])
		if fieldErr != nil {
			return pluginapi.DecisionRecord{}, fieldErr
		}

		output = append(output, field)
	}

	record, err = pluginapi.NewDecisionRecord(output)
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
	if name == fieldRole || name == fieldKind {
		return true
	}

	for _, field := range view.Fields() {
		if field.Name == name {
			return true
		}
	}
	return false
}
