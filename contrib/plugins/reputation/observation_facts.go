package main

import (
	"errors"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var errObservationInput = errors.New("invalid reputation observation facts")

const observationPrefix = "resource.reputation."

// decodeObservationFacts admits only the exact transport vocabulary and never caller-defined causality.
func decodeObservationFacts(facts []pluginapi.DecisionFactView) (observationInput, error) {
	var result observationInput

	seen := make(map[string]bool)

	for _, fact := range facts {
		if strings.HasPrefix(fact.ID(), "caller.") {
			continue
		}

		if !strings.HasPrefix(fact.ID(), observationPrefix) || seen[fact.ID()] {
			return observationInput{}, errObservationInput
		}

		seen[fact.ID()] = true
		if err := decodeObservationFact(&result, strings.TrimPrefix(fact.ID(), observationPrefix), fact.Value()); err != nil {
			return observationInput{}, err
		}
	}

	for _, required := range []string{fieldEventID, fieldObservedAt, fieldSignal, fieldSubjects} {
		if !seen[observationPrefix+required] {
			return observationInput{}, errObservationInput
		}
	}

	return result, nil
}

// decodeObservationFact projects one exact typed field without weak conversions.
func decodeObservationFact(result *observationInput, name string, value pluginapi.DecisionValue) error {
	var ok bool

	switch name {
	case fieldEventID:
		result.eventID, ok = value.StringValue()
	case fieldSignal:
		result.signal, ok = value.StringValue()
	case fieldCorrelationID:
		result.correlationID, ok = value.StringValue()
	case fieldObservedAt:
		result.observedAt, ok = value.Timestamp()
	case fieldMagnitude:
		var measurement float64

		measurement, ok = value.Double()
		result.magnitude = &measurement
	case fieldSubjects:
		records, valid := value.Records()
		if !valid {
			return errObservationInput
		}

		subjects, err := decodeSubjectRecords(records)
		if err != nil {
			return err
		}

		result.subjects = subjects
		ok = true
	default:
		return errObservationInput
	}

	if !ok {
		return errObservationInput
	}

	return nil
}

// decodeSubjectRecords requires exactly three bounded typed fields for each producer subject.
func decodeSubjectRecords(list pluginapi.DecisionRecordList) ([]subjectInput, error) {
	records := list.Records()
	if len(records) < 1 || len(records) > maximumSubjects {
		return nil, errObservationInput
	}

	result := make([]subjectInput, 0, len(records))
	for _, record := range records {
		subject, err := decodeSubjectRecord(record)
		if err != nil {
			return nil, err
		}

		result = append(result, subject)
	}

	return result, nil
}

// decodeSubjectRecord projects exactly one immutable three-field producer subject.
func decodeSubjectRecord(record pluginapi.DecisionRecord) (subjectInput, error) {
	fields := record.Fields()
	if len(fields) != 3 {
		return subjectInput{}, errObservationInput
	}

	var subject subjectInput

	for _, field := range fields {
		text, ok := field.Value().Value().StringValue()
		if !ok {
			return subjectInput{}, errObservationInput
		}

		switch field.Name() {
		case fieldRole:
			subject.role = text
		case fieldKind:
			subject.kind = text
		case fieldValue:
			subject.value = text
		default:
			return subjectInput{}, errObservationInput
		}
	}

	if subject.role == "" || subject.kind == "" || subject.value == "" {
		return subjectInput{}, errObservationInput
	}

	return subject, nil
}
