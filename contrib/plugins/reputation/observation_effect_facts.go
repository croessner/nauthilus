package main

import (
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// decodeObservationEffectFacts consumes only metadata and the hidden provider-owned collection, never caller subject expansion.
func decodeObservationEffectFacts(facts []pluginapi.DecisionFactView, module string) (observationInput, []admittedSubject, error) {
	if pluginapi.ValidateModuleName(module) != nil {
		return observationInput{}, nil, errObservationInput
	}

	prefix := "plugin." + module + "."

	var (
		input  observationInput
		frozen []admittedSubject
	)

	seen := make(map[string]bool)
	for _, fact := range facts {
		if seen[fact.ID()] {
			return observationInput{}, nil, errObservationInput
		}

		seen[fact.ID()] = true
		if err := consumeObservationEffectFact(fact, prefix, &input, &frozen); err != nil {
			return observationInput{}, nil, err
		}
	}

	for _, id := range []string{observationPrefix + fieldEventID, observationPrefix + fieldObservedAt, observationPrefix + fieldSignal, prefix + outputValid, prefix + outputEligible, prefix + outputSubjects} {
		if !seen[id] {
			return observationInput{}, nil, errObservationInput
		}
	}

	for _, subject := range frozen {
		if subject.primary {
			input.subjects = append(input.subjects, subject.subjectInput)
		}
	}

	return input, frozen, nil
}

// validObservationSummary requires positive eligibility while leaving source authority with the repeated catalog validation.
func validObservationSummary(name string, value pluginapi.DecisionValue) bool {
	switch name {
	case outputValid, outputEligible:
		enabled, ok := value.Boolean()
		return ok && enabled
	case outputReason, outputSourceClass, outputOrigin:
		text, ok := value.StringValue()
		return ok && boundedText(text, 64, false)
	case outputKinds:
		values, ok := value.Strings()
		return ok && len(values) <= 6
	}

	return false
}

// decodeAdmittedSubjects requires the complete bounded typed provider plan, including primary-root markers.
func decodeAdmittedSubjects(value pluginapi.DecisionValue) ([]admittedSubject, error) {
	list, ok := value.Records()
	if !ok || len(list.Records()) < 1 || len(list.Records()) > maximumExpandedSubjects {
		return nil, errObservationInput
	}

	subjects := make([]admittedSubject, 0, len(list.Records()))
	for _, record := range list.Records() {
		subject, err := decodeAdmittedRecord(record)
		if err != nil {
			return nil, err
		}

		subjects = append(subjects, subject)
	}

	return subjects, nil
}

// decodeAdmittedRecord reuses the canonical producer-field decoder and separately validates protected contribution metadata.
func decodeAdmittedRecord(record pluginapi.DecisionRecord) (admittedSubject, error) {
	if len(record.Fields()) != 6 {
		return admittedSubject{}, errObservationInput
	}

	var subject admittedSubject

	primaryFields := make([]pluginapi.DecisionRecordField, 0, 3)

	for _, field := range record.Fields() {
		ok := true

		switch field.Name() {
		case fieldPrimary:
			subject.primary, ok = field.Value().Value().Boolean()
		case fieldSubjectTag:
			subject.tag, ok = field.Value().Value().StringValue()
		case fieldWeight:
			subject.weight, ok = field.Value().Value().Double()
		default:
			primaryFields = append(primaryFields, field)
		}

		if !ok {
			return admittedSubject{}, errObservationInput
		}
	}

	core, err := pluginapi.NewDecisionRecord(primaryFields)
	if err != nil {
		return admittedSubject{}, errObservationInput
	}

	subject.subjectInput, err = decodeSubjectRecord(core)
	if err != nil || !boundedText(subject.tag, 128, false) || !nonnegativeBound(subject.weight, 1000) {
		return admittedSubject{}, errObservationInput
	}

	return subject, nil
}

// consumeObservationEffectFact separates protected plan decoding from immutable envelope completeness checks.
func consumeObservationEffectFact(fact pluginapi.DecisionFactView, prefix string, input *observationInput, frozen *[]admittedSubject) error {
	switch {
	case strings.HasPrefix(fact.ID(), "caller."):
	case fact.ID() == observationPrefix+fieldSubjects:
		// The caller collection never participates in effect-side subject expansion.
	case strings.HasPrefix(fact.ID(), observationPrefix):
		return decodeObservationFact(input, strings.TrimPrefix(fact.ID(), observationPrefix), fact.Value())
	case fact.ID() == prefix+outputSubjects:
		subjects, err := decodeAdmittedSubjects(fact.Value())
		*frozen = subjects

		return err
	case strings.HasPrefix(fact.ID(), prefix):
		if !validObservationSummary(strings.TrimPrefix(fact.ID(), prefix), fact.Value()) {
			return errObservationInput
		}
	default:
		return errObservationInput
	}

	return nil
}
