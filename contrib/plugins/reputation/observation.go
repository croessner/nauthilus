package main

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	reasonConflict  = "event_conflict"
	reasonValid     = "valid"
	reasonSource    = "source_unbound"
	reasonSignal    = "signal_invalid"
	reasonTime      = "time_invalid"
	reasonMagnitude = "magnitude_invalid"
	reasonSubject   = "subject_invalid"
	reasonDuplicate = "subject_duplicate"
	reasonInput     = "input_invalid"
)

var errASNUnavailable = errors.New("reputation ASN dependency unavailable")
var errASNNotFound = errors.New("reputation ASN verified absent")

type subjectInput struct{ role, kind, value string }

type observationInput struct {
	subjects      []subjectInput
	magnitude     *float64
	observedAt    time.Time
	eventID       string
	signal        string
	correlationID string
}

type admittedSubject struct {
	primary bool
	subjectInput
	tag    string
	weight float64
}

type admittedObservation struct {
	subjects []admittedSubject
	source   *sourcePolicy
	signal   *signalPolicy
	input    observationInput
}

// asnResolver accepts only an exact registered provider binding and the canonical admitted IP.
type asnResolver interface {
	lookupASN(context.Context, string, string) (string, error)
}

// admitObservation retains strict first-admission time validation for independent host observations.
func (c *configuration) admitObservation(ctx context.Context, source *sourcePolicy, input observationInput, now time.Time,
	tagger pluginapi.OpaqueIdentifierTagger, resolver asnResolver) (admittedObservation, string, error) {
	admitted, reason, err := c.admitCandidate(ctx, source, input, tagger, resolver)
	if err != nil || reason != reasonValid {
		return admitted, reason, err
	}

	if !validObservationTime(source, admitted.signal, input.observedAt, now) {
		return admittedObservation{}, reasonTime, nil
	}

	return admitted, reasonValid, nil
}

// admitCandidate validates contribution semantics before the owner distinguishes a new event from an immutable retry.
func (c *configuration) admitCandidate(ctx context.Context, source *sourcePolicy, input observationInput,
	tagger pluginapi.OpaqueIdentifierTagger, resolver asnResolver) (admittedObservation, string, error) {
	if err := ctx.Err(); err != nil {
		return admittedObservation{}, reasonInput, err
	}

	signal, reason := c.validateObservationEvidence(source, input)
	if reason != reasonValid {
		return admittedObservation{}, reason, nil
	}

	if tagger == nil {
		return admittedObservation{}, reasonInput, pluginapi.ErrOpaqueIdentifierTaggerUnavailable
	}

	subjects, reason, err := c.admitSubjects(ctx, source, signal, input.subjects, tagger, resolver)
	if err != nil || reason != reasonValid {
		return admittedObservation{}, reason, err
	}

	return admittedObservation{subjects: subjects, source: source, signal: signal, input: input}, reasonValid, nil
}

// validateObservationEvidence enforces the closed catalog and source measurement capabilities independently of retry timing.
func (c *configuration) validateObservationEvidence(source *sourcePolicy, input observationInput) (*signalPolicy, string) {
	if source == nil {
		return nil, reasonSource
	}

	if !boundedText(input.eventID, 128, false) || !boundedText(input.correlationID, 128, true) {
		return nil, reasonInput
	}

	signal := c.signals[input.signal]
	if signal == nil || !slices.Contains(source.config.AllowedSignals, input.signal) ||
		!compatibleOrigin(source.config.Binding.Kind, signal.config.EvidenceOrigin) {
		return nil, reasonSignal
	}

	if !validMagnitude(source, signal, input.magnitude) {
		return nil, reasonMagnitude
	}

	if len(input.subjects) < 1 || len(input.subjects) > source.config.MaximumSubjects {
		return nil, reasonSubject
	}

	return signal, reasonValid
}

// validMagnitude derives producer measurement eligibility from source and signal ownership.
func validMagnitude(source *sourcePolicy, signal *signalPolicy, magnitude *float64) bool {
	if magnitude == nil {
		return signal.config.Magnitude != magnitudeRequired
	}

	return source.config.AllowMagnitude && signal.config.Magnitude != magnitudeForbidden &&
		nonnegativeBound(*magnitude, signal.config.MagnitudeRange[1]) && *magnitude >= signal.config.MagnitudeRange[0]
}

// boundedText confines event and correlation identifiers to bounded non-control text.
func boundedText(value string, maximum int, optional bool) bool {
	return (optional && value == "") || (len(value) <= maximum && validPrincipal(value))
}

// admitSubjects canonicalizes caller inputs then detects duplicates across the complete expanded plan.
func (c *configuration) admitSubjects(ctx context.Context, source *sourcePolicy, signal *signalPolicy, input []subjectInput,
	tagger pluginapi.OpaqueIdentifierTagger, resolver asnResolver) ([]admittedSubject, string, error) {
	result := make([]admittedSubject, 0, len(input)*3)
	seen := make(map[string]struct{})

	for _, subject := range input {
		if !slices.Contains(source.config.AllowedSubjects[subject.role], subject.kind) {
			return nil, reasonSubject, nil
		}

		expanded, err := c.expandSubject(ctx, source, subject, resolver)
		if err != nil {
			if errors.Is(err, errSubject) {
				return nil, reasonSubject, nil
			}

			return nil, reasonSubject, err
		}

		for index, value := range expanded {
			multiplier, exists := signal.config.SubjectRoles[value.role][value.kind]
			if !exists {
				return nil, reasonSubject, nil
			}

			tag, err := tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: c.raw.SubjectScope, Kind: value.kind, Value: value.value})
			if err != nil {
				return nil, reasonSubject, err
			}

			key := value.kind + ":" + tag.String()
			if _, duplicate := seen[key]; duplicate {
				return nil, reasonDuplicate, nil
			}

			seen[key] = struct{}{}

			result = append(result, admittedSubject{primary: index == 0, subjectInput: value, tag: tag.String(), weight: signal.config.Weight * multiplier})
		}
	}

	if len(result) > maximumExpandedSubjects {
		return nil, reasonSubject, nil
	}

	sort.Slice(result, func(i, j int) bool { return result[i].kind+result[i].tag < result[j].kind+result[j].tag })

	return result, reasonValid, nil
}

// expandSubject derives related subjects, omitting only a provider-verified absent ASN.
func (c *configuration) expandSubject(ctx context.Context, source *sourcePolicy, subject subjectInput, resolver asnResolver) ([]subjectInput, error) {
	canonical, err := c.canonicalSubject(subject.kind, subject.value)
	if err != nil {
		return nil, err
	}

	subject.value = canonical

	result := []subjectInput{subject}
	if subject.kind != kindIP {
		return result, nil
	}

	for _, kind := range source.config.DerivedSubjects[subject.role] {
		value, err := c.derivedSubject(ctx, source, kind, canonical, resolver)
		if kind == kindASN && errors.Is(err, errASNNotFound) {
			continue
		}

		if err != nil {
			return nil, err
		}

		result = append(result, subjectInput{role: subject.role, kind: kind, value: value})
	}

	return result, nil
}

// derivedSubject binds network or provider-owned ASN attribution to the exact admitted address.
func (c *configuration) derivedSubject(ctx context.Context, source *sourcePolicy, kind, canonicalIP string, resolver asnResolver) (string, error) {
	if kind == kindNetwork {
		return c.networkSubject(canonicalIP), nil
	}

	if resolver == nil {
		return "", errASNUnavailable
	}

	value, err := resolver.lookupASN(ctx, source.config.ASNProvider, canonicalIP)
	if errors.Is(err, errASNNotFound) {
		return "", errASNNotFound
	}

	if err != nil {
		return "", errASNUnavailable
	}

	canonical, err := canonicalASN(value)
	if err != nil {
		return "", errASNUnavailable
	}

	return canonical, nil
}

// validObservationTime admits fresh evidence within the strictest source and signal time window.
func validObservationTime(source *sourcePolicy, signal *signalPolicy, observedAt, now time.Time) bool {
	return !now.IsZero() && !observedAt.IsZero() && !observedAt.After(now.Add(source.futureSkew)) &&
		now.Sub(observedAt) <= min(source.lateness, signal.maxAge)
}
