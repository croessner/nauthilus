package main

import (
	"context"
	"errors"
	"time"
)

// admitForPolicy validates source-owned contributions and probes the immutable manifest without allocating any state.
func (s *stateOwner) admitForPolicy(ctx context.Context, source *sourcePolicy, input observationInput, resolver asnResolver) (admitted admittedObservation, reason string, err error) {
	defer func() { s.telemetry.recordAdmission(ctx, source, input.signal, reason, err) }()

	if !s.ready.Load() {
		return admittedObservation{}, reasonInput, errStateUnavailable
	}

	admitted, reason, err = s.config.admitCandidate(ctx, source, input, s.planner.tagger, resolver)
	if err != nil || reason != reasonValid {
		return admitted, reason, err
	}

	request, err := s.planner.plan(ctx, admitted)
	if err != nil {
		return admittedObservation{}, reasonInput, err
	}

	request.Operation = "probe"
	keys, _ := s.keys.manifest(request.AllocationTag, request.SourceTag)

	response, err := s.run(ctx, scriptManifest, keys, request)
	if errors.Is(err, errEventConflict) {
		return admittedObservation{}, reasonConflict, nil
	}

	if err != nil {
		return admittedObservation{}, reasonInput, err
	}

	if len(response) == 1 && response[0] == assessmentMissing {
		if !validObservationTime(source, admitted.signal, input.observedAt, time.Now().UTC()) {
			return admittedObservation{}, reasonTime, nil
		}

		return admitted, reasonValid, nil
	}

	if _, _, err := decodeManifestAdmission(response, request); err != nil {
		return admittedObservation{}, reasonInput, err
	}

	return admitted, reasonValid, nil
}
