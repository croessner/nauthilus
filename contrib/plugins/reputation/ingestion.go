package main

import (
	"context"
	"encoding/json"
	"strconv"
)

type ingestionResult struct{ Applied, Duplicates int }

type subjectUpdate struct {
	Profiles         []profileDefinition `json:"profiles"`
	Classes          []classDefinition   `json:"classes"`
	EligibleProfiles []string            `json:"eligible_profiles"`
	Kind             string              `json:"kind"`
	Fingerprint      string              `json:"fingerprint"`
	SourceClass      string              `json:"source_class"`
	Direction        string              `json:"direction"`
	SeenTag          string              `json:"seen_tag"`
	Weight           float64             `json:"weight"`
	ObservedAt       float64             `json:"observed_at"`
	ManifestExpiry   float64             `json:"manifest_expiry"`
	Retention        float64             `json:"retention"`
	SeenTTL          float64             `json:"seen_ttl"`
	MaximumSeen      int                 `json:"maximum_seen"`
	Authoritative    bool                `json:"authoritative"`
}

// ingest establishes one immutable manifest before independently idempotent same-subject updates.
func (s *stateOwner) ingest(ctx context.Context, admitted admittedObservation) (ingestionResult, error) {
	if !s.ready.Load() {
		return ingestionResult{}, errStateUnavailable
	}

	request, err := s.planner.plan(ctx, admitted)
	if err != nil {
		return ingestionResult{}, err
	}

	payload, expiry, err := s.admitManifest(ctx, request)
	if err != nil {
		return ingestionResult{}, err
	}

	var result ingestionResult

	for _, model := range payload.Models {
		for _, subject := range model.Subjects {
			duplicate, err := s.updateSubject(ctx, payload, model, subject, expiry)
			if err != nil {
				return result, err
			}

			if duplicate {
				result.Duplicates++
			} else {
				result.Applied++
			}
		}
	}

	return result, nil
}

// admitManifest resolves the selected local candidate against Redis time and the complete frozen stored plan.
func (s *stateOwner) admitManifest(ctx context.Context, request manifestRequest) (manifestPayload, float64, error) {
	keys, shard := s.keys.manifest(request.AllocationTag, request.SourceTag)
	request.MaximumNewSubjects = shardBudget(request.MaximumNewSubjects, shard)
	request.MaximumEvents = shardBudget(request.MaximumEvents, shard)

	response, err := s.run(ctx, scriptManifest, keys, request)
	if err != nil {
		return manifestPayload{}, 0, err
	}

	if len(response) != 3 || response[0] != storageAdmitted {
		return manifestPayload{}, 0, errStateUnavailable
	}

	index, ok := response[1].(int64)
	if !ok || index < 1 || index > int64(len(request.Candidates)) {
		return manifestPayload{}, 0, errStateUnavailable
	}

	text, ok := response[2].(string)
	if !ok {
		return manifestPayload{}, 0, errStateUnavailable
	}

	expiry, err := strconv.ParseFloat(text, 64)
	if err != nil || !positiveBound(expiry, 1e11) {
		return manifestPayload{}, 0, errStateUnavailable
	}

	var payload manifestPayload
	if err := json.Unmarshal([]byte(request.Candidates[index-1].Payload), &payload); err != nil {
		return manifestPayload{}, 0, errStateUnavailable
	}

	return payload, expiry, nil
}

// updateSubject uses only the admitted manifest model and subject, never a caller-expanded fact list.
func (s *stateOwner) updateSubject(ctx context.Context, payload manifestPayload, model manifestModel, subject manifestSubject, expiry float64) (bool, error) {
	keys := s.keys.subject(subject.Tag, model.ID)
	request := subjectUpdate{Profiles: model.Profiles, Classes: model.Classes, EligibleProfiles: model.EligibleProfiles,
		Kind: subject.Kind, Fingerprint: model.Fingerprint, SourceClass: payload.SourceClass, Direction: model.Direction, SeenTag: payload.SeenTag,
		Weight: subject.Weight, ObservedAt: payload.ObservedAt, ManifestExpiry: expiry, Retention: s.config.retention.Seconds(), SeenTTL: s.config.seenTTL.Seconds(),
		MaximumSeen: s.config.raw.MaximumSeenEventsPerSubject, Authoritative: model.Authoritative}

	response, err := s.run(ctx, scriptIngestion, []string{keys.State, keys.Seen}, request)
	if err != nil {
		return false, err
	}

	if len(response) != 1 || (response[0] != storageApplied && response[0] != storageDuplicate) {
		return false, errStateUnavailable
	}

	return response[0] == storageDuplicate, nil
}
